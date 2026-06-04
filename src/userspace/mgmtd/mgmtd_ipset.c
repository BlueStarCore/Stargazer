/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_ipset.c — in-process ipset management over NFNETLINK
 *
 * Backs FQDN address objects: each fqdn-type firewall_address owns one
 * hash:ip set; iptables FORWARD rules reference it via -m set
 * --match-set, and the FQDN refresh engine (mgmtd_fqdn.c) rewrites the
 * membership as DNS answers change — the rule itself never changes.
 *
 * All operations are raw netlink (NFNL_SUBSYS_IPSET) on a short-lived
 * socket — no ipset binary, no forking, same pattern as the conntrack
 * code in mgmtd_diag.c.
 *
 * Membership model: ACCUMULATE with per-entry timeout.  Round-robin DNS
 * returns a different subset of a domain's pool on every query, so
 * replacing the membership with "the latest answer" makes a deny rule
 * flicker: it only blocks the IPs of the most recent resolve while
 * clients hold cached answers from earlier rotations.  Instead every
 * resolve ADDs its answers (a re-add refreshes the entry's timeout) and
 * the kernel expires entries not seen for SG_IPSET_ENTRY_TIMEOUT_SEC.
 * Over time the set converges on the whole rotation pool.  Trade-off:
 * after a domain moves, its old IPs stay matched for up to the timeout
 * — over-blocking (fail-closed), never under-blocking.
 */

#define _GNU_SOURCE
#include "mgmtd_apply.h"

#include <errno.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* ── NFNETLINK / ipset wire constants (linux/netfilter/ipset/ip_set.h) ── */

#define SG_NETLINK_NETFILTER   12
#define SG_NFNL_SUBSYS_IPSET   6
#define SG_NFPROTO_IPV4        2

#define SG_IPSET_PROTOCOL      7    /* IPSET_PROTOCOL (min accepted: 6)  */

#define SG_IPSET_CMD_CREATE    2
#define SG_IPSET_CMD_DESTROY   3
#define SG_IPSET_CMD_LIST      7
#define SG_IPSET_CMD_ADD       9
#define SG_IPSET_CMD_TYPE      13

#define SG_IPSET_ATTR_PROTOCOL 1    /* u8                                 */
#define SG_IPSET_ATTR_SETNAME  2    /* string                             */
#define SG_IPSET_ATTR_TYPENAME 3    /* string                             */
#define SG_IPSET_ATTR_REVISION 4    /* u8                                 */
#define SG_IPSET_ATTR_FAMILY   5    /* u8                                 */
#define SG_IPSET_ATTR_TIMEOUT  6    /* be32 seconds (create + ADT)        */
#define SG_IPSET_ATTR_DATA     7    /* nested                             */
#define SG_IPSET_ATTR_ADT      8    /* nested: list of DATA entries       */

/*
 * Per-entry lifetime.  An entry survives this long after it was last
 * seen in a resolve.  Long enough that every member of a round-robin
 * pool gets re-confirmed many times per period (60 resolves/hour at
 * the 60 s refresh interval), short enough that a domain that moved
 * stops being over-blocked within the hour.  A total DNS outage longer
 * than this drains the set — logged by the refresh worker every cycle.
 *
 * Default only — configurable via "config system settings → fqdn-ttl"
 * (apply_settings calls sg_ipset_set_entry_timeout).  Every ADD stamps
 * the entry with the CURRENT value, so a change takes effect on the
 * next refresh cycle without recreating rule-referenced sets.
 */
#define SG_IPSET_ENTRY_TIMEOUT_SEC 3600

static uint32_t ips_entry_timeout = SG_IPSET_ENTRY_TIMEOUT_SEC;

void sg_ipset_set_entry_timeout(uint32_t sec)
{
	ips_entry_timeout = sec;
}

uint32_t sg_ipset_entry_timeout(void)
{
	return ips_entry_timeout;
}

/* Inside IPSET_ATTR_DATA (ADT part) */
#define SG_IPSET_ATTR_IP       1    /* nested                             */
/* Inside IPSET_ATTR_IP */
#define SG_IPSET_ATTR_IPADDR_IPV4  1  /* be32, needs NET_BYTEORDER flag   */

#define SG_NLA_F_NESTED        0x8000
#define SG_NLA_F_NET_BYTEORDER 0x4000

#define SG_IPSET_MAXNAMELEN    32

/* nfgenmsg without <linux/netfilter/nfnetlink.h> (same as mgmtd_diag.c) */
struct sg_ipset_nfgenmsg {
	uint8_t  nfgen_family;
	uint8_t  version;
	uint16_t res_id;
};

/* ── Small netlink builders (self-contained, mirrors mgmtd_diag.c) ────── */

static int ips_nla_put(char *buf, int *off, int bufsz, uint16_t type,
		       const void *data, int len)
{
	int need = NLA_HDRLEN + NLA_ALIGN(len);

	if (*off + need > bufsz)
		return -1;

	struct nlattr *nla = (struct nlattr *)(buf + *off);
	nla->nla_type = type;
	nla->nla_len  = (uint16_t)(NLA_HDRLEN + len);
	if (len > 0)
		memcpy(buf + *off + NLA_HDRLEN, data, (size_t)len);
	/* zero alignment padding */
	if (NLA_ALIGN(len) > len)
		memset(buf + *off + NLA_HDRLEN + len, 0,
		       (size_t)(NLA_ALIGN(len) - len));
	*off += need;
	return 0;
}

static const void *ips_nla_find(const void *data, int len, int want, int *plen)
{
	const char *p = data;

	while (len >= NLA_HDRLEN) {
		const struct nlattr *nla = (const struct nlattr *)p;
		int alen = nla->nla_len;

		if (alen < NLA_HDRLEN || alen > len)
			break;
		if ((nla->nla_type & 0x3FFF) == want) {
			if (plen)
				*plen = alen - NLA_HDRLEN;
			return p + NLA_HDRLEN;
		}
		p   += NLA_ALIGN(alen);
		len -= NLA_ALIGN(alen);
	}
	return NULL;
}

/* Open a netfilter netlink socket with a 2s receive timeout. */
static int ips_socket(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW, SG_NETLINK_NETFILTER);
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };

	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

/* Start an ipset request: nlmsghdr + nfgenmsg + PROTOCOL attr.
 * Returns the running offset, or -1 on overflow. */
static int ips_msg_init(char *buf, int bufsz, uint8_t cmd, uint16_t flags)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct sg_ipset_nfgenmsg *nfg =
		(struct sg_ipset_nfgenmsg *)(buf + NLMSG_HDRLEN);
	int off = NLMSG_HDRLEN +
		  NLMSG_ALIGN((int)sizeof(struct sg_ipset_nfgenmsg));
	uint8_t proto = SG_IPSET_PROTOCOL;

	if (bufsz < off)
		return -1;
	memset(buf, 0, (size_t)off);
	nlh->nlmsg_type  = (uint16_t)((SG_NFNL_SUBSYS_IPSET << 8) | cmd);
	nlh->nlmsg_flags = (uint16_t)(NLM_F_REQUEST | flags);
	nlh->nlmsg_seq   = 1;
	nfg->nfgen_family = SG_NFPROTO_IPV4;

	if (ips_nla_put(buf, &off, bufsz, SG_IPSET_ATTR_PROTOCOL,
			&proto, 1) < 0)
		return -1;
	return off;
}

/*
 * ips_transact — send one request and wait for its ACK.
 *
 * Returns 0 on success (NLMSG_ERROR with error==0, or error==-tolerate),
 * the negative kernel errno otherwise, and -ETIMEDOUT/-EIO on socket
 * trouble.  ipset-private error codes (>= 4096) come back as
 * -IPSET_ERR_xxx — callers only need "non-zero means failed, log it".
 */
static int ips_transact(char *buf, int off, int tolerate)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct sockaddr_nl sa;
	char rbuf[4096];
	ssize_t rn;
	int fd, err;

	nlh->nlmsg_len    = (uint32_t)off;
	nlh->nlmsg_flags |= NLM_F_ACK;

	fd = ips_socket();
	if (fd < 0)
		return -EIO;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	if (sendto(fd, buf, (size_t)off, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	rn = recv(fd, rbuf, sizeof(rbuf), 0);
	close(fd);
	if (rn <= 0)
		return -ETIMEDOUT;

	const struct nlmsghdr *rh = (const struct nlmsghdr *)rbuf;
	if (rn < (ssize_t)NLMSG_HDRLEN || rh->nlmsg_len > (uint32_t)rn)
		return -EIO;
	if (rh->nlmsg_type != NLMSG_ERROR)
		return -EIO;	/* ACK expected — anything else is protocol drift */

	err = ((const struct nlmsgerr *)NLMSG_DATA(rh))->error;
	if (err == 0 || (tolerate && err == -tolerate))
		return 0;
	return err;
}

/* ── hash:ip revision probe (cached) ───────────────────────────────────── */

/*
 * The CREATE message must carry the set-type revision.  Ask the kernel
 * once (IPSET_CMD_TYPE) which revision range it supports for hash:ip
 * and use the maximum.  Failure here means ipset support is missing
 * from the kernel — every caller treats that as "FQDN objects cannot
 * be enforced" and fails closed.
 */
static int ips_hash_ip_revision(void)
{
	static int cached = -2;	/* -2 = not probed, -1 = unsupported */
	char buf[256], rbuf[4096];
	struct sockaddr_nl sa;
	const char *tname = "hash:ip";
	uint8_t fam = SG_NFPROTO_IPV4;
	ssize_t rn;
	int off, fd;

	if (cached != -2)
		return cached;

	off = ips_msg_init(buf, sizeof(buf), SG_IPSET_CMD_TYPE, 0);
	if (off < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_TYPENAME,
			tname, (int)strlen(tname) + 1) < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_FAMILY,
			&fam, 1) < 0)
		return cached = -1;
	((struct nlmsghdr *)buf)->nlmsg_len = (uint32_t)off;

	fd = ips_socket();
	if (fd < 0)
		return cached = -1;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(fd, buf, (size_t)off, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return cached = -1;
	}
	rn = recv(fd, rbuf, sizeof(rbuf), 0);
	close(fd);
	if (rn <= (ssize_t)NLMSG_HDRLEN)
		return cached = -1;

	const struct nlmsghdr *rh = (const struct nlmsghdr *)rbuf;
	if (rh->nlmsg_len > (uint32_t)rn || rh->nlmsg_type == NLMSG_ERROR)
		return cached = -1;

	const char *attrs = (const char *)NLMSG_DATA(rh) +
		NLMSG_ALIGN(sizeof(struct sg_ipset_nfgenmsg));
	int alen = (int)rh->nlmsg_len - NLMSG_HDRLEN -
		   (int)NLMSG_ALIGN(sizeof(struct sg_ipset_nfgenmsg));
	int rlen = 0;
	const void *rev = ips_nla_find(attrs, alen,
				       SG_IPSET_ATTR_REVISION, &rlen);

	if (!rev || rlen < 1)
		return cached = -1;
	return cached = *(const uint8_t *)rev;
}

/* ── Public API ────────────────────────────────────────────────────────── */

int sg_ipset_available(void)
{
	return ips_hash_ip_revision() >= 0;
}

/*
 * sg_fqdn_set_name — deterministic ipset name for an address object.
 *
 * "sgF_<object>" when it fits; otherwise "sgF_<prefix>_<fnv1a32-hex>".
 * Capped at IPSET_MAXNAMELEN-2 (30): 31 usable chars + NUL is the
 * kernel limit, minus one char of headroom for a future suffixed
 * companion set.  Object names are safe-ids, which are valid ipset
 * name characters.
 */
void sg_fqdn_set_name(const char *obj, char *out, size_t outsz)
{
	size_t len = obj ? strlen(obj) : 0;

	if (len > 0 && len + 4 <= SG_IPSET_MAXNAMELEN - 2) {
		snprintf(out, outsz, "sgF_%s", obj);
		return;
	}

	uint32_t h = 2166136261u;	/* FNV-1a 32-bit */
	for (size_t i = 0; i < len; i++) {
		h ^= (uint8_t)obj[i];
		h *= 16777619u;
	}
	snprintf(out, outsz, "sgF_%.17s_%08x", obj ? obj : "", h);
}

/* Create a hash:ip set with per-entry timeouts if it does not exist.
 *
 * No NLM_F_EXCL makes a same-parameter clash success, but the kernel
 * still returns EEXIST when ANY create parameter differs — including
 * the default timeout, which here tracks the fqdn-ttl setting.  So an
 * existing set from before a fqdn-ttl change WILL clash.  That clash
 * is harmless (every ADD stamps the entry timeout explicitly, the
 * create-time default never applies) and must not fail the caller:
 * ensure() failing here would break every membership update and make
 * the next chain rebuild SKIP fqdn rules — fail-open.  Tolerate it.
 *
 * Returns 0/negative errno. */
int sg_ipset_ensure(const char *set)
{
	char buf[512];
	int rev = ips_hash_ip_revision();
	uint8_t fam = SG_NFPROTO_IPV4, rev8;
	uint8_t tmo_be[4] = {		/* be32, NET_BYTEORDER */
		(uint8_t)(ips_entry_timeout >> 24),
		(uint8_t)(ips_entry_timeout >> 16),
		(uint8_t)(ips_entry_timeout >>  8),
		(uint8_t) ips_entry_timeout,
	};
	const char *tname = "hash:ip";
	int off;

	if (rev < 0)
		return -ENOTSUP;
	rev8 = (uint8_t)rev;

	off = ips_msg_init(buf, sizeof(buf), SG_IPSET_CMD_CREATE, 0);
	if (off < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_SETNAME,
			set, (int)strlen(set) + 1) < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_TYPENAME,
			tname, (int)strlen(tname) + 1) < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_REVISION,
			&rev8, 1) < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_FAMILY,
			&fam, 1) < 0)
		return -EMSGSIZE;

	/* DATA{ TIMEOUT } — default entry timeout, enables timeouts */
	int data_at = off;
	if (ips_nla_put(buf, &off, sizeof(buf),
			SG_IPSET_ATTR_DATA | SG_NLA_F_NESTED, NULL, 0) < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf),
			SG_IPSET_ATTR_TIMEOUT | SG_NLA_F_NET_BYTEORDER,
			tmo_be, 4) < 0)
		return -EMSGSIZE;
	((struct nlattr *)(buf + data_at))->nla_len = (uint16_t)(off - data_at);

	return ips_transact(buf, off, EEXIST);
}

/* Destroy a set.  ENOENT (already gone) is success. */
int sg_ipset_destroy(const char *set)
{
	char buf[256];
	int off = ips_msg_init(buf, sizeof(buf), SG_IPSET_CMD_DESTROY, 0);

	if (off < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_SETNAME,
			set, (int)strlen(set) + 1) < 0)
		return -EMSGSIZE;

	return ips_transact(buf, off, ENOENT);
}

/* Add one IPv4 (network byte order) to a set, stamped with the current
 * entry timeout — so a changed fqdn-ttl reaches every entry on its next
 * refresh, regardless of the set's create-time default. */
static int ips_add_ip(const char *set, uint32_t ip_be)
{
	char buf[512];
	uint8_t tmo_be[4] = {		/* be32, NET_BYTEORDER */
		(uint8_t)(ips_entry_timeout >> 24),
		(uint8_t)(ips_entry_timeout >> 16),
		(uint8_t)(ips_entry_timeout >>  8),
		(uint8_t) ips_entry_timeout,
	};
	int off = ips_msg_init(buf, sizeof(buf), SG_IPSET_CMD_ADD, 0);

	if (off < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_SETNAME,
			set, (int)strlen(set) + 1) < 0)
		return -EMSGSIZE;

	/* DATA{ IP{ IPADDR_IPV4 }, TIMEOUT } — lengths backfilled */
	int data_at = off;
	if (ips_nla_put(buf, &off, sizeof(buf),
			SG_IPSET_ATTR_DATA | SG_NLA_F_NESTED, NULL, 0) < 0)
		return -EMSGSIZE;
	int ip_at = off;
	if (ips_nla_put(buf, &off, sizeof(buf),
			SG_IPSET_ATTR_IP | SG_NLA_F_NESTED, NULL, 0) < 0)
		return -EMSGSIZE;
	if (ips_nla_put(buf, &off, sizeof(buf),
			SG_IPSET_ATTR_IPADDR_IPV4 | SG_NLA_F_NET_BYTEORDER,
			&ip_be, 4) < 0)
		return -EMSGSIZE;
	((struct nlattr *)(buf + ip_at))->nla_len = (uint16_t)(off - ip_at);
	if (ips_nla_put(buf, &off, sizeof(buf),
			SG_IPSET_ATTR_TIMEOUT | SG_NLA_F_NET_BYTEORDER,
			tmo_be, 4) < 0)
		return -EMSGSIZE;
	((struct nlattr *)(buf + data_at))->nla_len = (uint16_t)(off - data_at);

	return ips_transact(buf, off, 0);
}

/*
 * sg_ipset_add — merge addrs[0..n-1] into a set's membership.
 *
 * Adds run without NLM_F_EXCL, so an already-present entry is success
 * AND has its timeout refreshed — calling this every refresh interval
 * keeps live members alive while entries that stop appearing in DNS
 * answers expire after SG_IPSET_ENTRY_TIMEOUT_SEC.
 *
 * Returns 0 on success (n == 0 just ensures the set exists), negative
 * errno on the first failed add.
 */
int sg_ipset_add(const char *set, const uint32_t *addrs_be, int n)
{
	int rc, i;

	if (!set || n < 0)
		return -EINVAL;

	rc = sg_ipset_ensure(set);
	if (rc != 0)
		return rc;

	for (i = 0; i < n; i++) {
		rc = ips_add_ip(set, addrs_be[i]);
		if (rc != 0)
			return rc;
	}
	return 0;
}

/*
 * ips_walk — shared IPSET_CMD_LIST dump walker.
 *
 * Streams the set's members into whichever outputs are non-NULL:
 *   addrs[max_addrs] — raw be32 members (members beyond max_addrs are
 *                      counted but not stored)
 *   out[outsz]       — text, one member per line with its remaining
 *                      lifetime ("1.2.3.4  expires 3542s"); appends a
 *                      "(truncated)" marker if out runs short
 * Returns the member count, or negative errno (-ENOENT: no such set).
 */
static int ips_walk(const char *set, uint32_t *addrs, int max_addrs,
		    char *out, size_t outsz)
{
	char buf[256];
	struct sockaddr_nl sa;
	size_t used = 0;
	int off, fd, count = 0, truncated = 0;

	if (out)
		out[0] = '\0';

	off = ips_msg_init(buf, sizeof(buf), SG_IPSET_CMD_LIST, NLM_F_DUMP);
	if (off < 0 ||
	    ips_nla_put(buf, &off, sizeof(buf), SG_IPSET_ATTR_SETNAME,
			set, (int)strlen(set) + 1) < 0)
		return -EMSGSIZE;
	((struct nlmsghdr *)buf)->nlmsg_len = (uint32_t)off;

	fd = ips_socket();
	if (fd < 0)
		return -EIO;
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(fd, buf, (size_t)off, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int err = -errno;
		close(fd);
		return err;
	}

	for (;;) {
		char rbuf[16384];
		ssize_t rn = recv(fd, rbuf, sizeof(rbuf), 0);

		if (rn <= 0) {
			close(fd);
			return -ETIMEDOUT;
		}

		int mlen = (int)rn;
		for (struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
		     NLMSG_OK(rh, mlen); rh = NLMSG_NEXT(rh, mlen)) {
			if (rh->nlmsg_type == NLMSG_DONE)
				goto done;
			if (rh->nlmsg_type == NLMSG_ERROR) {
				int err = ((struct nlmsgerr *)
					   NLMSG_DATA(rh))->error;
				close(fd);
				return err ? err : count;
			}

			const char *attrs = (const char *)NLMSG_DATA(rh) +
				NLMSG_ALIGN(sizeof(struct sg_ipset_nfgenmsg));
			int alen = (int)rh->nlmsg_len - NLMSG_HDRLEN -
				   (int)NLMSG_ALIGN(sizeof(struct sg_ipset_nfgenmsg));
			int adt_len = 0;
			const char *adt = ips_nla_find(attrs, alen,
						       SG_IPSET_ATTR_ADT,
						       &adt_len);
			if (!adt) {
				/* header-only part (set exists, no ADT yet) */
				if (!(rh->nlmsg_flags & NLM_F_MULTI))
					goto done;
				continue;
			}

			/* ADT is a sequence of nested DATA entries:
			 * DATA{ IP{ IPADDR_IPV4 } } */
			while (adt_len >= NLA_HDRLEN) {
				const struct nlattr *d =
					(const struct nlattr *)adt;
				int dl = d->nla_len;

				if (dl < NLA_HDRLEN || dl > adt_len)
					break;
				if ((d->nla_type & 0x3FFF) !=
				    SG_IPSET_ATTR_DATA)
					goto next_entry;

				int ip_len = 0, a4 = 0, tl = 0;
				const uint8_t *b = NULL, *t;
				const char *ipn = ips_nla_find(
					adt + NLA_HDRLEN, dl - NLA_HDRLEN,
					SG_IPSET_ATTR_IP, &ip_len);
				if (ipn)
					b = ips_nla_find(ipn, ip_len,
						SG_IPSET_ATTR_IPADDR_IPV4,
						&a4);
				if (!b || a4 < 4)
					goto next_entry;

				if (addrs && count < max_addrs)
					memcpy(&addrs[count], b, 4);
				count++;
				if (!out)
					goto next_entry;

				/* remaining lifetime (be32 seconds) */
				char line[48];
				int w;
				t = ips_nla_find(adt + NLA_HDRLEN,
						 dl - NLA_HDRLEN,
						 SG_IPSET_ATTR_TIMEOUT, &tl);
				if (t && tl >= 4)
					w = snprintf(line, sizeof(line),
						"%u.%u.%u.%u  expires %us\n",
						b[0], b[1], b[2], b[3],
						((uint32_t)t[0] << 24) |
						((uint32_t)t[1] << 16) |
						((uint32_t)t[2] <<  8) |
						 (uint32_t)t[3]);
				else
					w = snprintf(line, sizeof(line),
						"%u.%u.%u.%u\n",
						b[0], b[1], b[2], b[3]);

				/* keep 16 bytes spare for the
				 * "(truncated)" marker */
				if (outsz - used > (size_t)w + 16) {
					memcpy(out + used, line, (size_t)w + 1);
					used += (size_t)w;
				} else {
					truncated = 1;
				}
next_entry:
				adt += NLA_ALIGN(dl);
				adt_len -= NLA_ALIGN(dl);
			}

			if (!(rh->nlmsg_flags & NLM_F_MULTI))
				goto done;
		}
	}

done:
	close(fd);
	if (truncated)
		/* entry writes leave >= 16 spare bytes, so this fits */
		snprintf(out + used, outsz - used, "(truncated)\n");
	return count;
}

/* Dump a set's membership as text (diagnostics).  Returns the member
 * count — which can exceed the lines written if out is too small —
 * or negative errno (-ENOENT: no such set). */
int sg_ipset_list(const char *set, char *out, size_t outsz)
{
	if (!set || !out || outsz < 32)
		return -EINVAL;
	return ips_walk(set, NULL, 0, out, outsz);
}

/* Read a set's members as raw be32 addresses (refresh keep-alive).
 * Returns the member count (may exceed max — extras not stored), or
 * negative errno (-ENOENT: no such set). */
int sg_ipset_members(const char *set, uint32_t *addrs_be, int max)
{
	if (!set || !addrs_be || max <= 0)
		return -EINVAL;
	return ips_walk(set, addrs_be, max, NULL, 0);
}
