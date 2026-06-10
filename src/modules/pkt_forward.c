// SPDX-License-Identifier: GPL-2.0-only
/*
 * pkt_forward.c - Packet forwarding hook for Stargazer NGFW
 *
 * Copyright (C) 2026 Stargazer Team
 *
 * Registers a Netfilter hook at NF_INET_FORWARD that drops structurally
 * invalid / attack-pattern packets (land attack, IP source routing, TCP
 * NULL/XMAS/FIN-no-ACK/SYN+data scans, Ping of Death) before they reach the
 * routing and NAT path.
 *
 * Connection state tracking and NAT are handled by the kernel's nf_conntrack.
 * For accepted packets the hook also accounts per-flow ML features into the
 * conntrack NF_CT_EXT_ML extension (timing, packet-length spread, TCP flags,
 * and the flow's in/out interface) — see ml_account().
 */

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timekeeping.h>
#include <linux/math64.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ml.h>

#ifndef PKT_FWD_VERSION
#define PKT_FWD_VERSION "unknown"
#endif

/* Counters (atomic for SMP) */
static atomic64_t pkts_forwarded       = ATOMIC64_INIT(0);
static atomic64_t pkts_dropped         = ATOMIC64_INIT(0);
static atomic64_t pkts_anomaly_dropped = ATOMIC64_INIT(0); /* L3/L4 anomaly */

/* --- Anomaly detection helpers -------------------------------------------- */

/*
 * is_ip_anomaly - Check for IP-level protocol anomalies.
 * Applied to all interfaces; these packets are structurally invalid.
 * Returns true (drop) for: land attack, IP source routing (LSRR/SSRR).
 */
static bool is_ip_anomaly(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	/* Land attack: source == destination */
	if (iph->saddr == iph->daddr)
		return true;

	/* IP source routing options (LSRR=131, SSRR=137) — used to bypass ACLs */
	if (iph->ihl > 5) {
		const u8 *opt;
		int       optlen;

		/* Pull the full IP header including options into linear data */
		if (!pskb_may_pull(skb, (unsigned int)iph->ihl * 4))
			return false; /* can't verify options; pass through */
		iph    = ip_hdr(skb); /* re-fetch after potential realloc */
		opt    = (const u8 *)iph + sizeof(struct iphdr);
		optlen = iph->ihl * 4 - (int)sizeof(struct iphdr);
		int       i      = 0;

		while (i < optlen) {
			u8 type = opt[i];

			if (type == 0)   /* IPOPT_END */
				break;
			if (type == 1) { /* IPOPT_NOP */
				i++;
				continue;
			}
			if (type == 131 || type == 137)  /* LSRR / SSRR */
				return true;
			if (i + 1 >= optlen)
				break;
			i += opt[i + 1] ? opt[i + 1] : 1;
		}
	}

	return false;
}

/*
 * is_tcp_anomaly - Check for TCP flag-based attack patterns.
 * Returns true (drop) for: NULL scan, XMAS scan, FIN without ACK, SYN+data.
 * Caller must ensure the TCP header (20 bytes past the IP header) is linear.
 * The header is located from the IP header, not skb_transport_header, so it
 * works regardless of whether the transport offset has been set.
 */
static bool is_tcp_anomaly(struct sk_buff *skb)
{
	struct iphdr  *iph  = ip_hdr(skb);
	struct tcphdr *tcph = (struct tcphdr *)((u8 *)iph + iph->ihl * 4);
	unsigned int   ip_hlen, tcp_hlen, tot_len;

	/* NULL scan: no TCP control bits set */
	if (!(tcph->fin | tcph->syn | tcph->rst | tcph->psh | tcph->ack | tcph->urg))
		return true;

	/* XMAS scan: FIN+URG+PSH simultaneously */
	if (tcph->fin && tcph->urg && tcph->psh)
		return true;

	/* FIN without ACK — invalid per RFC 793 */
	if (tcph->fin && !tcph->ack)
		return true;

	/* SYN with data payload — handshake SYNs carry no data */
	if (tcph->syn && !tcph->ack) {
		ip_hlen  = (unsigned int)iph->ihl * 4;
		tcp_hlen = (unsigned int)tcph->doff * 4;
		tot_len  = (unsigned int)ntohs(iph->tot_len);
		/* Guard against malformed tot_len (< sum of headers) */
		if (tcp_hlen >= 20 && tot_len > ip_hlen + tcp_hlen)
			return true;
	}

	return false;
}

/*
 * is_icmp_anomaly - Ping of Death: ICMP with anomalously large total length.
 * nf_defrag_ipv4 has already reassembled fragments; tot_len > 65500 bytes
 * indicates a crafted oversized echo that would overflow vulnerable stacks.
 */
static bool is_icmp_anomaly(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	return iph->protocol == IPPROTO_ICMP &&
	       ntohs(iph->tot_len) > 65500;
}

/* --- Packet validation ---------------------------------------------------- */

static bool is_valid_ipv4(struct sk_buff *skb)
{
	struct iphdr *iph;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return false;

	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->ihl < 5)
		return false;

	return true;
}

/* --- ML feature accounting ------------------------------------------------- */

/*
 * ml_account - record this packet into the flow's conntrack NF_CT_EXT_ML
 * extension. conntrack ran at PRE_ROUTING, so the entry is already attached
 * and the extension allocated; here we add the per-flow features the ACCT and
 * TSTAMP extensions don't carry — inter-arrival time, payload-length spread,
 * and accumulated TCP flags. Lengths are the L4 payload only (CICFlowMeter
 * convention): the IP and transport headers are subtracted off. Direction is
 * taken from conntrack (CTINFO2DIR). Best-effort, under the per-conntrack lock;
 * untracked packets (no ext) skip.
 */
static void ml_account(struct sk_buff *skb, u8 proto, int iif, int oif)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_conn_ml *ml;
	struct tcphdr *th = NULL;
	struct iphdr *iph;
	u64 now;
	int dir;
	u32 l3len;
	u16 ihl, l4hdr = 0, len;

	if (!ct)
		return;
	ml = nf_conn_ml_find(ct);
	if (!ml)
		return;

	iph = ip_hdr(skb);
	ihl = iph->ihl * 4;
	/* Effective L3 length: the smaller of the IP header's tot_len and the
	 * bytes actually present in the skb. */
	l3len = min_t(u32, ntohs(iph->tot_len), skb->len);
	/* Size of the transport header, to be subtracted for the L4 payload. */
	if (proto == IPPROTO_TCP) {
		th = (struct tcphdr *)((u8 *)iph + ihl);
		l4hdr = th->doff * 4;
	} else if (proto == IPPROTO_UDP) {
		l4hdr = sizeof(struct udphdr);
	} else if (proto == IPPROTO_ICMP) {
		l4hdr = sizeof(struct icmphdr);
	}
	/* L4 payload length, clamped at 0 so a malformed/short header (header
	 * claims more than the effective length) cannot wrap the subtraction. */
	len = (l3len > ihl + l4hdr) ? (u16)(l3len - ihl - l4hdr) : 0;

	dir = CTINFO2DIR(ctinfo);
	now = ktime_get_ns();

	spin_lock_bh(&ct->lock);
	/* Record the flow's in/out interfaces from the original direction only
	 * (reply packets traverse FORWARD with in/out swapped). Set once. The
	 * ml->iif/oif fields are u16, so store only when the kernel ifindex
	 * fits; otherwise leave them 0 (unset) rather than a truncated value. */
	if (dir == IP_CT_DIR_ORIGINAL && ml->iif == 0 &&
	    iif <= U16_MAX && oif <= U16_MAX) {
		ml->iif = (u16)iif;
		ml->oif = (u16)oif;
	}
	/* Payload-length sum / sum-of-squares / sample count (both directions),
	 * plus the per-direction payload totals for the fwd/bwd length means. */
	ml->pktlen_sum    += len;
	ml->pktlen_sq_sum += (u64)len * len;
	ml->pktlen_count++;
	if (dir == IP_CT_DIR_ORIGINAL)
		ml->bytes_fwd += len;
	else
		ml->bytes_bwd += len;

	/* Inter-arrival times, kept in microseconds: the mean is
	 * iat_sum_us/iat_count and the squares stay consistent with it. A gap is
	 * clamped to U32_MAX us (~4295 s) so a single square cannot overflow u64;
	 * conntrack timeouts keep real gaps well below that. */
	if (ml->first_ns == 0) {
		ml->first_ns = now;
	} else {
		u64 gap_us = div_u64(now - ml->last_ns, 1000);

		if (gap_us > U32_MAX)
			gap_us = U32_MAX;
		ml->iat_sum_us      += gap_us;
		ml->flow_iat_sq_sum += gap_us * gap_us;
		ml->iat_count++;
		if (gap_us < ml->flow_iat_min)
			ml->flow_iat_min = (u32)gap_us;
	}
	ml->last_ns = now;

	/* Forward-direction (original) inter-arrival times. */
	if (dir == IP_CT_DIR_ORIGINAL) {
		if (ml->last_seen_fwd) {
			u64 fgap_us = div_u64(now - (u64)ml->last_seen_fwd, 1000);

			if (fgap_us > U32_MAX)
				fgap_us = U32_MAX;
			ml->fwd_iat_sum    += fgap_us;
			ml->fwd_iat_sq_sum += fgap_us * fgap_us;
			ml->fwd_iat_count++;
		}
		ml->last_seen_fwd = now;
	}

	if (len < ml->len_min[dir])
		ml->len_min[dir] = len;
	if (len > ml->len_max[dir])
		ml->len_max[dir] = len;
	if (proto == IPPROTO_TCP && th) {
		u16 f = 0;

		if (th->fin) f |= 0x01;
		if (th->syn) { f |= 0x02; ml->syn_count++; }
		if (th->rst) f |= 0x04;
		if (th->psh) { f |= 0x08; ml->psh_count++; }
		if (th->ack) { f |= 0x10; ml->ack_count++; }
		if (th->urg) { f |= 0x20; ml->urg_count++; }
		ml->tcp_flags[dir] |= f;
	}
	spin_unlock_bh(&ct->lock);
}

/*
 * forward_hook - Netfilter callback for the FORWARD chain.
 *
 * Runs before conntrack confirm / NAT:
 *   [1] IPv4 header validation
 *   [2] L3/L4 anomaly detection (land attack, IP source routing, TCP
 *       NULL/XMAS/FIN-no-ACK/SYN+data, Ping of Death) — all interfaces
 *   [3] ML feature accounting into the conntrack NF_CT_EXT_ML extension
 *
 * Accepted packets continue to conntrack, the iptables policy chain, and NAT.
 */
static unsigned int forward_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	u8 proto;

	/* [1] IPv4 validation */
	if (!is_valid_ipv4(skb)) {
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}
	proto = ip_hdr(skb)->protocol;

	/* Make the TCP header linear before flag inspection. */
	if (proto == IPPROTO_TCP &&
	    !pskb_may_pull(skb, (unsigned int)ip_hdr(skb)->ihl * 4 +
			   sizeof(struct tcphdr))) {
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/* [2] L3/L4 anomaly detection — unconditional, all interfaces. */
	if (is_ip_anomaly(skb) ||
	    (proto == IPPROTO_TCP && is_tcp_anomaly(skb)) ||
	    is_icmp_anomaly(skb)) {
		atomic64_inc(&pkts_anomaly_dropped);
		atomic64_inc(&pkts_dropped);
		return NF_DROP;
	}

	/* [3] Accepted: record per-flow features for the ML daemon.
	 * At the FORWARD hook state->in/out are the flow's actual ingress and
	 * egress interfaces (conntrack stores neither, so we capture them here). */
	ml_account(skb, proto,
		   state->in  ? state->in->ifindex  : 0,
		   state->out ? state->out->ifindex : 0);

	atomic64_inc(&pkts_forwarded);
	return NF_ACCEPT;
}

/* --- procfs: /proc/stargazer/pkt_forward_stats ---------------------------- */

static struct proc_dir_entry *pf_proc_root;   /* /proc/stargazer */
static struct proc_dir_entry *proc_pf_stats;

static int pf_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		"pkts_forwarded=%lld\n"
		"pkts_dropped=%lld\n"
		"pkts_anomaly_dropped=%lld\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&pkts_anomaly_dropped));
	return 0;
}

static int pf_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, pf_stats_show, NULL);
}

static const struct proc_ops pf_stats_proc_ops = {
	.proc_open    = pf_stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static const struct nf_hook_ops nf_forward_ops = {
	.hook     = forward_hook,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_FORWARD,
	/* Sit at the very front of the FORWARD chain — ahead of the filter
	 * table / firewall policy (priority 0) — so malformed/attack packets
	 * are screened before policy evaluation. (Conntrack TRACKING happens
	 * earlier at PRE_ROUTING; there is no conntrack hook at FORWARD, so
	 * the ct read here uses state already established upstream.) */
	.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
};

static int __init pkt_forward_init(void)
{
	int ret;

	ret = nf_defrag_ipv4_enable(&init_net);
	if (ret < 0) {
		pr_err("pkt_forward: failed to enable IPv4 defrag (%d)\n", ret);
		return ret;
	}

	ret = nf_register_net_hook(&init_net, &nf_forward_ops);
	if (ret < 0) {
		nf_defrag_ipv4_disable(&init_net);
		pr_err("pkt_forward: forward hook registration failed (%d)\n", ret);
		return ret;
	}

	/* Create /proc/stargazer/ for the stats file. Failure is non-fatal —
	 * the module still functions without procfs. */
	pf_proc_root = proc_mkdir("stargazer", NULL);
	if (pf_proc_root)
		proc_pf_stats = proc_create("pkt_forward_stats", 0444,
					    pf_proc_root, &pf_stats_proc_ops);
	if (!proc_pf_stats)
		pr_warn("pkt_forward: could not create /proc/stargazer/pkt_forward_stats\n");

	pr_info("pkt_forward: loaded (v%s) — stateless anomaly screen\n",
		PKT_FWD_VERSION);
	return 0;
}

static void __exit pkt_forward_exit(void)
{
	nf_unregister_net_hook(&init_net, &nf_forward_ops);
	nf_defrag_ipv4_disable(&init_net);
	if (proc_pf_stats)
		proc_remove(proc_pf_stats);
	if (pf_proc_root)
		proc_remove(pf_proc_root);
	pr_info("pkt_forward: unloaded (fwd=%lld drop=%lld anomaly=%lld)\n",
		atomic64_read(&pkts_forwarded),
		atomic64_read(&pkts_dropped),
		atomic64_read(&pkts_anomaly_dropped));
}

module_init(pkt_forward_init);
module_exit(pkt_forward_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Stargazer Team");
MODULE_DESCRIPTION("Anomaly-screening FORWARD hook for BPI-R4 NGFW");
MODULE_VERSION(PKT_FWD_VERSION);
MODULE_SOFTDEP("pre: nf_defrag_ipv4");
