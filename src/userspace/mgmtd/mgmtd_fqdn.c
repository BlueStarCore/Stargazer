/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_fqdn.c — FQDN address object refresh engine
 *
 * Every fqdn-type firewall_address owns one hash:ip ipset
 * (mgmtd_ipset.c).  iptables rules match the SET, so rule chains never
 * change when DNS answers change — only the set membership does.
 *
 * Refresh model (ACCUMULATE — see mgmtd_ipset.c):
 *   - fqdn_refresh_tick()  — called from the mgmtd main loop; every
 *     SG_FQDN_REFRESH_SEC it snapshots the fqdn objects from the DB
 *     (in-process, parent side) and double-forks a worker that does
 *     the blocking getaddrinfo() + ipset adds.  The main loop never
 *     waits on DNS.
 *   - each resolve MERGES its answers into the set; a re-add refreshes
 *     the entry's kernel timeout.  Round-robin DNS hands out a
 *     different subset every query, so the set converges on the whole
 *     pool instead of flickering between single answers.
 *   - fqdn_refresh_kick()  — forces an immediate worker run; called
 *     after a policy/address apply so a new object converges fast.
 *   - fqdn_object_removed() — destroys the object's set on delete or
 *     rename so sets do not leak.
 *
 * Failure semantics (firewall honesty):
 *   - resolve failure → the worker re-adds the CURRENT members to
 *     refresh their timeouts ("keep-alive"), so a DNS outage never
 *     drains the set: an emptied set silently un-matches DENY rules.
 *     Logged every failing cycle.
 *   - a freshly created object is unenforced until its first resolve
 *     lands (normally < 1 s after apply, via the kicked worker).
 *   - entries a healthy resolver stops returning expire after
 *     SG_IPSET_ENTRY_TIMEOUT_SEC — bounded over-blocking, never
 *     under-blocking.
 *
 * Wildcards (*.example.com) are rejected at validation: matching them
 * needs DNS-response snooping, not periodic resolution (Phase 3 / IPS).
 */

#define _GNU_SOURCE
#include "mgmtd_apply.h"
#include "sg_db.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/file.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SG_FQDN_REFRESH_SEC  60   /* periodic re-resolve interval        */
#define SG_FQDN_MAX_IPS      16   /* A records taken per resolve (logged if more) */
#define SG_FQDN_MAX_OBJS     64   /* fqdn objects per run (logged if more)    */
/* Accumulation means a set can hold many resolves' worth of IPs, so the
 * failure-path keep-alive must cover far more than one answer's cap. */
#define SG_FQDN_KEEPALIVE_MAX 256

struct fqdn_job {
	char set[32];                       /* ipset name                  */
	char fqdn[SG_NET_TARGET_MAX + 1];   /* name to resolve             */
};

/* ── Resolution ────────────────────────────────────────────────────────── */

/*
 * Resolve one FQDN to its IPv4 A records (network byte order, deduped,
 * capped at max).  Returns the count, or -1 on resolver failure.
 */
static int fqdn_resolve(const char *fqdn, uint32_t *out, int max)
{
	struct addrinfo hints, *res = NULL, *ai;
	int n = 0, dropped = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(fqdn, NULL, &hints, &res) != 0)
		return -1;

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET ||
		    ai->ai_addrlen < sizeof(struct sockaddr_in))
			continue;
		uint32_t ip = ((struct sockaddr_in *)ai->ai_addr)
				->sin_addr.s_addr;
		int dup = 0;
		for (int i = 0; i < n; i++)
			if (out[i] == ip) { dup = 1; break; }
		if (dup)
			continue;
		if (n >= max) { dropped++; continue; }
		out[n++] = ip;
	}
	freeaddrinfo(res);

	if (dropped)
		mgmt_log("WARN", "fqdn: '%s' resolves to more than %d "
			 "addresses — %d dropped", fqdn, max, dropped);
	return n;
}

/* ── DB snapshot (parent side — child must not touch SQLite) ──────────── */

/*
 * Collect all fqdn-type address objects into jobs[].
 * Returns the count (0 = nothing to do, -1 = DB error).
 */
static int fqdn_collect_jobs(struct fqdn_job *jobs, int max)
{
	char *list = sg_db_list("firewall_address");
	int n = 0, skipped = 0;

	if (!list)
		return 0;	/* empty table — DB errors also land here */

	char *saveptr = NULL;
	for (char *id = strtok_r(list, "\n", &saveptr); id;
	     id = strtok_r(NULL, "\n", &saveptr)) {
		char *data = sg_db_get("firewall_address", id);
		if (!data)
			continue;

		/* fq must carry a full-length FQDN — the validator accepts
		 * up to SG_NET_TARGET_MAX (253), VALBUFSZ (128) would
		 * silently truncate and resolve the wrong name. */
		char atype[VALBUFSZ], fq[SG_NET_TARGET_MAX + 1];
		extract_val(data, "type", atype, sizeof(atype));
		extract_val(data, "fqdn", fq, sizeof(fq));
		free(data);

		if (strcmp(atype, "fqdn") != 0 || !fq[0])
			continue;
		if (n >= max) { skipped++; continue; }

		sg_fqdn_set_name(id, jobs[n].set, sizeof(jobs[n].set));
		snprintf(jobs[n].fqdn, sizeof(jobs[n].fqdn), "%s", fq);
		n++;
	}
	free(list);

	if (skipped)
		mgmt_log("ERROR", "fqdn: more than %d fqdn objects — %d NOT "
			 "refreshed", max, skipped);
	return n;
}

/* Shared job snapshot buffer — every user runs from the single-threaded
 * mgmtd main loop, never concurrently (the refresh worker gets its own
 * copy via fork). */
static struct fqdn_job g_jobs[SG_FQDN_MAX_OBJS];

/* ── Worker (double-fork, same pattern as stream_exec) ─────────────────── */

/*
 * fqdn_refresh_kick — snapshot the fqdn objects and run the resolves in
 * a detached worker.  The DB snapshot happens in the PARENT (the forked
 * child must never use the inherited SQLite handle); the worker only
 * does getaddrinfo() + netlink.
 */
void fqdn_refresh_kick(void)
{
	struct fqdn_job *jobs = g_jobs;
	int njobs = fqdn_collect_jobs(jobs, SG_FQDN_MAX_OBJS);

	if (njobs <= 0)
		return;

	pid_t wrapper = fork();
	if (wrapper < 0) {
		mgmt_log("ERROR", "fqdn: fork failed: refresh skipped");
		return;
	}
	if (wrapper == 0) {
		/* Wrapper: detach from supervisor bookkeeping (see
		 * stream_exec): reset handlers, close inherited fds,
		 * double-fork so init reaps the worker. */
		signal(SIGCHLD, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGINT,  SIG_DFL);
		for (int fd = 3; fd < 256; fd++)
			close(fd);	/* EBADF on unopened fds is fine */

		pid_t inner = fork();
		if (inner != 0)
			_exit(inner < 0 ? 1 : 0);

		/* Worker.  Serialize against a previous worker that is
		 * still resolving: with a dead/slow resolver one run over
		 * 64 objects can outlast the 60 s tick (musl getaddrinfo
		 * retries for seconds per name), and the parent cannot
		 * waitpid a child reparented to init — so workers gate
		 * themselves on a lock file.  Skipping a round is safe:
		 * membership only ever ages at fqdn-ttl (hours), and the
		 * next tick retries.  Held until _exit releases it. */
		int lk = open("/run/stargazer-fqdn.lock",
			      O_CREAT | O_RDWR | O_CLOEXEC, 0600);
		if (lk < 0) {
			/* Cannot establish the single-flight lock — skip rather
			 * than run unserialized, which under stress (slow
			 * resolver outlasting the tick) would let workers pile
			 * up. Skipping is safe: membership only ages at fqdn-ttl
			 * and the next tick retries. */
			mgmt_log("WARN", "fqdn: cannot open refresh lock (%s) — "
				 "this round skipped", strerror(errno));
			_exit(0);
		}
		if (flock(lk, LOCK_EX | LOCK_NB) != 0) {
			mgmt_log("WARN", "fqdn: previous refresh still "
				 "running — this round skipped");
			_exit(0);
		}

		/* Worker: blocking resolves, then exit. */
		for (int i = 0; i < njobs; i++) {
			uint32_t ips[SG_FQDN_KEEPALIVE_MAX];
			int n = fqdn_resolve(jobs[i].fqdn, ips,
					     SG_FQDN_MAX_IPS);
			if (n <= 0) {
				/* Keep-alive: refresh the timeouts of the
				 * current members so a DNS outage cannot
				 * drain the set (deny rules must not
				 * silently un-match).  n == 0 (resolver
				 * succeeded with zero A records) gets the
				 * same treatment — an answer that would
				 * empty a DENY set is never trusted. */
				const char *why = n < 0 ? "failed"
					: "returned no IPv4 addresses";
				n = sg_ipset_members(jobs[i].set, ips,
						     SG_FQDN_KEEPALIVE_MAX);
				if (n > SG_FQDN_KEEPALIVE_MAX) {
					mgmt_log("ERROR", "fqdn: set %s has "
						 "%d members, keep-alive only "
						 "covers %d — extras may "
						 "expire during the outage",
						 jobs[i].set, n,
						 SG_FQDN_KEEPALIVE_MAX);
					n = SG_FQDN_KEEPALIVE_MAX;
				}
				mgmt_log("WARN", "fqdn: resolve '%s' %s "
					 "— keeping %d last-known member(s) "
					 "alive", jobs[i].fqdn, why,
					 n > 0 ? n : 0);
				if (n <= 0)
					continue;
			}
			int rc = sg_ipset_add(jobs[i].set, ips, n);
			if (rc != 0)
				mgmt_log("ERROR", "fqdn: ipset update %s "
					 "failed (%d)", jobs[i].set, rc);
		}
		_exit(0);
	}

	/* Parent: reap the wrapper (exits in < 1 ms). */
	waitpid(wrapper, NULL, 0);
}

/* ── Periodic tick (mgmtd main loop) ───────────────────────────────────── */

void fqdn_refresh_tick(void)
{
	static time_t next;
	time_t now = time(NULL);

	if (now < next)
		return;
	next = now + SG_FQDN_REFRESH_SEC;
	fqdn_refresh_kick();
}

/*
 * fqdn_restamp_all — re-add every set's current members so they carry
 * the (just-changed) entry timeout immediately, instead of each member
 * keeping its old TTL until a resolve happens to re-confirm it.
 * Netlink only, no DNS — safe to run inline in the daemon.
 */
void fqdn_restamp_all(void)
{
	int njobs = fqdn_collect_jobs(g_jobs, SG_FQDN_MAX_OBJS);

	for (int i = 0; i < njobs; i++) {
		uint32_t ips[SG_FQDN_KEEPALIVE_MAX];
		int n = sg_ipset_members(g_jobs[i].set, ips,
					 SG_FQDN_KEEPALIVE_MAX);
		if (n <= 0)
			continue;	/* no set yet / empty — nothing to do */
		if (n > SG_FQDN_KEEPALIVE_MAX) {
			mgmt_log("ERROR", "fqdn: restamp %s covers only %d of "
				 "%d members — extras keep the old ttl",
				 g_jobs[i].set, SG_FQDN_KEEPALIVE_MAX, n);
			n = SG_FQDN_KEEPALIVE_MAX;
		}
		int rc = sg_ipset_add(g_jobs[i].set, ips, n);
		if (rc != 0)
			mgmt_log("ERROR", "fqdn: restamp %s failed (%d)",
				 g_jobs[i].set, rc);
	}
}

/* ── Lifecycle hooks ───────────────────────────────────────────────────── */

/*
 * fqdn_object_removed — destroy the set of a deleted/renamed object.
 * Callers guarantee no rule references it any more (reference check on
 * delete; rename patches referencing rules then rebuilds).  EBUSY here
 * means a rule still holds the set — log it, never crash the apply.
 */
void fqdn_object_removed(const char *obj_name)
{
	char set[32];
	int rc;

	sg_fqdn_set_name(obj_name, set, sizeof(set));
	rc = sg_ipset_destroy(set);
	if (rc != 0)
		mgmt_log("WARN", "fqdn: destroy set %s (object %s) failed "
			 "(%d) — orphan set until reboot", set, obj_name, rc);
}
