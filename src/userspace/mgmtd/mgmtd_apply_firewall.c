/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_firewall.c — Atomic FORWARD chain rebuild
 *
 * On any firewall_policy change (create, update, delete, move),
 * the entire FORWARD chain is rebuilt from the DB and loaded
 * atomically via iptables-restore --noflush.
 *
 * Flow:
 *   1. Flush FORWARD chain (policy DROP catches all traffic)
 *   2. Read ALL firewall_policy entries from DB in sequence order
 *   3. Generate iptables-restore script in memory:
 *        *filter
 *        -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
 *        -A FORWARD ... (highest sequence first = highest priority)
 *        COMMIT
 *   4. Pipe to iptables-restore --noflush (atomic kernel load)
 *
 * Higher sequence = higher priority = earlier in the chain.
 * Disabled entries are skipped (not in kernel).
 * The FORWARD chain policy (DROP) is set at boot by init_firewall()
 * and is NOT touched by this rebuild — only the rules change.
 *
 * Fields used:
 *   srcintf  — source interface ("any" → omit -i)
 *   dstintf  — destination interface ("any" → omit -o)
 *   srcaddr  — source CIDR ("all"/"any" → omit -s)
 *   dstaddr  — destination CIDR ("all"/"any" → omit -d)
 *   action   — "accept"/"allow" → ACCEPT; "deny" → REJECT; "drop" → DROP
 *   status   — "disable" → skip rule entirely
 *   sequence — priority (higher = checked first)
 */

#include "mgmtd_apply.h"
#include "mgmtd_dynbuf.h"
#include "sg_db.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Address / Service resolution ───────────────────────────────────────── */

/*
 * resolve_address_ex — Resolve a policy/NAT address field.
 *
 *   ADDR_MATCH_ALL — any/all/0.0.0.0/0: omit the -s/-d flag
 *   ADDR_CIDR      — out holds a CIDR for -s/-d
 *   ADDR_IPSET     — out holds an ipset name for -m set --match-set
 *                    (fqdn-type objects; the set is created here so the
 *                    emitted rule always references an existing set —
 *                    membership is filled by the FQDN refresh engine)
 *   ADDR_SKIP      — dangling/unenforceable: skip the rule (fail-closed)
 */
enum addr_kind resolve_address_ex(const char *val, char *out, size_t outsz)
{
	if (!val || !val[0])
		return ADDR_MATCH_ALL;

	/* "any" and "all" are match-all keywords — no DB lookup needed */
	if (strcmp(val, "any") == 0 || strcmp(val, "all") == 0)
		return ADDR_MATCH_ALL;

	/* Raw CIDR passthrough (backward compat for NAT legacy data) */
	if (sg_is_cidr(val)) {
		if (strcmp(val, "0.0.0.0/0") == 0)
			return ADDR_MATCH_ALL;
		snprintf(out, outsz, "%s", val);
		return ADDR_CIDR;
	}

	/* Look up firewall_address entry */
	char *data = sg_db_get("firewall_address", val);
	if (!data) {
		mgmt_log("ERROR", "resolve_address: '%s' not found", val);
		return ADDR_SKIP;
	}

	char atype[VALBUFSZ], subnet[VALBUFSZ];
	extract_val(data, "type",   atype,  sizeof(atype));
	extract_val(data, "subnet", subnet, sizeof(subnet));
	free(data);

	if (strcmp(atype, "fqdn") == 0) {
		if (!sg_ipset_available()) {
			mgmt_log("ERROR", "resolve_address: '%s' is an FQDN "
				 "object but the kernel lacks ipset support "
				 "— rule skipped (fail-closed)", val);
			return ADDR_SKIP;
		}
		sg_fqdn_set_name(val, out, outsz);
		if (sg_ipset_ensure(out) != 0) {
			mgmt_log("ERROR", "resolve_address: cannot create "
				 "ipset %s for '%s' — rule skipped "
				 "(fail-closed)", out, val);
			return ADDR_SKIP;
		}
		return ADDR_IPSET;
	}

	if (!subnet[0] || !sg_is_cidr(subnet)) {
		mgmt_log("ERROR", "resolve_address: '%s' invalid subnet",
			 val);
		return ADDR_SKIP;
	}

	/* 0.0.0.0/0 = match-all → omit flag for cleaner rules */
	if (strcmp(subnet, "0.0.0.0/0") == 0)
		return ADDR_MATCH_ALL;

	snprintf(out, outsz, "%s", subnet);
	return ADDR_CIDR;
}

/*
 * resolve_address — legacy single-CIDR resolver, kept for the NAT path.
 *
 * Returns:
 *   pointer to out  — resolved CIDR (caller uses it)
 *   NULL            — match-all (0.0.0.0/0), omit -s/-d flag
 *   "SKIP"          — not found, or an fqdn-type object: NAT rules
 *                     cannot match a DNS-derived set (fail-closed)
 */
const char *resolve_address(const char *val, char *out, size_t outsz)
{
	switch (resolve_address_ex(val, out, outsz)) {
	case ADDR_MATCH_ALL:
		return NULL;
	case ADDR_CIDR:
		return out;
	case ADDR_IPSET:
		mgmt_log("ERROR", "resolve_address: FQDN object '%s' is not "
			 "supported in NAT rules — rule skipped", val);
		return "SKIP";
	case ADDR_SKIP:
	default:
		return "SKIP";
	}
}

/*
 * resolve_service — Look up a firewall_service entry.
 *
 * Returns:
 *   0  = match-all (no service filter)
 *   1  = resolved, proto_out and port_out filled
 *  -1  = not found (dangling ref — skip rule, fail-closed)
 */
static int resolve_service(const char *val,
			   char *proto_out, size_t psz,
			   char *port_out, size_t ptsz)
{
	proto_out[0] = '\0';
	port_out[0] = '\0';

	if (!val || !val[0])
		return 0;

	char *data = sg_db_get("firewall_service", val);
	if (!data) {
		mgmt_log("ERROR", "resolve_service: '%s' not found", val);
		return -1;
	}

	extract_val(data, "protocol", proto_out, psz);
	extract_val(data, "port-range", port_out, ptsz);
	free(data);

	if (!proto_out[0]) {
		mgmt_log("ERROR", "resolve_service: '%s' no protocol", val);
		return -1;
	}

	/* protocol=all means no filtering */
	if (strcmp(proto_out, "all") == 0)
		return 0;

	return 1;
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

static const char *action_to_target(const char *action)
{
	if (strcmp(action, "accept") == 0 || strcmp(action, "allow") == 0)
		return "ACCEPT";
	if (strcmp(action, "deny") == 0)
		return "REJECT";
	return "DROP";
}

/* ── Rebuild ─────────────────────────────────────────────────────────────── */

/*
 * connmark_supported - probe once whether iptables can use the connmark
 * match + CONNMARK target (needs CONFIG_NF_CONNTRACK_MARK + xt_connmark).
 * Result is cached. When available we re-evaluate live flows on a policy change
 * via a connmark DIRTY bit + per-flow policy_id; when not, we fall back to
 * flushing the whole conntrack table.
 */
static int connmark_supported(void)
{
	static int cached = -1;
	if (cached >= 0)
		return cached;

	const char *newc[]   = {"iptables", "-N", "SG_CMK_PROBE", NULL};
	const char *addc[]   = {"iptables", "-A", "SG_CMK_PROBE",
				"-m", "connmark", "--mark", "0/0xff",
				"-j", "CONNMARK", "--set-xmark", "0/0xff", NULL};
	const char *flushc[] = {"iptables", "-F", "SG_CMK_PROBE", NULL};
	const char *delc[]   = {"iptables", "-X", "SG_CMK_PROBE", NULL};

	ipt_exec(newc);
	cached = (ipt_exec(addc) == 0) ? 1 : 0;
	ipt_exec(flushc);
	ipt_exec(delc);

	mgmt_log("INFO", "connmark %s; policy changes %s",
		 cached ? "available" : "unavailable",
		 cached ? "re-evaluate only affected live flows"
			: "flush conntrack (fallback)");
	return cached;
}

/*
 * connbytes_supported — probe xt_connbytes availability (cached).
 *
 * xt_connbytes needs CONFIG_NETFILTER_XT_MATCH_CONNBYTES=y/m + module load.
 * If unavailable: the NFQUEUE rule falls back to --ctstate NEW (SYN packets
 * only, the old behaviour). The fallback is less effective (it never sees
 * payload data packets) but the ML + L1 pipeline still runs and does not crash.
 */
static int connbytes_supported(void)
{
	static int cached = -1;
	if (cached >= 0)
		return cached;

	const char *newc[]   = {"iptables", "-N", "SG_CB_PROBE", NULL};
	const char *addc[]   = {"iptables", "-A", "SG_CB_PROBE",
				"-m", "connbytes",
				"--connbytes-dir", "both",
				"--connbytes-mode", "bytes",
				"--connbytes", "0:16384", "-j", "RETURN", NULL};
	const char *flushc[] = {"iptables", "-F", "SG_CB_PROBE", NULL};
	const char *delc[]   = {"iptables", "-X", "SG_CB_PROBE", NULL};

	ipt_exec(newc);
	cached = (ipt_exec(addc) == 0) ? 1 : 0;
	ipt_exec(flushc);
	ipt_exec(delc);

	mgmt_log("INFO", "xt_connbytes(mode bytes) %s; IPS NFQUEUE rule uses %s",
		 cached ? "available" : "unavailable",
		 cached ? "bidirectional connbytes byte-window (P1)"
			: "--ctstate NEW (SYN-only fallback)");
	return cached;
}

/*
 * mark_target_supported — probe xt_MARK (cached). Per-policy IPS scoping sets the
 * skb mark = profile-id before NFQUEUE so ipsd filters signatures by the flow's
 * profile. Without CONFIG_NETFILTER_XT_TARGET_MARK → do NOT emit MARK
 * (iptables-restore is atomic: one bad rule breaks the WHOLE chain) → ipsd gets
 * prof_id=0 → inspects against ALL rules (fail-safe = the old global behaviour).
 * Scoping degrades gracefully and does not break IPS.
 */
static int mark_target_supported(void)
{
	static int cached = -1;
	if (cached >= 0)
		return cached;

	const char *newc[]   = {"iptables", "-N", "SG_MK_PROBE", NULL};
	const char *addc[]   = {"iptables", "-A", "SG_MK_PROBE",
				"-j", "MARK", "--set-xmark", "0x1/0xff", NULL};
	const char *flushc[] = {"iptables", "-F", "SG_MK_PROBE", NULL};
	const char *delc[]   = {"iptables", "-X", "SG_MK_PROBE", NULL};

	ipt_exec(newc);
	cached = (ipt_exec(addc) == 0) ? 1 : 0;
	ipt_exec(flushc);
	ipt_exec(delc);

	mgmt_log("INFO", "xt_MARK %s; per-policy IPS scoping %s",
		 cached ? "available" : "unavailable",
		 cached ? "ON (skb mark = profile-id)"
			: "OFF → ipsd inspects globally (fail-safe)");
	return cached;
}

/*
 * Per-flow connmark layout (FortiGate-style dirty-session):
 *   bit 0      DIRTY     — set on flows that must re-traverse the policy chain
 *   bits 1-7   reserved  (kept 0)
 *   bits 8-31  policy_id — the cmkid of the policy that last permitted the flow
 *
 * An ACCEPT rule stamps (cmkid << 8) and clears DIRTY in one masked write, so a
 * permitted flow records its policy and fast-paths. The fast-path rule accepts
 * ESTABLISHED,RELATED only while DIRTY is clear; a flow marked dirty (by
 * conntrack_mark_dirty_by_policy on a policy change) falls through and is
 * re-evaluated against the current chain — still-allowed flows get re-stamped,
 * denied flows fall to DROP. The DIRTY bit is non-destructive: the connection
 * tracking entry is kept, so a still-allowed flow resumes the moment one
 * original-direction packet re-stamps it (clearing DIRTY heals both directions,
 * since connmark is per-entry). The policy rules match the original direction
 * only, so during the brief dirty window a reply-direction-only packet finds no
 * fast-path and no matching rule and is dropped until the original direction
 * re-stamps — for TCP this is absorbed by ACK/retransmit; bursty asymmetric
 * flows may see a momentary blip, not a teardown.
 */
#define SG_CMK_DIRTY       0x00000001u
#define SG_CMK_PID_SHIFT   8
#define SG_CMK_STAMP_MASK  0xFFFFFF01u   /* policy_id field + DIRTY bit */

/* IPS connmark bits — MUST match src/userspace/ipsd/nfq.h. */
#define SG_CMK_IPS_BLOCK     0x00000002u   /* flow convicted by ipsd → DROP all packets */
#define SG_CMK_IPS_INSPECTED 0x00000004u   /* verdict reached → skip re-queueing        */

/* IPS profile id carried in the connmark (bits 3-7 → 1..31) — MUST match
 * src/userspace/ipsd/nfq.h. Used on the HTTPS deep-inspection path: the bumped
 * flow is REDIRECTed to ssld and never hits the FORWARD NFQUEUE MARK rule, so the
 * profile id is stamped into the connmark at PREROUTING and ipsd recovers it from
 * conntrack (CTA_MARK) on the inspection IPC. */
#define SG_CMK_IPS_PROFID_SHIFT 3
#define SG_CMK_IPS_PROFID_MASK  0x000000F8u   /* bits 3-7 — profile id 1..31      */

/* Bit map: IPS uses bits 1-2 + profid bits 3-7, must NOT overlap DIRTY (bit 0) or
 * policy_id (bits 8-31). Asserted at compile time. */
_Static_assert((SG_CMK_IPS_BLOCK | SG_CMK_IPS_INSPECTED) ==
	       0x00000006u, "IPS bits must be 1-2");
_Static_assert(((SG_CMK_IPS_BLOCK | SG_CMK_IPS_INSPECTED | SG_CMK_IPS_PROFID_MASK) &
		(SG_CMK_DIRTY | 0xFFFFFF00u)) == 0,
	       "IPS bits overlap DIRTY/policy_id");
_Static_assert((31u << SG_CMK_IPS_PROFID_SHIFT) == SG_CMK_IPS_PROFID_MASK,
	       "profid 31 must fill the profid mask");

/* Validate config security_ips for CFG_SET (no kernel changes). */
sg_status_t validate_ips(const char *id, const char *data,
			 char *result, size_t rsize)
{
	(void)id;
	char status[VALBUFSZ], mode[VALBUFSZ], queue[VALBUFSZ];
	extract_val(data, "status",    status, sizeof(status));
	extract_val(data, "mode",      mode,   sizeof(mode));
	extract_val(data, "queue-num", queue,  sizeof(queue));

	if (status[0] && strcmp(status, "enable") && strcmp(status, "disable")) {
		snprintf(result, rsize, "status must be enable/disable");
		return SG_ERR_INVALID_VAL;
	}
	if (mode[0] && strcmp(mode, "detect") && strcmp(mode, "prevent")) {
		snprintf(result, rsize, "mode must be detect/prevent");
		return SG_ERR_INVALID_VAL;
	}
	if (queue[0]) {
		for (const char *p = queue; *p; p++)
			if (*p < '0' || *p > '9') {
				snprintf(result, rsize, "queue-num must be a number");
				return SG_ERR_INVALID_VAL;
			}
		int v = atoi(queue);
		if (v < 0 || v > 65535) {
			snprintf(result, rsize, "queue-num out of range [0,65535]");
			return SG_ERR_INVALID_VAL;
		}
	}
	snprintf(result, rsize, "IPS config valid");
	return SG_OK;
}

/*
 * ips_profile_active — does the policy have IPS?
 * Returns 1 if `name` points to an existing security_ips-profile with
 * status=enable (not "none"/empty). Nonexistent / disabled profile → 0
 * (fail-safe: no inspection, no NFQUEUE emitted). Replaces the old literal
 * "default" check.
 */
static int ips_profile_active(const char *name)
{
	if (!name || !name[0] || strcmp(name, "none") == 0)
		return 0;
	char *st = sg_db_get_val("security_ips-profile", name, "status");
	int ok = st && strcmp(st, "enable") == 0;
	if (st && !ok)
		mgmt_log("INFO", "ips_profile_active: profile '%s' disabled — "
			 "policy will not run IPS", name);
	free(st);
	if (!st)
		mgmt_log("WARN", "ips_profile_active: profile '%s' does not exist "
			 "— policy will not run IPS", name);
	return ok;
}

/*
 * ips_policy_on — does the policy enable IPS, per the ips-status toggle.
 * Backward compatible: status="disable" → explicitly off; "enable" → per profile;
 * EMPTY (old policy without ips-status) → old fallback logic (per profile, i.e.
 * profile != none/disabled). This means NO DB migration is needed.
 */
int ips_policy_on(const char *status, const char *profile)
{
	if (status && strcmp(status, "disable") == 0)
		return 0;
	return ips_profile_active(profile);
}

/*
 * Read IPS state: returns 1 if security_ips status=enable, fills *queue.
 * Steering is only emitted when enabled (off-by-default, fail-safe).
 */
static int ips_enabled(int *queue, int *snapshot_n, int *snapshot_bytes)
{
	if (queue)         *queue         = 0;
	if (snapshot_n)    *snapshot_n    = 8;       /* default */
	if (snapshot_bytes) *snapshot_bytes = 16384;  /* default K (P1) */
	char *st = sg_db_get_val("security_ips", "0", "status");
	int on = st && strcmp(st, "enable") == 0;
	free(st);
	if (on) {
		if (queue) {
			char *q = sg_db_get_val("security_ips", "0",
						"queue-num");
			if (q && q[0]) {
				int v = atoi(q);
				if (v >= 0 && v <= 65535)
					*queue = v;
			}
			free(q);
		}
		if (snapshot_n) {
			char *sn = sg_db_get_val("security_ips", "0",
						 "snapshot-n");
			if (sn && sn[0]) {
				int v = atoi(sn);
				if (v >= 1 && v <= 64)
					*snapshot_n = v;
			}
			free(sn);
		}
		if (snapshot_bytes) {
			char *sb = sg_db_get_val("security_ips", "0",
						 "snapshot-bytes");
			if (sb && sb[0]) {
				int v = atoi(sb);
				if (v >= 1024 && v <= 262144)
					*snapshot_bytes = v;
			}
			free(sb);
		}
	}
	return on;
}

/*
 * ipsd_sync — synchronise the stargazer-ipsd lifecycle with the NFQUEUE state.
 *
 * Uses mgmtd's supervisor_start() / supervisor_stop() — the same mechanism that
 * manages webd/udhcpc: fork()+exec() in spawn_child(), SIGTERM to stop with a
 * waitpid(WNOHANG) poll over 3s then SIGKILL, and SIGCHLD+reap_children() in the
 * main loop to handle zombies and restart on crash.
 *
 * `active=1` + ipsd not running → supervisor_start() → fork()+exec() ipsd.
 * `active=0` + ipsd running      → supervisor_stop() → SIGTERM → reap.
 * State already matches          → do nothing (avoids needless restarts).
 *
 * Fail-safe: missing binary/ruleset → log a warning, do not start.
 */
#define IPSD_CHILD_NAME "stargazer-ipsd"
#define IPSD_BIN        "/sbin/stargazer-ipsd"
#define IPSD_RULES      "/etc/stargazer/ips/rules/active.rules"
#define IPSD_MODE_FILE  "/run/stargazer-ipsd.mode"  /* mode of the running ipsd */

/* Effective mode from DB: "detect" if DB=detect, otherwise "prevent". */
static const char *ips_mode_str(void)
{
	char *m = sg_db_get_val("security_ips", "0", "mode");
	int detect = m && strcmp(m, "detect") == 0;
	free(m);
	return detect ? "detect" : "prevent";
}

static void ipsd_sync(int active, int queue_num)
{
	int running = (supervisor_get_pid(IPSD_CHILD_NAME) > 0);

	/* Mode is set via a CLI flag at start → changing the mode in the DB
	 * requires a RESTART of ipsd. Compare the DB mode with the running ipsd's
	 * mode (stored in /run/...mode); if they differ → stop so the start branch
	 * below relaunches with the new flag RIGHT in this apply (no manual
	 * reboot/toggle needed). */
	if (active && running) {
		const char *want = ips_mode_str();
		char cur[16] = "";
		FILE *mf = fopen(IPSD_MODE_FILE, "r");
		if (mf) { if (!fgets(cur, sizeof(cur), mf)) cur[0] = '\0'; fclose(mf); }
		char *nl = strchr(cur, '\n'); if (nl) *nl = '\0';
		if (strcmp(cur, want) != 0) {
			mgmt_log("INFO", "ipsd_sync: mode %s→%s — restarting ipsd",
				 cur[0] ? cur : "?", want);
			supervisor_stop(IPSD_CHILD_NAME);
			running = 0;   /* → start branch relaunches with the new mode */
		}
	}

	if (active && !running) {
		/* Check the binary + ruleset exist before forking */
		if (access(IPSD_BIN,   X_OK) != 0 ||
		    access(IPSD_RULES, R_OK) != 0) {
			mgmt_log("WARN", "ipsd_sync: %s or %s does not exist "
				 "— IPS not started",
				 IPSD_BIN, IPSD_RULES);
			return;
		}

		char qarg[16];
		snprintf(qarg, sizeof(qarg), "%d", queue_num);
		/* Pass mode via CLI: ipsd's load_config_from_mgmtd is not trusted
		 * (it assembles its own IPC request), so read the mode from the DB
		 * here and pass the -d (detect) flag directly. The ipsd default is
		 * PREVENT; -d → DETECT (alert, no drop). Changing mode requires
		 * restarting ipsd (toggle IPS or reboot). */
		const char *mode = ips_mode_str();
		int detect = strcmp(mode, "detect") == 0;
		/* Record the mode being started so a later apply detects a mode change → restart. */
		FILE *mf = fopen(IPSD_MODE_FILE, "w");
		if (mf) { fprintf(mf, "%s\n", mode); fclose(mf); }
		const char *argv[8];
		int ai = 0;
		argv[ai++] = IPSD_BIN;
		argv[ai++] = "-q"; argv[ai++] = qarg;
		argv[ai++] = "-r"; argv[ai++] = IPSD_RULES;
		if (detect) argv[ai++] = "-d";
		argv[ai] = NULL;

		/*
		 * SRC_CONFIG: the supervisor only restarts after a crash if
		 * security_ips.default.status is still "enable". When the admin disables
		 * IPS (status=disable → rebuild_forward_chain → ipsd_sync(0))
		 * supervisor_stop() sets restart_max=0 first → no restart.
		 */
		int rc = supervisor_start(IPSD_CHILD_NAME, argv,
					  SRC_CONFIG,
					  "security_ips", "0",
					  "status", "enable");
		if (rc != 0)
			mgmt_log("ERROR", "ipsd_sync: supervisor_start failed");

	} else if (!active && running) {
		supervisor_stop(IPSD_CHILD_NAME);
		mgmt_log("INFO", "ipsd_sync: stopping ipsd "
			 "(no policy uses an IPS profile anymore)");
	}
	/* active == running: do nothing */
}

sg_status_t rebuild_forward_chain(char *result, size_t rsize)
{
	struct dynbuf buf;
	if (dbuf_init(&buf, 4096) < 0) {
		snprintf(result, rsize, "Out of memory");
		return SG_ERR_SYSTEM_FAIL;
	}

	int cmk = connmark_supported();

	/* Header */
	dbuf_append(&buf, "*filter\n", 8);

	/* Foundation rules (conntrack-stateful):
	 *   - drop packets conntrack cannot associate with a valid flow (INVALID);
	 *   - fast-path accept of established/related return traffic. */
	int ips_q = 0, ips_sbytes = 16384;
	int ips_on = ips_enabled(&ips_q, NULL, &ips_sbytes);
	{
		const char *inv = "-A FORWARD -m conntrack --ctstate INVALID -j DROP\n";
		dbuf_append(&buf, inv, strlen(inv));

		/* [IPS] flow already convicted by ipsd → DROP all packets, BEFORE
		 * the fast-path accept (so ESTABLISHED packets of a bad flow are
		 * still blocked). */
		if (ips_on)
			dbuf_printf(&buf,
				"-A FORWARD -m connmark --mark 0x%x/0x%x -j DROP\n",
				SG_CMK_IPS_BLOCK, SG_CMK_IPS_BLOCK);

		/*
		 * [IPS] Inspection window: when IPS is on + connbytes is available,
		 * the ESTABLISHED fast-path only applies to flows that have ALREADY
		 * EXCEEDED K bytes. Within the first K bytes, ESTABLISHED packets
		 * (request/response data) do NOT fast-path but fall through to the
		 * per-policy NFQUEUE so ipsd can inspect the payload. Without this
		 * gate the fast-path accepts every ESTABLISHED data packet outright →
		 * ipsd only sees the SYN (NEW) and content signatures NEVER match
		 * (tcp_payload=0).
		 */
		char cbw[160] = "";
		if (ips_on && connbytes_supported())
			snprintf(cbw, sizeof(cbw),
				 " -m connbytes --connbytes %d:"
				 " --connbytes-mode bytes --connbytes-dir both",
				 ips_sbytes);

		if (cmk)
			/* Established/related flows fast-path ONLY while their DIRTY
			 * bit is clear. A flow marked dirty on a policy change falls
			 * through to the policy rules below for re-evaluation. */
			dbuf_printf(&buf,
				"-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED%s"
				" -m connmark ! --mark 0x%x/0x%x -j ACCEPT\n",
				cbw, SG_CMK_DIRTY, SG_CMK_DIRTY);
		else
			dbuf_printf(&buf,
				"-A FORWARD -m conntrack"
				" --ctstate ESTABLISHED,RELATED%s -j ACCEPT\n", cbw);

		/* IPS NFQUEUE: emitted per-policy (FortiGate-style), NOT globally here.
		 * Only an accept policy with ips-profile != none (profile enabled) emits
		 * NFQUEUE, right before that policy's ACCEPT rule in the loop below. */
	}

	/* Read all policies ordered by sequence DESC (highest first) */
	char *list = sg_db_list_ordered("firewall_policy", "sequence");
	int rule_count = 0;

	if (list) {
		char *saveptr = NULL;
		for (char *id = strtok_r(list, "\n", &saveptr);
		     id;
		     id = strtok_r(NULL, "\n", &saveptr)) {

			char *data = sg_db_get("firewall_policy", id);
			if (!data)
				continue;

			char srcintf[VALBUFSZ], dstintf[VALBUFSZ];
			char srcaddr[VALBUFSZ], dstaddr[VALBUFSZ];
			char action[VALBUFSZ], status[VALBUFSZ];
			char service[VALBUFSZ], cmkid_s[VALBUFSZ];
			char ips_profile[VALBUFSZ], ips_status[VALBUFSZ];

			extract_val(data, "srcintf",     srcintf,     sizeof(srcintf));
			extract_val(data, "dstintf",     dstintf,     sizeof(dstintf));
			extract_val(data, "srcaddr",     srcaddr,     sizeof(srcaddr));
			extract_val(data, "dstaddr",     dstaddr,     sizeof(dstaddr));
			extract_val(data, "action",      action,      sizeof(action));
			extract_val(data, "status",      status,      sizeof(status));
			extract_val(data, "service",     service,     sizeof(service));
			extract_val(data, "cmkid",       cmkid_s,     sizeof(cmkid_s));
			extract_val(data, "ips-profile", ips_profile, sizeof(ips_profile));
			extract_val(data, "ips-status",  ips_status,  sizeof(ips_status));

			free(data);

			/* Stable per-policy id stamped into connmark bits 8-31 so a
			 * flow records which policy permitted it (0 = none/unstamped). */
			unsigned long cmkid = strtoul(cmkid_s, NULL, 10);

			if (strcmp(status, "disable") == 0)
				continue;

			const char *target = action_to_target(action);

			/* Build rule line */
			size_t rule_start = buf.used;
			dbuf_printf(&buf, "-A FORWARD");

			if (srcintf[0] && strcmp(srcintf, "any") != 0)
				dbuf_printf(&buf, " -i %s", srcintf);
			if (dstintf[0] && strcmp(dstintf, "any") != 0)
				dbuf_printf(&buf, " -o %s", dstintf);
			/* Resolve address objects.  CIDR objects emit -s/-d;
			 * fqdn objects emit an ipset match — the rule then
			 * follows DNS changes via set membership without
			 * ever rebuilding the chain. */
			{
				char resolved[VALBUFSZ];
				switch (resolve_address_ex(srcaddr, resolved,
							   sizeof(resolved))) {
				case ADDR_SKIP:
					goto skip_rule;
				case ADDR_CIDR:
					dbuf_printf(&buf, " -s %s", resolved);
					break;
				case ADDR_IPSET:
					dbuf_printf(&buf, " -m set"
						    " --match-set %s src",
						    resolved);
					break;
				case ADDR_MATCH_ALL:
					break;
				}
			}
			{
				char resolved[VALBUFSZ];
				switch (resolve_address_ex(dstaddr, resolved,
							   sizeof(resolved))) {
				case ADDR_SKIP:
					goto skip_rule;
				case ADDR_CIDR:
					dbuf_printf(&buf, " -d %s", resolved);
					break;
				case ADDR_IPSET:
					dbuf_printf(&buf, " -m set"
						    " --match-set %s dst",
						    resolved);
					break;
				case ADDR_MATCH_ALL:
					break;
				}
			}

			/* Resolve service object */
			char svc_proto[VALBUFSZ];
			svc_proto[0] = '\0';
			{
				char svc_port[VALBUFSZ];
				int svc_rc = resolve_service(service,
					svc_proto, sizeof(svc_proto),
					svc_port, sizeof(svc_port));
				if (svc_rc < 0)
					goto skip_rule;
				if (svc_rc == 1 && svc_proto[0]) {
					dbuf_printf(&buf, " -p %s", svc_proto);
					/* ICMP has no ports */
					if (svc_port[0] &&
					    strcmp(svc_proto, "icmp") != 0)
						dbuf_printf(&buf, " --dport %s",
							    svc_port);
				}
			}

			/*
			 * deny → REJECT: TCP gets RST so the sender fails
			 * immediately; everything else gets ICMP port-unreachable.
			 *
			 * When the service is "any" (svc_proto empty) we cannot
			 * know the protocol at rule-build time, so we split into
			 * two rules: a TCP-specific rule with --reject-with
			 * tcp-reset, followed by a catch-all for the rest.
			 * The prefix is copied to a stack buffer before the first
			 * dbuf_printf because that call may reallocate buf.data.
			 */
			if (strcmp(target, "REJECT") == 0 &&
			    svc_proto[0] == '\0') {
				size_t plen = buf.used - rule_start;
				char saved_pfx[256];
				if (plen < sizeof(saved_pfx)) {
					memcpy(saved_pfx, buf.data + rule_start,
					       plen);
					dbuf_printf(&buf,
						" -p tcp"
						" -j REJECT"
						" --reject-with tcp-reset\n");
					rule_count++;
					dbuf_append(&buf, saved_pfx, plen);
					dbuf_printf(&buf, " -j REJECT\n");
					rule_count++;
				} else {
					/* Safety: prefix overflowed — emit plain REJECT */
					dbuf_printf(&buf, " -j REJECT\n");
					rule_count++;
				}
			} else if (strcmp(target, "REJECT") == 0 &&
				   strcmp(svc_proto, "tcp") == 0) {
				dbuf_printf(&buf,
					" -j REJECT --reject-with tcp-reset\n");
				rule_count++;
			} else {
				/*
				 * For ACCEPT rules (when connmark is available and the
				 * policy has a stable cmkid), prepend a CONNMARK rule that
				 * stamps the policy_id into bits 8-31 and clears the DIRTY
				 * bit, so the flow records its policy and fast-paths.
				 * Uses the same saved_pfx technique as the REJECT split.
				 * DENY/DROP flows are never stamped, so a dirtied flow the
				 * new policy denies keeps falling through to its drop.
				 */
				if (strcmp(target, "ACCEPT") == 0) {
					/*
					 * An ACCEPT policy may emit 1-3 rules sharing a
					 * common match prefix. Save the prefix ONCE into
					 * saved_pfx, then after each sub-rule re-APPEND
					 * saved_pfx to form the prefix for the next rule —
					 * do NOT truncate buf.used (that would erase the
					 * rule just emitted).
					 *
					 * Order (FortiGate-style, per ips-profile):
					 *   [IPS]  <match> connbytes 0:K bytes both → NFQUEUE
					 *          ipsd reassembles the stream + inspects the
					 *          first K bytes (both directions) of each flow
					 *          (P1). NF_ACCEPT; NF_DROP+BLOCK on detection.
					 *          `! INSPECTED` lets ipsd offload early.
					 *   [CMK]  <match> → CONNMARK (stamp policy_id)
					 *          <match> → ACCEPT
					 *
					 * connbytes-mode bytes --connbytes-dir both: counts
					 * BYTES in both directions. Past K → rule no longer
					 * matches → flow goes straight through (already
					 * inspected the full window). Closes segment-splitting/
					 * direction-flipping/small-MSS evasion. No
					 * --queue-bypass: ipsd dies → fail-closed. Fallback
					 * (kernel lacks connbytes mode bytes): ctstate NEW
					 * (SYN-only) — pipeline still runs, less effective.
					 */
					size_t pfx_len = buf.used - rule_start;
					char saved_pfx[256];
					int pfx_ok = (pfx_len < sizeof(saved_pfx));
					if (pfx_ok)
						memcpy(saved_pfx,
						       buf.data + rule_start,
						       pfx_len);

					if (pfx_ok && ips_on &&
					    ips_policy_on(ips_status, ips_profile)) {

						/* [MARK] Carry the IPS profile-id down to
						 * ipsd via the skb mark (NFQA_MARK) →
						 * per-policy scoping: ipsd applies only this
						 * profile's signatures to the flow. Uses the skb
						 * mark instead of connmark because the device
						 * kernel lacks glue_ct (NFQA_CT is unreliable).
						 * low byte = bit+1 (0 = none). MARK is non-
						 * terminating → the packet continues down to the
						 * NFQUEUE already carrying the mark. Set on the
						 * bare prefix (every packet of the flow within the
						 * K-byte window gets marked). */
						int pid = ips_profid(ips_profile);
						if (pid >= 1 && mark_target_supported()) {
							dbuf_printf(&buf,
							    " -j MARK --set-xmark"
							    " 0x%x/0xff\n", pid);
							dbuf_append(&buf, saved_pfx,
								    pfx_len);
							rule_count++;
						}

						if (connbytes_supported()) {
							dbuf_printf(&buf,
							    " -m connbytes"
							    " --connbytes-dir both"
							    " --connbytes-mode bytes"
							    " --connbytes 0:%d"
							    " -m connmark"
							    " ! --mark 0x%x/0x%x"
							    " -j NFQUEUE"
							    " --queue-num %d\n",
							    ips_sbytes,
							    SG_CMK_IPS_INSPECTED,
							    SG_CMK_IPS_INSPECTED,
							    ips_q);
						} else {
							/* Fallback: only feed NEW packets to IPS */
							dbuf_printf(&buf,
							    " -m conntrack"
							    " --ctstate NEW"
							    " -m connmark"
							    " ! --mark 0x%x/0x%x"
							    " -j NFQUEUE"
							    " --queue-num %d\n",
							    SG_CMK_IPS_INSPECTED,
							    SG_CMK_IPS_INSPECTED,
							    ips_q);
						}

						rule_count++;
						/* re-append prefix for next rule */
						dbuf_append(&buf, saved_pfx, pfx_len);
					}


					if (pfx_ok && cmk && cmkid > 0) {
						dbuf_printf(&buf,
							" -j CONNMARK --set-xmark"
							" 0x%lx/0x%x\n",
							(cmkid << SG_CMK_PID_SHIFT),
							SG_CMK_STAMP_MASK);
						rule_count++;
						/* re-append prefix for ACCEPT */
						dbuf_append(&buf, saved_pfx, pfx_len);
					}
				}
				dbuf_printf(&buf, " -j %s\n", target);
				rule_count++;
			}
			continue; /* success — skip the rollback below */
		skip_rule:
			buf.used = rule_start; /* roll back partial -A FORWARD write */
		}
		free(list);
	}

	dbuf_append(&buf, "COMMIT\n", 7);

	/* Flush FORWARD chain.  During this brief window the chain
	 * policy (DROP) catches all forwarded traffic — fail-closed. */
	const char *flush[] = {"iptables", "-F", "FORWARD", NULL};
	ipt_exec(flush);

	/* Atomic restore — only adds to FORWARD (--noflush keeps
	 * INPUT and OUTPUT untouched). */
	const char *restore[] = {"iptables-restore", "--noflush", NULL};
	int exit_code = 0;
	char *out = pipe_exec_stdin(restore, buf.data, buf.used, &exit_code);

	if (exit_code != 0) {
		mgmt_log("ERROR", "rebuild_forward_chain: iptables-restore "
			 "failed (exit %d): %s", exit_code,
			 out ? out : "");
		free(out);
		free(buf.data);
		/* Recovery: at minimum restore the ESTABLISHED,RELATED rule */
		flush_forward_chain();
		snprintf(result, rsize, "FORWARD chain rebuild failed");
		return SG_ERR_SYSTEM_FAIL;
	}

	free(out);
	free(buf.data);

	/* Newly created fqdn sets are empty until their first resolve —
	 * kick the refresh worker now so they converge in well under a
	 * second instead of waiting for the periodic tick.  Detached
	 * worker: never blocks the apply (or boot replay) on DNS. */
	fqdn_refresh_kick();

	/*
	 * IPS daemon lifecycle: start ipsd if there are NFQUEUE rules in the
	 * just-rebuilt chain, stop it if there are none. mgmtd is the sole manager
	 * of ipsd — init does not start ipsd directly (just as webd is supervised
	 * by mgmtd).
	 *
	 * "nfqueue_active" = ips_on AND at least one accept policy + ips-profile.
	 * Simple counting approach: re-read the DB rather than threading a counter
	 * through — rebuild already read the DB once, re-reading is idempotent and
	 * keeps the function simple.
	 */
	{
		int nfqueue_active = 0;
		if (ips_on) {
			char *list = sg_db_list("firewall_policy");
			if (list) {
				char *sp = NULL;
				for (char *id = strtok_r(list, "\n", &sp);
				     id; id = strtok_r(NULL, "\n", &sp)) {
					char *d = sg_db_get("firewall_policy", id);
					if (!d) continue;
					char act[VALBUFSZ], ipp[VALBUFSZ], st[VALBUFSZ];
					char ipst[VALBUFSZ];
					extract_val(d, "action",      act, sizeof(act));
					extract_val(d, "ips-profile", ipp, sizeof(ipp));
					extract_val(d, "ips-status",  ipst, sizeof(ipst));
					extract_val(d, "status",      st,  sizeof(st));
					free(d);
					if (strcmp(st, "disable") == 0) continue;
					if ((strcmp(act, "accept") == 0 ||
					     strcmp(act, "allow")  == 0) &&
					    ips_policy_on(ipst, ipp)) {
						nfqueue_active = 1;
						break;
					}
				}
				free(list);
			}
		}
		/*
		 * Build active.rules BEFORE ipsd_sync. At boot, reconcile runs
		 * rebuild_forward_chain before active.rules is built → ipsd_sync sees
		 * active.rules missing → does NOT start ipsd (even though a profile is
		 * attached). Building it here (only when a policy uses IPS) ensures the
		 * file exists exactly when ipsd_sync checks → ipsd can start from the
		 * very first boot.
		 */
		if (nfqueue_active) {
			char rb[256];
			rebuild_ips_active(rb, sizeof(rb));
		}
		ipsd_sync(nfqueue_active, ips_q);
	}

	/* NOTE: rebuild only rewrites the rules. Applying the change to LIVE flows
	 * (marking them dirty so they re-traverse, or flushing in the no-connmark
	 * fallback) is a separate step the caller invokes via
	 * conntrack_reeval_after_policy_change() — boot replay skips it. */
	snprintf(result, rsize, "FORWARD chain rebuilt (%d rules)", rule_count);
	return SG_OK;
}

/*
 * conntrack_reeval_after_policy_change - force live flows to be re-evaluated
 * against the just-rebuilt FORWARD chain. Call AFTER rebuild_forward_chain()
 * on any real policy change (not boot replay).
 *
 * pid == 0 dirties all flows; pid == cmkid(P) dirties only flows that policy P
 * permitted. Narrowing is used only where it cannot newly-shadow other flows
 * (deleting P, or an action/comment-only edit of P — see policy_reeval_scope);
 * every other change passes 0. With connmark we mark flows dirty
 * (non-destructive: allowed flows re-stamp and continue, denied flows drop).
 * Without connmark, or if the dirty pass fails, we fall back to flushing the
 * whole conntrack table.
 */
void conntrack_reeval_after_policy_change(unsigned int pid)
{
	if (!connmark_supported()) {
		conntrack_flush_all();
		return;
	}
	if (conntrack_mark_dirty_by_policy(pid) != 0)
		conntrack_flush_all();   /* fallback: never leave stale fast-path marks */
}

/*
 * validate_firewall_policy — field validation only, no kernel changes.
 * Used by CFG_APPLY (test run) so it doesn't duplicate rules.
 */
sg_status_t validate_firewall_policy(const char *id, const char *data,
				     char *result, size_t rsize)
{
	char action[VALBUFSZ], srcintf[VALBUFSZ], dstintf[VALBUFSZ];

	extract_val(data, "action",  action,  sizeof(action));
	extract_val(data, "srcintf", srcintf, sizeof(srcintf));
	extract_val(data, "dstintf", dstintf, sizeof(dstintf));

	if (action[0] == '\0') {
		snprintf(result, rsize, "Missing 'action'");
		return SG_ERR_MISSING_ARG;
	}

	if (strcmp(action, "accept") != 0 && strcmp(action, "allow") != 0 &&
	    strcmp(action, "deny")   != 0 && strcmp(action, "drop")  != 0) {
		snprintf(result, rsize, "Invalid action '%s' (accept/deny/drop)",
			 action);
		return SG_ERR_INVALID_VAL;
	}

	if (srcintf[0] && strcmp(srcintf, "any") != 0 &&
	    !sg_is_iface_name(srcintf)) {
		snprintf(result, rsize, "Invalid srcintf '%s'", srcintf);
		return SG_ERR_INVALID_VAL;
	}

	if (dstintf[0] && strcmp(dstintf, "any") != 0 &&
	    !sg_is_iface_name(dstintf)) {
		snprintf(result, rsize, "Invalid dstintf '%s'", dstintf);
		return SG_ERR_INVALID_VAL;
	}

	/* IPS profile is only valid on an ACCEPT policy — DENY/DROP drop packets
	 * at L4, leaving no payload to inspect. Like FortiGate: the security
	 * profile tab is hidden entirely on a DENY policy. */
	{
		char ips_profile[VALBUFSZ];
		extract_val(data, "ips-profile", ips_profile, sizeof(ips_profile));
		int is_accept = (strcmp(action, "accept") == 0 ||
				 strcmp(action, "allow") == 0);
		if (!is_accept && ips_profile[0] &&
		    strcmp(ips_profile, "none") != 0 &&
		    strcmp(ips_profile, "default") != 0) {
			snprintf(result, rsize,
				 "ips-profile cannot be set on policy '%s' "
				 "(only valid for action=accept)",
				 action);
			return SG_ERR_INVALID_VAL;
		}
		/* ips-status (toggle) can also only be enabled on ACCEPT. */
		char ips_status[VALBUFSZ];
		extract_val(data, "ips-status", ips_status, sizeof(ips_status));
		if (!is_accept && strcmp(ips_status, "enable") == 0) {
			snprintf(result, rsize,
				 "ips cannot be enabled on policy '%s' "
				 "(only valid for action=accept)", action);
			return SG_ERR_INVALID_VAL;
		}
	}

	/* SSL inspection is also only valid on ACCEPT — DENY/DROP drop packets at
	 * L4, leaving no TLS to decrypt. The built-in "no-inspection" = off, so it
	 * is always allowed. */
	{
		char ssl_profile[VALBUFSZ];
		extract_val(data, "ssl-profile", ssl_profile, sizeof(ssl_profile));
		int is_accept = (strcmp(action, "accept") == 0 ||
				 strcmp(action, "allow") == 0);
		if (!is_accept && ssl_profile[0] &&
		    strcmp(ssl_profile, "no-inspection") != 0) {
			snprintf(result, rsize,
				 "ssl-profile cannot be set on policy '%s' "
				 "(only valid for action=accept)",
				 action);
			return SG_ERR_INVALID_VAL;
		}
	}

	/* Enforce unique policy name across all firewall_policy entries.
	 * Skip the check when id is empty (defensive) or name is not set. */
	if (id && id[0]) {
		char name[VALBUFSZ];
		extract_val(data, "name", name, sizeof(name));
		if (name[0]) {
			char *matches = sg_db_find_referencing(
				"firewall_policy", "name", name);
			if (matches) {
				int dup = 0;
				char *copy = strdup(matches);
				if (!copy) {
					free(matches);
					snprintf(result, rsize, "Out of memory");
					return SG_ERR_SYSTEM_FAIL;
				}
				char *sp   = NULL;
				for (char *t = strtok_r(copy, "\n", &sp);
				     t; t = strtok_r(NULL, "\n", &sp)) {
					/* sg_db_find_referencing returns "type:id" */
					const char *colon = strchr(t, ':');
					const char *found_id = colon ? colon + 1 : t;
					if (found_id[0] && strcmp(found_id, id) != 0) {
						dup = 1;
						break;
					}
				}
				free(copy);
				free(matches);
				if (dup) {
					snprintf(result, rsize,
						 "Policy name '%s' is already in use",
						 name);
					return SG_ERR_INVALID_VAL;
				}
			}
		}
	}

	snprintf(result, rsize, "Policy %s validated", id ? id : "");
	return SG_OK;
}

