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
 * xt_connbytes cần CONFIG_NETFILTER_XT_MATCH_CONNBYTES=y/m + module load.
 * Nếu không có: NFQUEUE rule fallback về --ctstate NEW (chỉ gói SYN, giống
 * cách cũ). Fallback ít hiệu quả hơn (không thấy payload data packets) nhưng
 * pipeline ML + L1 vẫn chạy, không crash.
 */
static int connbytes_supported(void)
{
	static int cached = -1;
	if (cached >= 0)
		return cached;

	const char *newc[]   = {"iptables", "-N", "SG_CB_PROBE", NULL};
	const char *addc[]   = {"iptables", "-A", "SG_CB_PROBE",
				"-m", "connbytes",
				"--connbytes-dir", "original",
				"--connbytes-mode", "packets",
				"--connbytes", "0:7", "-j", "RETURN", NULL};
	const char *flushc[] = {"iptables", "-F", "SG_CB_PROBE", NULL};
	const char *delc[]   = {"iptables", "-X", "SG_CB_PROBE", NULL};

	ipt_exec(newc);
	cached = (ipt_exec(addc) == 0) ? 1 : 0;
	ipt_exec(flushc);
	ipt_exec(delc);

	mgmt_log("INFO", "xt_connbytes %s; IPS NFQUEUE rule uses %s",
		 cached ? "available" : "unavailable",
		 cached ? "connbytes (N-packet gate)"
			: "--ctstate NEW (SYN-only fallback)");
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

/* IPS connmark bits — PHẢI khớp src/userspace/ipsd/nfq.h. */
#define SG_CMK_IPS_BLOCK     0x00000002u   /* flow ipsd kết án → mọi gói DROP   */
#define SG_CMK_IPS_INSPECTED 0x00000004u   /* đã có verdict → khỏi queue lại    */

/* Validate config security_ips cho CFG_SET (không đụng kernel). */
sg_status_t validate_ips(const char *id, const char *data,
			 char *result, size_t rsize)
{
	(void)id;
	char status[VALBUFSZ], mode[VALBUFSZ], queue[VALBUFSZ];
	extract_val(data, "status",    status, sizeof(status));
	extract_val(data, "mode",      mode,   sizeof(mode));
	extract_val(data, "queue-num", queue,  sizeof(queue));

	if (status[0] && strcmp(status, "enable") && strcmp(status, "disable")) {
		snprintf(result, rsize, "status phải là enable/disable");
		return SG_ERR_INVALID_VAL;
	}
	if (mode[0] && strcmp(mode, "detect") && strcmp(mode, "prevent")) {
		snprintf(result, rsize, "mode phải là detect/prevent");
		return SG_ERR_INVALID_VAL;
	}
	if (queue[0]) {
		for (const char *p = queue; *p; p++)
			if (*p < '0' || *p > '9') {
				snprintf(result, rsize, "queue-num phải là số");
				return SG_ERR_INVALID_VAL;
			}
		int v = atoi(queue);
		if (v < 0 || v > 65535) {
			snprintf(result, rsize, "queue-num ngoài [0,65535]");
			return SG_ERR_INVALID_VAL;
		}
	}
	snprintf(result, rsize, "IPS config hợp lệ");
	return SG_OK;
}

/*
 * Đọc trạng thái IPS: trả 1 nếu security_ips status=enable, điền *queue.
 * Steering chỉ phát khi bật (off-by-default, fail-safe).
 */
static int ips_enabled(int *queue, int *snapshot_n)
{
	if (queue)    *queue    = 0;
	if (snapshot_n) *snapshot_n = 8;   /* default */
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
	}
	return on;
}

/*
 * ipsd_sync — đồng bộ lifecycle stargazer-ipsd với trạng thái NFQUEUE.
 *
 * Dùng supervisor_start() / supervisor_stop() của mgmtd — đây là cùng cơ
 * chế quản lý webd/udhcpc: fork()+exec() trong spawn_child(), SIGTERM để
 * stop với waitpid(WNOHANG) poll 3s rồi SIGKILL, SIGCHLD+reap_children()
 * trong main loop xử lý zombie và restart khi crash.
 *
 * `active=1` + ipsd chưa chạy  → supervisor_start() → fork()+exec() ipsd.
 * `active=0` + ipsd đang chạy  → supervisor_stop() → SIGTERM → reap.
 * Trạng thái khớp              → không làm gì (ngăn restart không cần).
 *
 * Fail-safe: binary/ruleset thiếu → log cảnh báo, không start.
 */
#define IPSD_CHILD_NAME "stargazer-ipsd"
#define IPSD_BIN        "/sbin/stargazer-ipsd"
#define IPSD_RULES      "/etc/stargazer/ips/rules/active.rules"

static void ipsd_sync(int active, int queue_num)
{
	int running = (supervisor_get_pid(IPSD_CHILD_NAME) > 0);

	if (active && !running) {
		/* Kiểm tra binary + ruleset tồn tại trước khi fork */
		if (access(IPSD_BIN,   X_OK) != 0 ||
		    access(IPSD_RULES, R_OK) != 0) {
			mgmt_log("WARN", "ipsd_sync: %s hoặc %s không tồn tại "
				 "— IPS không được khởi động",
				 IPSD_BIN, IPSD_RULES);
			return;
		}

		char qarg[16];
		snprintf(qarg, sizeof(qarg), "%d", queue_num);
		const char *argv[] = {
			IPSD_BIN, "-q", qarg, "-r", IPSD_RULES, NULL
		};

		/*
		 * SRC_CONFIG: supervisor chỉ restart sau crash nếu
		 * security_ips.default.status vẫn là "enable". Khi admin tắt
		 * IPS (status=disable → rebuild_forward_chain → ipsd_sync(0))
		 * supervisor_stop() set restart_max=0 trước → không restart.
		 */
		int rc = supervisor_start(IPSD_CHILD_NAME, argv,
					  SRC_CONFIG,
					  "security_ips", "0",
					  "status", "enable");
		if (rc != 0)
			mgmt_log("ERROR", "ipsd_sync: supervisor_start thất bại");

	} else if (!active && running) {
		supervisor_stop(IPSD_CHILD_NAME);
		mgmt_log("INFO", "ipsd_sync: dừng ipsd "
			 "(không còn policy nào dùng ips-profile=default)");
	}
	/* active == running: không làm gì */
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
	int ips_q = 0, ips_snap = 8;
	int ips_on = ips_enabled(&ips_q, &ips_snap);
	{
		const char *inv = "-A FORWARD -m conntrack --ctstate INVALID -j DROP\n";
		dbuf_append(&buf, inv, strlen(inv));

		/* [IPS] flow đã bị ipsd kết án → DROP mọi gói, TRƯỚC fast-path
		 * accept (để gói ESTABLISHED của flow xấu vẫn bị chặn). */
		if (ips_on)
			dbuf_printf(&buf,
				"-A FORWARD -m connmark --mark 0x%x/0x%x -j DROP\n",
				SG_CMK_IPS_BLOCK, SG_CMK_IPS_BLOCK);

		if (cmk)
			/* Established/related flows fast-path ONLY while their DIRTY
			 * bit is clear. A flow marked dirty on a policy change falls
			 * through to the policy rules below for re-evaluation. */
			dbuf_printf(&buf,
				"-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED"
				" -m connmark ! --mark 0x%x/0x%x -j ACCEPT\n",
				SG_CMK_DIRTY, SG_CMK_DIRTY);
		else
			dbuf_printf(&buf,
				"-A FORWARD -m conntrack"
				" --ctstate ESTABLISHED,RELATED -j ACCEPT\n");

		/* IPS NFQUEUE: đặt per-policy (FortiGate-style), KHÔNG global ở đây.
		 * Chỉ policy accept có ips-profile=default mới emit rule NFQUEUE,
		 * ngay trước rule ACCEPT của policy đó trong vòng lặp bên dưới. */
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
			char ips_profile[VALBUFSZ];

			extract_val(data, "srcintf",     srcintf,     sizeof(srcintf));
			extract_val(data, "dstintf",     dstintf,     sizeof(dstintf));
			extract_val(data, "srcaddr",     srcaddr,     sizeof(srcaddr));
			extract_val(data, "dstaddr",     dstaddr,     sizeof(dstaddr));
			extract_val(data, "action",      action,      sizeof(action));
			extract_val(data, "status",      status,      sizeof(status));
			extract_val(data, "service",     service,     sizeof(service));
			extract_val(data, "cmkid",       cmkid_s,     sizeof(cmkid_s));
			extract_val(data, "ips-profile", ips_profile, sizeof(ips_profile));

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
					 * ACCEPT policy có thể emit 1-3 rule dùng chung
					 * match prefix. Lưu prefix ONCE vào saved_pfx, rồi
					 * sau mỗi sub-rule APPEND lại saved_pfx để tạo prefix
					 * cho rule tiếp theo — KHÔNG truncate buf.used (làm
					 * thế sẽ xóa mất rule vừa emit).
					 *
					 * Thứ tự (FortiGate-style, theo ips-profile):
					 *   [IPS]  <match> connbytes 0:(N-1) → NFQUEUE
					 *          ipsd nhận N gói đầu mỗi flow, trả
					 *          NF_ACCEPT; NF_DROP+BLOCK khi phát hiện.
					 *   [CMK]  <match> → CONNMARK (stamp policy_id)
					 *          <match> → ACCEPT
					 *
					 * connbytes-dir original: chỉ đếm gói từ initiator.
					 * Sau N gói, connbytes > N-1 → rule không match →
					 * flow đi thẳng qua CONNMARK+ACCEPT. Không loop.
					 * Không --queue-bypass: ipsd chết → fail-closed.
					 */
					size_t pfx_len = buf.used - rule_start;
					char saved_pfx[256];
					int pfx_ok = (pfx_len < sizeof(saved_pfx));
					if (pfx_ok)
						memcpy(saved_pfx,
						       buf.data + rule_start,
						       pfx_len);

					if (pfx_ok && ips_on &&
					    strcmp(ips_profile, "default") == 0) {
						if (connbytes_supported()) {
							/* N-packet gate: inspect first
							 * snapshot_n packets/direction */
							dbuf_printf(&buf,
								" -m connbytes"
								" --connbytes-dir original"
								" --connbytes-mode packets"
								" --connbytes 0:%d"
								" -j NFQUEUE"
								" --queue-num %d\n",
								ips_snap - 1, ips_q);
						} else {
							/* Fallback: only SYN (NEW) — ML
							 * + L1 rules still work; L2 payload
							 * signature sees empty payload on TCP.
							 * Add CONFIG_NETFILTER_XT_MATCH_CONNBYTES
							 * to kernel for full inspection. */
							dbuf_printf(&buf,
								" -m conntrack"
								" --ctstate NEW"
								" -j NFQUEUE"
								" --queue-num %d\n",
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
	 * IPS daemon lifecycle: start ipsd nếu có NFQUEUE rules trong chain vừa
	 * rebuild, stop nếu không có. mgmtd là người duy nhất quản lý ipsd —
	 * init không start ipsd trực tiếp (đúng như webd được mgmtd supervise).
	 *
	 * "nfqueue_active" = ips_on VÀ có ít nhất một policy accept + ips-profile.
	 * Cách đếm đơn giản: đọc lại DB thay vì truyền counter qua — rebuild đã
	 * đọc DB một lần rồi, đọc lại là idempotent và giữ hàm đơn giản.
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
					extract_val(d, "action",      act, sizeof(act));
					extract_val(d, "ips-profile", ipp, sizeof(ipp));
					extract_val(d, "status",      st,  sizeof(st));
					free(d);
					if (strcmp(st, "disable") == 0) continue;
					if ((strcmp(act, "accept") == 0 ||
					     strcmp(act, "allow")  == 0) &&
					    strcmp(ipp, "default") == 0) {
						nfqueue_active = 1;
						break;
					}
				}
				free(list);
			}
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

	/* IPS profile chỉ hợp lệ trên ACCEPT policy — DENY/DROP drop gói ở L4,
	 * không có payload để inspect. Giống FortiGate: security profile tab ẩn
	 * hoàn toàn trên DENY policy. */
	{
		char ips_profile[VALBUFSZ];
		extract_val(data, "ips-profile", ips_profile, sizeof(ips_profile));
		int is_accept = (strcmp(action, "accept") == 0 ||
				 strcmp(action, "allow") == 0);
		if (!is_accept && ips_profile[0] &&
		    strcmp(ips_profile, "none") != 0) {
			snprintf(result, rsize,
				 "ips-profile không thể đặt trên policy '%s' "
				 "(chỉ hợp lệ cho action=accept)",
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

