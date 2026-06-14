/* SPDX-License-Identifier: MIT */
/*
 * mgmtd_apply_ssl.c — Steering traffic HTTPS vào stargazer-ssld (SSL inspection)
 *
 * Khi một accept policy gán `security_ssl-inspection-profile` (enabled), ta
 * REDIRECT các flow TLS được forward vào cổng nghe của ssld bằng một luật
 * trong *nat PREROUTING:
 *
 *   -A PREROUTING -i <srcintf> -p tcp --dport 443 -j REDIRECT --to-ports 8443
 *
 * CHỐNG LOOP — vì sao KHÔNG cần `-m owner` ở đây:
 *   Kết nối ssld mở RA server thật là traffic do CHÍNH firewall sinh ra
 *   (local-out) → đi qua chain OUTPUT, KHÔNG quay lại PREROUTING. Vì vậy luật
 *   REDIRECT ở PREROUTING không bao giờ bắt lại traffic của ssld → không loop.
 *   Cơ chế giới hạn đúng là SCOPE THEO INTERFACE NỘI BỘ (`-i srcintf`): chỉ
 *   redirect traffic ĐẾN TỪ vùng LAN, không đụng traffic box tự sinh, không
 *   đụng traffic vào từ WAN. (`-m owner` chỉ hợp lệ ở OUTPUT/POSTROUTING, đặt
 *   vào PREROUTING sẽ lỗi — nên tuyệt đối không dùng ở đây.)
 *
 * Luật này được nhúng vào *nat restore của rebuild_nat_chains() để cả bảng nat
 * là một lần restore nguyên tử (không xung đột flush với DNAT/SNAT của user).
 *
 * Fail-safe: thiếu config / disabled / input bẩn → KHÔNG emit luật → traffic
 * đi bình thường (không chặn). SSL inspection là tùy chọn, off-by-default.
 */

#include "mgmtd_apply.h"
#include "mgmtd_dynbuf.h"
#include "sg_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>      /* stat — mtime active.rules vào ssld sig */
#include <unistd.h>

#define SSL_PROF_TYPE  "security_ssl-inspection-profile"
#define SSL_PORT_BASE  8443    /* ssld profile #i nghe cổng BASE+i */
#define SSL_SET_FILE   "/run/stargazer-ssld.set"  /* tập profile đang chạy */
#define SSL_DEF_LISTEN "8443"

#define SSLD_BIN       "/sbin/stargazer-ssld"
#define SSLD_CHILD     "stargazer-ssld"
#define SSL_DIR        "/etc/stargazer/ssl"
#define SSL_CACERT     SSL_DIR "/ca-cert.pem"
#define SSL_CAKEY      SSL_DIR "/ca-key.pem"
#define SSL_EXEMPT     SSL_DIR "/exempt.txt"
#define SSL_CFG_SIG    "/run/stargazer-ssld.cfg"
#define SSL_IPS_RULES  "/etc/stargazer/ips/rules/active.rules"

/* Tên interface an toàn cho iptables (chữ/số . _ - @, độ dài hợp lý). */
static int valid_ifname(const char *s)
{
	if (!s || !*s || strlen(s) > 31)
		return 0;
	for (const char *p = s; *p; p++) {
		char c = *p;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') ||
		      c == '.' || c == '_' || c == '-' || c == '@'))
			return 0;
	}
	return 1;
}

static int is_any(const char *s)
{
	return !s || !*s || !strcmp(s, "any") || !strcmp(s, "all");
}

/* Cổng ssld của profile (enabled, != no-inspection) theo INDEX liệt kê DB.
 * Trả >0 nếu active, 0 nếu disabled/no-inspection/không tồn tại. Dùng CHUNG cho
 * ssld_sync (launch) và emit_ssl_steering (redirect) → cổng nhất quán. */
static int ssl_profile_port(const char *name)
{
	if (!name || !*name || strcmp(name, "no-inspection") == 0)
		return 0;
	char *list = sg_db_list(SSL_PROF_TYPE);
	if (!list)
		return 0;
	int port = 0, idx = 0;
	char *sp = NULL;
	for (char *id = strtok_r(list, "\n", &sp); id;
	     id = strtok_r(NULL, "\n", &sp)) {
		if (strcmp(id, "no-inspection") == 0)
			continue;
		char *st = sg_db_get_val(SSL_PROF_TYPE, id, "status");
		int en = st && strcmp(st, "enable") == 0;
		free(st);
		if (!en)
			continue;
		if (strcmp(id, name) == 0) { port = SSL_PORT_BASE + idx; break; }
		idx++;
	}
	free(list);
	return port;
}

/*
 * ssl_steer_allowed — deep SSL inspection CHỈ giải mã khi policy có IPS bật.
 * Trả 1 nếu policy được phép steer vào ssld; 0 nếu profile là DEEP mà IPS của
 * policy tắt → bỏ qua (traffic đi như accept thường, KHÔNG giải mã — đúng yêu
 * cầu "ssl inspection phục vụ IPS"). Certificate mode vốn không giải mã nên
 * luôn cho steer (chỉ peek SNI/splice).
 */
static int ssl_steer_allowed(const char *prof, const char *ips_status,
			     const char *ips_profile)
{
	char *mode = sg_db_get_val(SSL_PROF_TYPE, prof, "inspection-mode");
	int is_deep = mode && strcmp(mode, "deep") == 0;
	free(mode);
	if (is_deep && !ips_policy_on(ips_status, ips_profile))
		return 0;
	return 1;
}

/*
 * emit_ssl_steering — PER-POLICY (FortiGate-style). Mỗi accept policy có
 * ssl-profile (enabled, != no-inspection) → REDIRECT tcp:443 của srcintf policy
 * tới cổng ssld của profile đó. Policy dùng no-inspection → KHÔNG steer (traffic
 * đi thẳng). Fail-safe: input bẩn → bỏ qua policy đó.
 */
int emit_ssl_steering(struct dynbuf *buf)
{
	char *list = sg_db_list("firewall_policy");
	if (!list)
		return 0;
	int n = 0;
	char *sp = NULL;
	for (char *id = strtok_r(list, "\n", &sp); id;
	     id = strtok_r(NULL, "\n", &sp)) {
		char *data = sg_db_get("firewall_policy", id);
		if (!data)
			continue;
		char action[VALBUFSZ], st[VALBUFSZ], srcintf[VALBUFSZ], prof[VALBUFSZ];
		char ipst[VALBUFSZ], ipp[VALBUFSZ];
		extract_val(data, "action",      action,  sizeof(action));
		extract_val(data, "status",      st,      sizeof(st));
		extract_val(data, "srcintf",     srcintf, sizeof(srcintf));
		extract_val(data, "ssl-profile", prof,    sizeof(prof));
		extract_val(data, "ips-status",  ipst,    sizeof(ipst));
		extract_val(data, "ips-profile", ipp,     sizeof(ipp));
		free(data);

		if (strcmp(action, "accept") != 0 || strcmp(st, "enable") != 0)
			continue;
		if (!prof[0] || strcmp(prof, "no-inspection") == 0)
			continue;
		int port = ssl_profile_port(prof);
		if (port <= 0)
			continue;               /* profile disabled/không tồn tại */
		if (!is_any(srcintf) && !valid_ifname(srcintf))
			continue;               /* fail-safe khỏi injection */
		if (!ssl_steer_allowed(prof, ipst, ipp))
			continue;               /* deep nhưng IPS tắt → không giải mã */

		dbuf_printf(buf, "-A PREROUTING");
		if (!is_any(srcintf))
			dbuf_printf(buf, " -i %s", srcintf);
		dbuf_printf(buf, " -p tcp --dport 443 -j REDIRECT --to-ports %d\n",
			    port);
		mgmt_log("INFO", "SSL steering: policy %s prof=%s -i %s tcp:443 "
			 "-> :%d", id, prof, is_any(srcintf) ? "any" : srcintf, port);
		n++;
	}
	free(list);
	return n;
}

/* ── Supervisor: start/stop stargazer-ssld theo config ──────────────────── */

/* Ghi exempt list (SNI cách dấu phẩy/space) ra `path`, mỗi dòng 1 SNI. */
static int write_exempt_to(const char *path, const char *list)
{
	FILE *f = fopen(path, "w");
	if (!f)
		return -1;
	int n = 0;
	if (list && *list) {
		char *dup = strdup(list);
		if (dup) {
			for (char *t = strtok(dup, " ,\t\n"); t;
			     t = strtok(NULL, " ,\t\n")) {
				fprintf(f, "%s\n", t);
				n++;
			}
			free(dup);
		}
	}
	fclose(f);
	return n;
}

/* Tìm dòng "name\t<sig>" trong tập (prev/desired). cmp_sig!=NULL → trả 1 nếu
 * sig khớp; cmp_sig==NULL → trả 1 nếu chỉ cần name tồn tại. */
static int set_has(const char *set, const char *name, const char *cmp_sig)
{
	size_t nl = strlen(name);
	for (const char *p = set; p && *p; ) {
		const char *eol = strchr(p, '\n');
		size_t ll = eol ? (size_t)(eol - p) : strlen(p);
		if (ll > nl && strncmp(p, name, nl) == 0 && p[nl] == '\t') {
			if (!cmp_sig)
				return 1;
			const char *ps = p + nl + 1;
			size_t sl = ll - nl - 1;
			return strlen(cmp_sig) == sl && strncmp(ps, cmp_sig, sl) == 0;
		}
		if (!eol) break;
		p = eol + 1;
	}
	return 0;
}

/*
 * ssld_input_access_sync — mở INPUT cho gói TLS đã REDIRECT vào ssld.
 *
 * Sau REDIRECT (nat PREROUTING) gói đổi đích thành firewall:<ssld_port> → trở
 * thành local-destined → đi qua chain INPUT. Nhưng INPUT có policy DROP và mỗi
 * interface có chain SG_IN_<if> kết thúc bằng `-j DROP`, KHÔNG mở cổng ssld →
 * gói NEW tới cổng ssld bị bỏ, client không bao giờ nhận SYN-ACK (curl treo).
 *
 * Ta mở CHÍNH XÁC traffic đã-redirect: theo (-i srcintf, --dport ssld_port) của
 * từng accept policy đang steer, trong một chain riêng SG_SSLD nhảy từ ĐẦU
 * INPUT (trước các chain per-interface kết thúc DROP). Rebuild wholesale mỗi lần
 * sync (flush + repopulate) nên không tích luỹ rule. Không policy nào steer →
 * chain rỗng → no-op (gói RETURN về INPUT, đi tiếp bình thường). Gọi từ
 * ssld_sync, ngay sau khi steering REDIRECT đã apply.
 */
static void ssld_input_access_sync(void)
{
	/* Chain riêng + jump ở đầu INPUT (idempotent: -D rồi -I → đúng 1 jump). */
	const char *mk[] = {"iptables", "-N", "SG_SSLD", NULL};
	free(safe_exec(mk));                    /* bỏ qua lỗi nếu chain đã có */
	const char *dj[] = {"iptables", "-D", "INPUT", "-j", "SG_SSLD", NULL};
	free(safe_exec(dj));                    /* bỏ qua lỗi nếu jump chưa có */
	const char *ij[] = {"iptables", "-I", "INPUT", "-j", "SG_SSLD", NULL};
	ipt_exec(ij);
	const char *fl[] = {"iptables", "-F", "SG_SSLD", NULL};
	ipt_exec(fl);

	char *list = sg_db_list("firewall_policy");
	if (!list)
		return;
	char *sp = NULL;
	for (char *id = strtok_r(list, "\n", &sp); id;
	     id = strtok_r(NULL, "\n", &sp)) {
		char *data = sg_db_get("firewall_policy", id);
		if (!data)
			continue;
		char action[VALBUFSZ], st[VALBUFSZ], srcintf[VALBUFSZ], prof[VALBUFSZ];
		char ipst[VALBUFSZ], ipp[VALBUFSZ];
		extract_val(data, "action",      action,  sizeof(action));
		extract_val(data, "status",      st,      sizeof(st));
		extract_val(data, "srcintf",     srcintf, sizeof(srcintf));
		extract_val(data, "ssl-profile", prof,    sizeof(prof));
		extract_val(data, "ips-status",  ipst,    sizeof(ipst));
		extract_val(data, "ips-profile", ipp,     sizeof(ipp));
		free(data);

		if (strcmp(action, "accept") != 0 || strcmp(st, "enable") != 0)
			continue;
		if (!prof[0] || strcmp(prof, "no-inspection") == 0)
			continue;
		int port = ssl_profile_port(prof);
		if (port <= 0)
			continue;               /* profile disabled/không tồn tại */
		if (!is_any(srcintf) && !valid_ifname(srcintf))
			continue;               /* fail-safe khỏi injection */
		if (!ssl_steer_allowed(prof, ipst, ipp))
			continue;               /* deep nhưng IPS tắt → không giải mã */

		char portstr[16];
		snprintf(portstr, sizeof(portstr), "%d", port);
		if (is_any(srcintf)) {
			const char *a[] = {"iptables", "-A", "SG_SSLD",
				"-p", "tcp", "-m", "tcp", "--dport", portstr,
				"-j", "ACCEPT", NULL};
			ipt_exec(a);
		} else {
			const char *a[] = {"iptables", "-A", "SG_SSLD",
				"-i", srcintf, "-p", "tcp", "-m", "tcp",
				"--dport", portstr, "-j", "ACCEPT", NULL};
			ipt_exec(a);
		}
		mgmt_log("INFO", "SSL input-access: policy %s -i %s tcp/%d ACCEPT",
			 id, is_any(srcintf) ? "any" : srcintf, port);
	}
	free(list);
}

/*
 * ssld_sync — reconcile MỘT ssld/profile (option-1). Mỗi profile enabled
 * (!= no-inspection) → 1 ssld nghe cổng BASE+idx với settings của profile.
 * Profile xoá/disable/đổi config → stop/restart đúng instance. Gọi SAU
 * rebuild_nat_chains. Child name = "stargazer-ssld-<profile>".
 */
void ssld_sync(void)
{
	/* Migration: dừng ssld single của model cũ nếu còn chạy. */
	if (supervisor_get_pid(SSLD_CHILD) > 0)
		supervisor_stop(SSLD_CHILD);

	char prev[4096] = "";
	FILE *pf = fopen(SSL_SET_FILE, "r");
	if (pf) { size_t r = fread(prev, 1, sizeof(prev) - 1, pf); prev[r] = '\0'; fclose(pf); }

	char desired[4096]; size_t dpos = 0; desired[0] = '\0';
	int have_bin = access(SSLD_BIN, X_OK) == 0;

	/* mtime của active.rules → vào sig mỗi profile: rule đổi → sig đổi → ssld
	 * restart để nạp ruleset mới (ssld nạp rule lúc khởi động, không hot-reload
	 * như ipsd). rebuild_ips_active gọi ssld_sync() sau khi swap active.rules. */
	struct stat rst;
	long rules_mtime = (stat(SSL_IPS_RULES, &rst) == 0) ? (long)rst.st_mtime : 0;

	/* Phase 4: cờ IPC toàn cục (security_ips). ipc-inspect=disable → ssld soi
	 * per-chunk (-Q). ipc-failmode=closed → ssld chặn flow khi IPC lỗi (-F). */
	char *ipc_insp = sg_db_get_val("security_ips", "0", "ipc-inspect");
	char *ipc_fm   = sg_db_get_val("security_ips", "0", "ipc-failmode");
	int ipc_off    = ipc_insp && strcmp(ipc_insp, "disable") == 0;
	int ipc_closed = ipc_fm   && strcmp(ipc_fm, "closed") == 0;
	free(ipc_insp); free(ipc_fm);

	char *list = sg_db_list(SSL_PROF_TYPE);
	int idx = 0;
	if (list) {
		char *sp = NULL;
		for (char *id = strtok_r(list, "\n", &sp); id;
		     id = strtok_r(NULL, "\n", &sp)) {
			if (strcmp(id, "no-inspection") == 0)
				continue;
			char *stt = sg_db_get_val(SSL_PROF_TYPE, id, "status");
			int en = stt && strcmp(stt, "enable") == 0;
			free(stt);
			if (!en)
				continue;
			int port = SSL_PORT_BASE + idx; idx++;

			char *mode  = sg_db_get_val(SSL_PROF_TYPE, id, "inspection-mode");
			char *nosni = sg_db_get_val(SSL_PROF_TYPE, id, "no-sni");
			char *untr  = sg_db_get_val(SSL_PROF_TYPE, id, "untrusted-server-cert");
			char *exempt= sg_db_get_val(SSL_PROF_TYPE, id, "exempt");
			int certificate  = mode  && strcmp(mode, "certificate") == 0;
			int nosni_splice = nosni && strcmp(nosni, "splice") == 0;
			int untr_block   = !untr || strcmp(untr, "block") == 0;

			char exfile[256], portstr[16], child[128], sig[384];
			snprintf(exfile, sizeof(exfile),
				 "/etc/stargazer/ssl/exempt-%s.txt", id);
			write_exempt_to(exfile, exempt);
			snprintf(portstr, sizeof(portstr), "%d", port);
			snprintf(child, sizeof(child), "stargazer-ssld-%s", id);
			snprintf(sig, sizeof(sig), "%d|%d|%d|%d|%d|%d|%ld|%s", port,
				 certificate, nosni_splice, untr_block, ipc_off,
				 ipc_closed, rules_mtime, exempt ? exempt : "");
			dpos += (size_t)snprintf(desired + dpos, sizeof(desired) - dpos,
						 "%s\t%s\n", id, sig);

			int running = supervisor_get_pid(child) > 0;
			if (running && set_has(prev, id, sig)) {
				/* đã chạy đúng config → giữ nguyên */
			} else if (have_bin) {
				if (running) supervisor_stop(child);
				const char *argv[24]; int ai = 0;
				argv[ai++] = SSLD_BIN;
				argv[ai++] = "-p"; argv[ai++] = portstr;
				if (certificate)  argv[ai++] = "-S";
				if (nosni_splice) argv[ai++] = "-B";
				if (untr_block)   argv[ai++] = "-V";
				if (ipc_off)      argv[ai++] = "-Q";   /* P4: tắt IPC */
				if (ipc_closed)   argv[ai++] = "-F";   /* P4: fail-closed */
				if (exempt && *exempt) { argv[ai++] = "-b"; argv[ai++] = exfile; }
				if (access(SSL_IPS_RULES, R_OK) == 0) {
					argv[ai++] = "-r"; argv[ai++] = SSL_IPS_RULES;
				}
				argv[ai++] = "-c"; argv[ai++] = SSL_CACERT;
				argv[ai++] = "-k"; argv[ai++] = SSL_CAKEY;
				argv[ai] = NULL;
				if (supervisor_start(child, argv, SRC_CONFIG,
						     SSL_PROF_TYPE, id, "status", "enable") != 0)
					mgmt_log("ERROR", "ssld_sync: start %s thất bại", child);
				else
					mgmt_log("INFO", "ssld_sync: %s chạy :%d mode=%s",
						 child, port, certificate ? "certificate" : "deep");
			} else {
				mgmt_log("WARN", "ssld_sync: %s không có — profile %s "
					 "không inspect được (HTTPS policy đó có thể đứt)",
					 SSLD_BIN, id);
			}
			free(mode); free(nosni); free(untr); free(exempt);
		}
		free(list);
	}

	/* Dừng instance trong prev không còn trong desired (profile gỡ/disable). */
	for (const char *p = prev; *p; ) {
		const char *eol = strchr(p, '\n');
		size_t ll = eol ? (size_t)(eol - p) : strlen(p);
		const char *tab = memchr(p, '\t', ll);
		if (tab) {
			char name[96];
			size_t nl = (size_t)(tab - p);
			if (nl < sizeof(name)) {
				memcpy(name, p, nl); name[nl] = '\0';
				if (!set_has(desired, name, NULL)) {
					char child[128];
					snprintf(child, sizeof(child),
						 "stargazer-ssld-%s", name);
					if (supervisor_get_pid(child) > 0) {
						supervisor_stop(child);
						mgmt_log("INFO", "ssld_sync: dừng %s "
							 "(profile gỡ/disable)", child);
					}
				}
			}
		}
		if (!eol) break;
		p = eol + 1;
	}

	FILE *wf = fopen(SSL_SET_FILE, "w");
	if (wf) { fwrite(desired, 1, dpos, wf); fclose(wf); }

	/* Mở INPUT cho gói đã REDIRECT vào ssld (nếu không, INPUT DROP nuốt sạch
	 * → client treo). Chạy SAU khi đã biết profile/port nào active. */
	ssld_input_access_sync();
}
