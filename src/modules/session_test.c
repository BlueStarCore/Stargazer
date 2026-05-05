// SPDX-License-Identifier: GPL-2.0-only
/*
 * session_test.c — Kernel self-test for the Stargazer session tracking module.
 *
 * Tests the session.ko public API directly, without going through the network
 * stack or any device driver.  Exercises:
 *
 *   sess_lookup_or_create() — create a new session via orig key
 *   sess_update()           — increment per-direction packet/byte counters
 *   sess_lookup_or_create() — find existing session via reply key
 *   sess_delete()           — remove and schedule deferred free
 *
 * On load: runs all tests in module_init, writes results to
 *          /proc/stargazer/session_test as key=value pairs.
 * On unload: removes the procfs entry.
 *
 * Test 5-tuple: 10.88.0.2:55000 → 10.88.1.2:5353 (UDP, pkt_len=32).
 * This subnet (10.88.x.x) is reserved for Stargazer self-tests and
 * must not appear in production traffic.
 */

#define pr_fmt(fmt) "session_test: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/byteorder/generic.h>

#include "session.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Self-test for Stargazer session tracking (session.ko)");
MODULE_SOFTDEP("pre: session");

/* Test 5-tuple ------------------------------------------------------------ */
#define ST_SRC_IP    cpu_to_be32(0x0A580002u)  /* 10.88.0.2 */
#define ST_DST_IP    cpu_to_be32(0x0A580102u)  /* 10.88.1.2 */
#define ST_SPORT     cpu_to_be16(55000u)
#define ST_DPORT     cpu_to_be16(5353u)
#define ST_PROTO     17u                        /* UDP */
#define ST_PKT_LEN   32u                        /* IP+UDP+payload */

/* Results written by module_init, read via procfs -------------------------- */
static char  st_buf[512];
static size_t st_len;

static struct proc_dir_entry *st_proc;

/* procfs show callback */
static int st_show(struct seq_file *m, void *v)
{
	seq_write(m, st_buf, st_len);
	return 0;
}

static int st_open(struct inode *inode, struct file *file)
{
	return single_open(file, st_show, NULL);
}

static const struct proc_ops st_proc_ops = {
	.proc_open    = st_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* -------------------------------------------------------------------------
 * Module init: run all tests, populate st_buf
 * -------------------------------------------------------------------------*/
static int __init session_test_init(void)
{
	struct sess_key orig_key = {
		.src_ip   = ST_SRC_IP,
		.dst_ip   = ST_DST_IP,
		.src_port = ST_SPORT,
		.dst_port = ST_DPORT,
		.proto    = ST_PROTO,
	};
	struct sess_key reply_key = {
		.src_ip   = ST_DST_IP,
		.dst_ip   = ST_SRC_IP,
		.src_port = ST_DPORT,
		.dst_port = ST_SPORT,
		.proto    = ST_PROTO,
	};

	/* Fake skb used only for skb->len in sess_update */
	struct sk_buff *skb = alloc_skb(ST_PKT_LEN, GFP_KERNEL);
	if (!skb) {
		pr_err("alloc_skb failed\n");
		return -ENOMEM;
	}
	skb_put(skb, ST_PKT_LEN);   /* sets skb->len = ST_PKT_LEN */

	/* ── SESS-06/07: create session, verify orig direction ──────────── */
	int dir = -1;
	bool sess_created = false;
	u64  pkts_orig = 0, bytes_orig = 0;

	rcu_read_lock();
	struct session *s = sess_lookup_or_create(&orig_key, &dir);
	if (s) {
		sess_created = (dir == SESS_DIR_ORIG);
		sess_update(s, skb, SESS_DIR_ORIG);
		pkts_orig  = s->stats.pkts_orig;
		bytes_orig = s->stats.bytes_orig;
	}
	rcu_read_unlock();

	if (!s) {
		pr_err("sess_lookup_or_create returned NULL\n");
		kfree_skb(skb);
		return -EFAULT;
	}

	/* ── SESS-09/10: lookup via reply key, verify REPLY direction ───── */
	int dir2 = -1;
	bool reply_found = false;
	u64  pkts_reply = 0;

	rcu_read_lock();
	struct session *sr = sess_lookup_or_create(&reply_key, &dir2);
	if (sr) {
		reply_found = (dir2 == SESS_DIR_REPLY);
		sess_update(sr, skb, SESS_DIR_REPLY);
		pkts_reply = sr->stats.pkts_reply;
	}
	rcu_read_unlock();

	/* ── Clean up test session ─────────────────────────────────────── */
	rcu_read_lock();
	struct session *s_del = sess_lookup(&orig_key);
	if (s_del)
		sess_delete(s_del);
	rcu_read_unlock();

	kfree_skb(skb);

	/* ── Write results in the format cli_diagnose_session.c expects ─── */
	st_len = (size_t)scnprintf(st_buf, sizeof(st_buf),
		"sessions_created=%d\n"
		"pkts_orig=%llu\n"
		"pkts_reply=%llu\n"
		"bytes_orig=%llu\n"
		"bidirectional=%d\n",
		sess_created ? 1 : 0,
		pkts_orig,
		pkts_reply,
		bytes_orig,
		reply_found ? 1 : 0);

	/* Publish results under /proc/stargazer/ (shared dir owned by session.ko) */
	st_proc = proc_create("session_test", 0444, sg_proc_root, &st_proc_ops);
	if (!st_proc)
		pr_warn("could not create /proc/stargazer/session_test\n");

	pr_info("done: created=%d orig=%llu/%llu reply=%llu bidir=%d\n",
		sess_created, pkts_orig, bytes_orig, pkts_reply, reply_found);
	return 0;
}

static void __exit session_test_exit(void)
{
	if (st_proc)
		proc_remove(st_proc);
}

module_init(session_test_init);
module_exit(session_test_exit);
