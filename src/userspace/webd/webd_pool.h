/* SPDX-License-Identifier: MIT */
/*
 * webd_pool.h — Thread pool for async IPC dispatch
 *
 * Main thread queues work items; worker threads perform blocking IPC
 * to mgmtd and wake the main thread via mg_wakeup() with the result.
 */

#ifndef WEBD_POOL_H
#define WEBD_POOL_H

#include <stddef.h>
#include <stdint.h>

#include "mongoose.h"

#define WEBD_POOL_SIZE      4       /* worker threads */
#define WEBD_QUEUE_MAX      32      /* max pending work items */

/* Flow types for multi-step IPC operations */
#define FLOW_SIMPLE         0
#define FLOW_LOGIN          1
#define FLOW_CONFIG_LIST    2
#define FLOW_CONFIG_CREATE  3
#define FLOW_CONFIG_UPDATE  4
#define FLOW_RESOURCES      5
#define FLOW_RESOURCES_DET  6
#define FLOW_DIAGNOSE       7
#define FLOW_FIRMWARE_INFO  8
#define FLOW_FIRMWARE_PROG  9
#define FLOW_REBOOT         10
#define FLOW_WHOAMI         11
#define FLOW_CHANGE_PW      12
#define FLOW_RES_RAM        13
#define FLOW_RES_DISK       14
#define FLOW_RES_PROCTOP    15
#define FLOW_ADMIN_CREATE   16
#define FLOW_CONFIG_MOVE    17
#define FLOW_IFACE_LIVE     18
#define FLOW_FIRMWARE_UPLOAD 19
#define FLOW_MONITOR_DHCP    20
#define FLOW_MONITOR_SESSIONS 21
#define FLOW_IPS_STATUS      22
#define FLOW_IPS_ALERTS      23
#define FLOW_IPS_SIGS        24
#define FLOW_IPS_UPDATE      25
#define FLOW_IPS_ALERTS_JSON 26
#define FLOW_IPS_UPDATE_LOG  27
#define FLOW_RES_PERCORE     28

typedef struct {
	unsigned long   conn_id;        /* Mongoose connection ID */
	uint32_t        ipc_cmd;        /* SG_CMD_* to send */
	char            username[64];
	uint64_t        session_tag;
	char           *payload;        /* heap-allocated, worker frees */
	size_t          payload_len;
	int             flow_type;
	char            extra[256];     /* config type, URL path context */
} work_item_t;

typedef struct {
	char   *data;       /* heap-allocated JSON response, main thread frees */
	size_t  data_len;
	int     http_status;
	char    extra_hdrs[256]; /* additional response headers (e.g. Set-Cookie) */
} work_result_t;

/* Initialize the pool with a pointer to the Mongoose manager. */
void  webd_pool_init(struct mg_mgr *mgr);

/*
 * Enqueue a work item. Called from main thread only.
 * Returns 0 on success, -1 if queue is full (caller returns 503).
 * Takes ownership of item->payload.
 */
int   webd_pool_enqueue(work_item_t *item);

/* Shut down pool: signal workers to stop and join all threads. */
void  webd_pool_shutdown(void);

#endif /* WEBD_POOL_H */
