/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */
#ifndef	_DMU_KRRP_H
#define	_DMU_KRRP_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	SBS_UNAVAIL,
	SBS_AVAIL,
	SBS_USED,
	SBS_DONE,
	SBS_DESTROYED,
	SBS_NUMTYPES
} dmu_krrp_state_t;

typedef struct dmu_krrp_task dmu_krrp_task_t;

typedef struct dmu_krrp_stream {
	kmutex_t mtx;
	kcondvar_t cv;
	boolean_t running;
	kthread_t *work_thread;
	void (*task_executor)(void *);
	dmu_krrp_task_t *task;
} dmu_krrp_stream_t;

struct dmu_krrp_task {
	kmutex_t buffer_state_lock;
	kcondvar_t buffer_state_cv;
	kcondvar_t buffer_destroy_cv;
	kreplication_buffer_t *buffer;
	size_t buffer_bytes_read;
	boolean_t is_read;
	boolean_t is_full;
	dmu_krrp_state_t buffer_state;
	int buffer_error;
	dmu_krrp_stream_t *stream_handler;
	kreplication_zfs_args_t buffer_args;
	char cookie[ZFS_MAX_DATASET_NAME_LEN];
};


int dmu_krrp_buffer_write(void *buf, int len,
    dmu_krrp_task_t *krrp_task);
int dmu_krrp_buffer_read(void *buf, int len,
    dmu_krrp_task_t *krrp_task);
int dmu_krrp_arc_bypass(void *buf, int len, void *arg);
int dmu_krrp_direct_arc_read(spa_t *spa, dmu_krrp_task_t *krrp_task,
    zio_cksum_t *zc, const blkptr_t *bp);

typedef int (*dmu_krrp_arc_bypass_cb)(void *, int, dmu_krrp_task_t *);
typedef struct {
	dmu_krrp_task_t *krrp_task;
	zio_cksum_t *zc;
	dmu_krrp_arc_bypass_cb cb;
} dmu_krrp_arc_bypass_t;

#ifdef	__cplusplus
}
#endif

#endif /* _DMU_KRRP_H */
