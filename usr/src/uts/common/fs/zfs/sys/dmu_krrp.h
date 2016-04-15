/*
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */
#ifndef	_DMU_KRRP_H
#define	_DMU_KRRP_H

#ifdef	__cplusplus
extern "C" {
#endif

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
