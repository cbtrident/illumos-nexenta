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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Writecache basics.
 * ZFS allows to store up to 3 dva per block pointer. Normally, all of the dvas
 * are valid at all time (or at least supposed to be so, and if data under a
 * dva is broken it is repaired with data under another dva). WRC alters the
 * behaviour. Each cached with wrc block has two dvas, and validity of them
 * changes during time. At first, when zfs decides to chace a block with wrc,
 * two dvas are allocated: one on a special device and one on a normal one.
 * Data is written to the special dva only. At the time the special dva is
 * valid and the normal one contains garbage. Later, after move operation is
 * performed for a block, i.e. the data stored under the special dva is copied
 * to the place pointed by the normal dva, the special dva is freed and can be
 * reused and the normal dva now valid and contains actual data.
 * To let zfs know which dva is valid and which is not, all data is moved by
 * chunks bounded with birth txg. When a new chunck of data should be moved, a
 * snapshot (recursive, starting at the very root dataset) is created. the
 * snapshot is used to perform simple traverse over it and not to miss any
 * block. The txg boundaries are from old_move_snap_txg + 1 to new_move_snap.
 * Checking blocks' birth txg against those boundaries, zfs understand which
 * dva is valid at the moment.
 */

#include <sys/fm/fs/zfs.h>
#include <sys/special.h>
#include <sys/spa_impl.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/zap.h>
#include <sys/zil.h>
#include <sys/ddt.h>
#include <sys/dmu_traverse.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_scan.h>
#include <sys/dsl_prop.h>
#include <sys/arc.h>
#include <sys/vdev_impl.h>
#include <sys/mutex.h>
#include <sys/time.h>
#include <sys/arc.h>
#include <sys/zio_compress.h>
#include <sys/zfs_ioctl.h>
#ifdef _KERNEL
#include <sys/ddi.h>
#endif

extern int zfs_txg_timeout;
extern int zfs_scan_min_time_ms;
extern uint64_t zfs_dirty_data_sync;
extern uint64_t krrp_debug;

typedef enum {
	WRC_READ_FROM_SPECIAL = 1,
	WRC_WRITE_TO_NORMAL,
} wrc_io_type_t;

/*
 * timeout (in seconds) that is used to schedule a job that moves
 * blocks from a special device to other deivices in a pool
 */
int zfs_wrc_schedtmo = 0;

uint64_t zfs_wrc_data_max = 48 << 20; /* Max data to migrate in a pass */

uint64_t wrc_mv_cancel_threshold_initial = 20;
/* we are not sure if we need logic of threshold increment */
uint64_t wrc_mv_cancel_threshold_step = 0;
uint64_t wrc_mv_cancel_threshold_cap = 50;

static boolean_t wrc_check_space(spa_t *spa);

static void wrc_free_block(wrc_block_t *block);
static void wrc_clean_tree(wrc_data_t *wrc_data, avl_tree_t *tree);
static void wrc_clean_plan_tree(wrc_data_t *wrc_data);
static void wrc_clean_moved_tree(wrc_data_t *wrc_data);

static void wrc_activate_impl(spa_t *spa, boolean_t pool_creation);
static wrc_block_t *wrc_create_block(wrc_data_t *wrc_data,
    const blkptr_t *bp);
static void wrc_move_block(void *arg);
static int wrc_move_block_impl(wrc_block_t *block);
static int wrc_collect_special_blocks(dsl_pool_t *dp);
static void wrc_close_window(wrc_data_t *wrc_data);
static void wrc_write_update_window(void *void_spa, dmu_tx_t *tx);

static int wrc_io(wrc_io_type_t type, wrc_block_t *block, void *data);
static int wrc_blocks_compare(const void *arg1, const void *arg2);
static int wrc_instances_compare(const void *arg1, const void *arg2);

static void wrc_unregister_instance_impl(wrc_instance_t *wrc_instance,
    boolean_t rele_autosnap);
static void wrc_unregister_instances(wrc_data_t *wrc_data);
static wrc_instance_t *wrc_register_instance(wrc_data_t *wrc_data,
    objset_t *os);
static void wrc_unregister_instance(wrc_data_t *wrc_data, objset_t *os,
    boolean_t rele_autosnap);
static wrc_instance_t *wrc_lookup_instance(wrc_data_t *wrc_data,
    uint64_t ds_object, avl_index_t *where);
static void wrc_rele_autosnaps(wrc_data_t *wrc_data, uint64_t txg_to_rele,
    boolean_t purge);

void
wrc_init(wrc_data_t *wrc_data, spa_t *spa)
{
	(void) memset(wrc_data, 0, sizeof (wrc_data_t));

	wrc_data->wrc_spa = spa;

	mutex_init(&wrc_data->wrc_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&wrc_data->wrc_cv, NULL, CV_DEFAULT, NULL);

	avl_create(&wrc_data->wrc_blocks, wrc_blocks_compare,
	    sizeof (wrc_block_t), offsetof(wrc_block_t, node));
	avl_create(&wrc_data->wrc_moved_blocks, wrc_blocks_compare,
	    sizeof (wrc_block_t), offsetof(wrc_block_t, node));
	avl_create(&wrc_data->wrc_instances, wrc_instances_compare,
	    sizeof (wrc_instance_t), offsetof(wrc_instance_t, node));

	wrc_data->wrc_instance_fini = taskq_create("wrc_instance_finalization",
	    1, maxclsyspri, 50, INT_MAX, TASKQ_PREPOPULATE);
}

void
wrc_fini(wrc_data_t *wrc_data)
{
	taskq_wait(wrc_data->wrc_instance_fini);
	taskq_destroy(wrc_data->wrc_instance_fini);

	mutex_enter(&wrc_data->wrc_lock);

	wrc_clean_plan_tree(wrc_data);
	wrc_clean_moved_tree(wrc_data);

	avl_destroy(&wrc_data->wrc_blocks);
	avl_destroy(&wrc_data->wrc_moved_blocks);
	avl_destroy(&wrc_data->wrc_instances);

	mutex_exit(&wrc_data->wrc_lock);

	cv_destroy(&wrc_data->wrc_cv);
	mutex_destroy(&wrc_data->wrc_lock);

	wrc_data->wrc_spa = NULL;
}

#ifndef _KERNEL
/*ARGSUSED*/
static clock_t
drv_usectohz(uint64_t time)
{
	return (1000);
}
#endif

static wrc_block_t *
wrc_create_block(wrc_data_t *wrc_data, const blkptr_t *bp)
{
	wrc_block_t *block;

	block = kmem_alloc(sizeof (*block), KM_NOSLEEP);
	if (block == NULL)
		return (NULL);

	/*
	 * Fill information describing data we need to move
	 */
#ifdef _KERNEL
	DTRACE_PROBE6(wrc_plan_block_data,
	    uint64_t, BP_PHYSICAL_BIRTH(bp),
	    uint64_t, DVA_GET_VDEV(&bp->blk_dva[0]),
	    uint64_t, DVA_GET_OFFSET(&bp->blk_dva[0]),
	    uint64_t, DVA_GET_VDEV(&bp->blk_dva[1]),
	    uint64_t, DVA_GET_OFFSET(&bp->blk_dva[1]),
	    uint64_t, BP_GET_PSIZE(bp));
#endif

	mutex_init(&block->lock, NULL, MUTEX_DEFAULT, NULL);
	block->data = wrc_data;
	block->blk_prop = 0;

	block->dva[0] = bp->blk_dva[0];
	block->dva[1] = bp->blk_dva[1];
	block->btxg = BP_PHYSICAL_BIRTH(bp);

	WRCBP_SET_COMPRESS(block, BP_GET_COMPRESS(bp));
	WRCBP_SET_PSIZE(block, BP_GET_PSIZE(bp));
	WRCBP_SET_LSIZE(block, BP_GET_LSIZE(bp));

	return (block);
}

static void
wrc_free_block(wrc_block_t *block)
{
	mutex_destroy(&block->lock);
	kmem_free(block, sizeof (*block));
}

static void
wrc_clean_tree(wrc_data_t *wrc_data, avl_tree_t *tree)
{
	void *cookie = NULL;
	wrc_block_t *block = NULL;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	while ((block = avl_destroy_nodes(tree, &cookie)) != NULL)
		wrc_free_block(block);
}

static void
wrc_clean_plan_tree(wrc_data_t *wrc_data)
{
	wrc_clean_tree(wrc_data, &wrc_data->wrc_blocks);
	wrc_data->wrc_blocks_count = 0;
}

static void
wrc_clean_moved_tree(wrc_data_t *wrc_data)
{
	wrc_clean_tree(wrc_data, &wrc_data->wrc_moved_blocks);
	wrc_data->wrc_blocks_mv = 0;
}

/* WRC-MOVE routines */

/* Disable wrc threads but other params are left */
void
wrc_enter_fault_state(spa_t *spa)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;

	mutex_enter(&wrc_data->wrc_lock);

	if (!wrc_data->wrc_isfault) {
		wrc_data->wrc_thr_exit = B_TRUE;
		wrc_data->wrc_isfault = B_TRUE;
		wrc_data->wrc_walking = B_FALSE;
		cv_broadcast(&wrc_data->wrc_cv);
	}

	mutex_exit(&wrc_data->wrc_lock);
}

/*
 * Writeback Cache Migration Tunables
 *
 * 1. wrc_idle_delay_ms - time to sleep when there are no blocks to move
 *    OR, when we need to update the current spa utilization by the user/app
 *
 * 2. wrc_throttle_move_delay_ms - sleep to abide by the maximum
 *    permitted rate of migration
 *
 * 3. wrc_update_statistics_interval_ms - pool utilization recompute interval
 *    (all tunables above are in milliseconds)
 *
 * 4. wrc_min_move_tasks_count & wrc_max_move_tasks_count: the min/max number
 *    of concurrent active taskq workers processing the blocks to be migrated
 *
 * 5. wrc_spa_util_low_wm & wrc_spa_util_high_wm - min/max spa utilization
 *    levels to control the rate of migration: low_wm corresponds to the
 *    highest rate, and vise versa.
 */
uint64_t wrc_idle_delay_ms = 1000;
uint64_t wrc_throttle_move_delay_ms = 10;
uint64_t wrc_update_statistics_interval_ms = 60000;

uint64_t wrc_min_move_tasks_count = 1;
uint64_t wrc_max_move_tasks_count = 256;

uint64_t wrc_spa_util_low_wm = 10;
uint64_t wrc_spa_util_high_wm = 90;

/*
 * Per-queue limits on the number of I/O's active to
 * each device from vdev_queue.c. Default value: 10.
 */
extern uint32_t zfs_vdev_async_write_max_active;

/*
 * Throtte special=>normal migration of collected blocks.
 * Returns B_TRUE indicating that the mover must slow down, B_FALSE otherwise.
 */
static boolean_t
wrc_throttle_move(wrc_data_t *wrc_data)
{
	wrc_stat_t *wrc_stat = &wrc_data->wrc_stat;
	uint64_t spa_util = wrc_stat->wrc_spa_util;
	uint64_t blocks_in_progress = 0;
	uint64_t max_tasks = 0;
	uint64_t delta_tasks = 0;

	if (wrc_data->wrc_locked)
		return (B_TRUE);

	/* get throttled by the taskq itself */
	if (spa_util < wrc_spa_util_low_wm)
		return (B_FALSE);

	blocks_in_progress =
	    wrc_data->wrc_blocks_out - wrc_data->wrc_blocks_mv;

	if (wrc_data->wrc_move_threads <= wrc_min_move_tasks_count)
		return (blocks_in_progress > wrc_min_move_tasks_count);

	max_tasks = wrc_data->wrc_move_threads - wrc_min_move_tasks_count;

	spa_util = MIN(spa_util, wrc_spa_util_high_wm);
	spa_util = MAX(spa_util, wrc_spa_util_low_wm);

	/*
	 * Number of concurrent taskq workers is:
	 * min + throttle-defined delta
	 */
	delta_tasks =
	    max_tasks - max_tasks * (wrc_spa_util_high_wm - spa_util) /
	    (wrc_spa_util_high_wm - wrc_spa_util_low_wm);

	DTRACE_PROBE4(wrc_throttle_move,
	    spa_t *, wrc_data->wrc_spa,
	    uint64_t, blocks_in_progress,
	    uint64_t, max_tasks,
	    uint64_t, delta_tasks);

	return (blocks_in_progress > (wrc_min_move_tasks_count + delta_tasks));
}

/*
 * Walk the wrc-collected-blocks AVL and for each wrc block (wrc_block_t):
 * 1. yank it from the collected-blocks AVL tree
 * 2. add it to the moved-blocks AVL tree
 * 3. dispatch taskq to execute the special=>normal migration
 * Break when either reaching an upper limit, in total bytes, or when
 * wrc_throttle_move() (the "throttler") wants us to slow-down
 */
static void
wrc_move_blocks_tree(wrc_data_t *wrc_data)
{
	wrc_stat_t *wrc_stat = &wrc_data->wrc_stat;
	uint64_t written_bytes = 0;
	uint64_t active_txg = 0;

	mutex_enter(&wrc_data->wrc_lock);
	active_txg = wrc_data->wrc_finish_txg;

	for (;;) {
		wrc_block_t *block = NULL;

		if (wrc_data->wrc_thr_exit)
			break;

		/*
		 * Move the block to the tree of moved blocks
		 * and place into the queue of blocks to be
		 * physically moved
		 */
		block = avl_first(&wrc_data->wrc_blocks);
		if (block == NULL)
			break;

		wrc_data->wrc_blocks_count--;
		ASSERT(wrc_data->wrc_blocks_count >= 0);
		avl_remove(&wrc_data->wrc_blocks, block);
		avl_add(&wrc_data->wrc_moved_blocks, block);
		wrc_data->wrc_blocks_out++;

		mutex_exit(&wrc_data->wrc_lock);

		/* TQ_SLEEP guarantees the successful dispatching */
		VERIFY(taskq_dispatch(wrc_data->wrc_move_taskq,
		    wrc_move_block, block, TQ_SLEEP) != 0);

		written_bytes += WRCBP_GET_PSIZE(block);

		mutex_enter(&wrc_data->wrc_lock);

		if (active_txg != wrc_data->wrc_finish_txg)
			break;

		/*
		 * Update existing wrc statistics during
		 * the next wrc_move_begin() iteration
		 */
		if (ddi_get_lbolt() - wrc_stat->wrc_stat_lbolt >
		    drv_usectohz(wrc_update_statistics_interval_ms * MILLISEC))
			wrc_stat->wrc_stat_update = B_TRUE;

		if (written_bytes > zfs_wrc_data_max ||
		    wrc_throttle_move(wrc_data))
			break;
	}

	mutex_exit(&wrc_data->wrc_lock);

	DTRACE_PROBE2(wrc_move_blocks_tree,
	    spa_t *, wrc_data->wrc_spa,
	    uint64_t, written_bytes);
}

/*
 * Begin new writecache migration iteration.
 * Returns B_TRUE if the migration can proceed, B_FALSE otherwise.
 * Is called from the wrc_thread prior to moving the next batch
 * of blocks.
 *
 * Quick theory of operation:
 * 1. If the pool is idle we can allow ourselves to speed-up
 *    special => normal migration
 * 2. And vise versa, higher utilization of this spa under user
 *    workload must have /more/ system resources for itself
 * 3. Which means in turn less system resources for the writecache.
 * 4. Finally, since the pool's utilization is used to speed-up or
 *    slow down (throttle) migrations. measuring of this utilization
 *    must be done in isolation - that is, when writecache migration
 *    is either not running at all or contributes relatively
 *    little to the total utilization.
 *
 * In in this wrc_move_begin() we periodcially update wrc_spa_util
 * and use it to throttle writecache via wrc_throttle_move()
 *
 * Note that we actually sleep here based on the following tunables:
 *
 * 1. wrc_idle_delay_ms when there are no blocks to move
 *    OR, when we need to update the spa utilization by the user
 *
 * 2. sleep wrc_throttle_move_delay_ms when the throttling mechanism
 *    tells us to slow down
 */
static boolean_t
wrc_move_begin(wrc_data_t *wrc_data)
{
	spa_t *spa = wrc_data->wrc_spa;
	wrc_stat_t *wrc_stat = &wrc_data->wrc_stat;
	spa_avg_stat_t *spa_stat = &spa->spa_avg_stat;

	for (;;) {
		boolean_t throttle_move = B_FALSE;
		boolean_t stat_update = B_FALSE;
		uint64_t blocks_count = 0;
		uint64_t delay = 0;

		mutex_enter(&wrc_data->wrc_lock);

		if (spa->spa_state == POOL_STATE_UNINITIALIZED ||
		    wrc_data->wrc_thr_exit) {
			mutex_exit(&wrc_data->wrc_lock);
			return (B_FALSE);
		}

		blocks_count = wrc_data->wrc_blocks_count;
		throttle_move = wrc_throttle_move(wrc_data);
		stat_update = wrc_stat->wrc_stat_update;

		mutex_exit(&wrc_data->wrc_lock);

		DTRACE_PROBE3(wrc_move_begin,
		    spa_t *, spa,
		    uint64_t, blocks_count,
		    boolean_t, throttle_move);

		if (stat_update) {
			/*
			 * Waits for all previously scheduled
			 * move tasks to complete
			 */
			taskq_wait(wrc_data->wrc_move_taskq);
			delay = wrc_idle_delay_ms;
		} else if (blocks_count == 0) {
			delay = wrc_idle_delay_ms;
		} else if (throttle_move) {
			delay = wrc_throttle_move_delay_ms;
		} else {
			return (B_TRUE);
		}

		mutex_enter(&wrc_data->wrc_lock);

		/*
		 * Sleep wrc_idle_delay_ms when there are no blocks to move
		 * or when we need to update the spa utilization by the user.
		 * Sleep wrc_throttle_move_delay_ms when the throttling
		 * mechanism tells us to slow down.
		 */
		(void) cv_timedwait(&wrc_data->wrc_cv,
		    &wrc_data->wrc_lock,
		    ddi_get_lbolt() + drv_usectohz(delay * MILLISEC));

		/* Update wrc statistics after idle period */
		if (wrc_stat->wrc_stat_update) {
			DTRACE_PROBE2(wrc_move_begin_update_stat,
			    spa_t *, spa, uint64_t, spa_stat->spa_utilization);
			wrc_stat->wrc_stat_update = B_FALSE;
			wrc_stat->wrc_stat_lbolt = ddi_get_lbolt();
			wrc_stat->wrc_spa_util = spa_stat->spa_utilization;
		}

		mutex_exit(&wrc_data->wrc_lock);

		/* Return B_TRUE if the migration can proceed */
		if (blocks_count > 0 && !throttle_move)
			return (B_TRUE);
	}
}

/*
 * Thread to manage the data movement from
 * special devices to normal devices.
 * This thread runs as long as the spa is active.
 */
static void
wrc_thread(wrc_data_t *wrc_data)
{
	spa_t *spa = wrc_data->wrc_spa;
	char tq_name[MAXPATHLEN];

	DTRACE_PROBE1(wrc_thread_start, spa_t *, spa);

	/* Prepare move queue and make the wrc active */
	(void) snprintf(tq_name, sizeof (tq_name),
	    "%s_wrc_move", spa->spa_name);

	wrc_data->wrc_move_taskq = taskq_create(tq_name,
	    wrc_data->wrc_move_threads, maxclsyspri,
	    50, INT_MAX, TASKQ_PREPOPULATE);

	/* Main dispatch loop */
	for (;;) {
		if (!wrc_move_begin(wrc_data))
			break;

		wrc_move_blocks_tree(wrc_data);
	}

	taskq_wait(wrc_data->wrc_move_taskq);
	taskq_destroy(wrc_data->wrc_move_taskq);

	wrc_data->wrc_thread = NULL;
	DTRACE_PROBE1(wrc_thread_done, spa_t *, spa);
	thread_exit();
}

static uint64_t wrc_fault_limit = 10;

typedef struct {
	void *buf;
	int len;
} wrc_arc_bypass_t;

static int
wrc_arc_bypass_cb(void *buf, int len, void *arg)
{
	wrc_arc_bypass_t *bypass = arg;

	bypass->len = len;

	(void) memcpy(bypass->buf, buf, len);

	return (0);
}

uint64_t wrc_arc_enabled = 1;
/*
 * Moves blocks from a special device to other devices in a pool.
 */
void
wrc_move_block(void *arg)
{
	wrc_block_t *block = arg;
	wrc_data_t *wrc_data = block->data;
	spa_t *spa = wrc_data->wrc_spa;
	int err = 0;

	if (wrc_data->wrc_purge || wrc_data->wrc_isfault ||
	    !wrc_data->wrc_isvalid) {
		atomic_inc_64(&wrc_data->wrc_blocks_mv);
		return;
	}

	err = wrc_move_block_impl(block);
	if (err == 0) {
		atomic_inc_64(&wrc_data->wrc_blocks_mv);
	} else {
		/* io error occured */
		if (++wrc_data->wrc_fault_moves >= wrc_fault_limit) {
			/* error limit exceeded - disable wrc */
			cmn_err(CE_WARN,
			    "WRC: can not move data on %s with error[%d]. "
			    "Current window will be purged\n",
			    spa->spa_name, err);

			mutex_enter(&wrc_data->wrc_lock);
			wrc_purge_window(spa, NULL);
			mutex_exit(&wrc_data->wrc_lock);
		} else {
			cmn_err(CE_WARN,
			    "WRC: can not move data on %s with error[%d]\n"
			    "WRC: retry block (fault limit: %llu/%llu)",
			    spa->spa_name, err,
			    (unsigned long long) wrc_data->wrc_fault_moves,
			    (unsigned long long) wrc_fault_limit);

			/*
			 * re-plan the block with the highest priority and
			 * try to move it again
			 *
			 * TQ_SLEEP guarantees the successful dispatching
			 */
			VERIFY(taskq_dispatch(wrc_data->wrc_move_taskq,
			    wrc_move_block, block, TQ_SLEEP | TQ_FRONT) != 0);
		}
	}
}

static int
wrc_move_block_impl(wrc_block_t *block)
{
	void *buf;
	int err = 0;
	wrc_data_t *wrc_data = block->data;
	spa_t *spa = wrc_data->wrc_spa;

	if (WRCBP_IS_DELETED(block))
		return (0);

	spa_config_enter(spa, SCL_VDEV | SCL_STATE_ALL, FTAG, RW_READER);

	buf = zio_data_buf_alloc(WRCBP_GET_PSIZE(block));

	if (wrc_arc_enabled) {
		blkptr_t pseudo_bp = { 0 };
		wrc_arc_bypass_t bypass = { 0 };
		void *dbuf = NULL;

		if (WRCBP_GET_COMPRESS(block) != ZIO_COMPRESS_OFF) {
			dbuf = zio_data_buf_alloc(WRCBP_GET_LSIZE(block));
			bypass.buf = dbuf;
		} else {
			bypass.buf = buf;
		}

		pseudo_bp.blk_dva[0] = block->dva[0];
		pseudo_bp.blk_dva[1] = block->dva[1];
		BP_SET_BIRTH(&pseudo_bp, block->btxg, block->btxg);

		mutex_enter(&block->lock);
		if (WRCBP_IS_DELETED(block)) {
			if (WRCBP_GET_COMPRESS(block) != ZIO_COMPRESS_OFF)
				zio_data_buf_free(dbuf, WRCBP_GET_LSIZE(block));

			goto out;
		}

		err = arc_io_bypass(spa, &pseudo_bp,
		    wrc_arc_bypass_cb, &bypass);

		if (!err && WRCBP_GET_COMPRESS(block) != ZIO_COMPRESS_OFF) {
			size_t size = zio_compress_data(
			    (enum zio_compress)WRCBP_GET_COMPRESS(block),
			    dbuf, buf, bypass.len);
			size_t rounded =
			    P2ROUNDUP(size, (size_t)SPA_MINBLOCKSIZE);
			if (rounded != WRCBP_GET_PSIZE(block)) {
				/* random error to get to slow path */
				err = ERANGE;
				cmn_err(CE_WARN, "WRC WARN: ARC COMPRESSION "
				    "FAILED: %u %u %u",
				    (unsigned)size,
				    (unsigned)WRCBP_GET_PSIZE(block),
				    (unsigned)WRCBP_GET_COMPRESS(block));
			} else if (rounded > size) {
				bzero((char *)buf + size, rounded - size);
			}
		}

		if (WRCBP_GET_COMPRESS(block) != ZIO_COMPRESS_OFF)
			zio_data_buf_free(dbuf, WRCBP_GET_LSIZE(block));

	} else {
		err = ENOTSUP;
		mutex_enter(&block->lock);
		if (WRCBP_IS_DELETED(block))
			goto out;
	}

	/*
	 * Any error means that arc read failed and block is being moved via
	 * slow path
	 */
	if (err) {
		err = wrc_io(WRC_READ_FROM_SPECIAL, block, buf);
		if (err) {
			cmn_err(CE_WARN, "WRC: move task has failed to read:"
			    " error [%d]", err);
			goto out;
		}
		DTRACE_PROBE(wrc_move_from_disk);
	} else {
		DTRACE_PROBE(wrc_move_from_arc);
	}

	err = wrc_io(WRC_WRITE_TO_NORMAL, block, buf);
	if (err) {
		cmn_err(CE_WARN, "WRC: move task has failed to write: "
		    "error [%d]", err);
		goto out;
	}

#ifdef _KERNEL
	DTRACE_PROBE5(wrc_move_block_data,
	    uint64_t, DVA_GET_VDEV(&block->dva[0]),
	    uint64_t, DVA_GET_OFFSET(&block->dva[0]),
	    uint64_t, DVA_GET_VDEV(&block->dva[1]),
	    uint64_t, DVA_GET_OFFSET(&block->dva[1]),
	    uint64_t, WRCBP_GET_PSIZE(block));
#endif

out:
	mutex_exit(&block->lock);
	zio_data_buf_free(buf, WRCBP_GET_PSIZE(block));

	spa_config_exit(spa, SCL_VDEV | SCL_STATE_ALL, FTAG);

	return (err);
}

/* WRC-WALK routines */

int
wrc_walk_lock(spa_t *spa)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;

	mutex_enter(&wrc_data->wrc_lock);
	while (wrc_data->wrc_locked)
		(void) cv_wait(&wrc_data->wrc_cv, &wrc_data->wrc_lock);
	if (wrc_data->wrc_thr_exit) {
		mutex_exit(&wrc_data->wrc_lock);
		return (ENOLCK);
	}

	wrc_data->wrc_locked = B_TRUE;
	while (wrc_data->wrc_walking)
		(void) cv_wait(&wrc_data->wrc_cv, &wrc_data->wrc_lock);
	if (wrc_data->wrc_thr_exit) {
		mutex_exit(&wrc_data->wrc_lock);
		return (ENOLCK);
	}

	cv_broadcast(&wrc_data->wrc_cv);
	mutex_exit(&wrc_data->wrc_lock);

	return (0);
}

void
wrc_walk_unlock(spa_t *spa)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;
	mutex_enter(&wrc_data->wrc_lock);
	wrc_data->wrc_locked = B_FALSE;
	cv_broadcast(&wrc_data->wrc_cv);
	mutex_exit(&wrc_data->wrc_lock);
}

/* thread to collect blocks that must be moved */
static void
wrc_walk_thread(wrc_data_t *wrc_data)
{
	spa_t *spa = wrc_data->wrc_spa;
	int err = 0;

	DTRACE_PROBE1(wrc_walk_thread_start, char *, spa->spa_name);

	for (;;) {
		err = 0;
		mutex_enter(&wrc_data->wrc_lock);

		wrc_data->wrc_walking = B_FALSE;

		cv_broadcast(&wrc_data->wrc_cv);

		/* Set small wait time to delay walker restart */
		do {
			(void) cv_timedwait(&wrc_data->wrc_cv,
			    &wrc_data->wrc_lock,
			    ddi_get_lbolt() + hz / 4);
		} while (spa->spa_state == POOL_STATE_UNINITIALIZED &&
		    !wrc_data->wrc_thr_exit);

		if (wrc_data->wrc_thr_exit || !spa->spa_dsl_pool) {
			mutex_exit(&wrc_data->wrc_lock);
			break;
		}

		wrc_data->wrc_walking = B_TRUE;

		cv_broadcast(&wrc_data->wrc_cv);

		mutex_exit(&wrc_data->wrc_lock);

		err = wrc_collect_special_blocks(spa->spa_dsl_pool);
		if (err != 0) {
			cmn_err(CE_WARN, "WRC: can not "
			    "traverse pool: error [%d]. "
			    "Current window will be purged\n", err);

			wrc_purge_window(spa, NULL);
		}
	}

	wrc_data->wrc_walk_thread = NULL;

	DTRACE_PROBE1(wrc_walk_thread_done, char *, spa->spa_name);

	thread_exit();
}

int wrc_force_trigger = 1;
/*
 * This function triggers the write cache thread if the past
 * two sync context dif not sync more than 1/8th of
 * zfs_dirty_data_sync.
 * This function is called only if the current sync context
 * did not sync more than 1/16th of zfs_dirty_data_sync.
 */
void
wrc_trigger_wrcthread(spa_t *spa, uint64_t prev_sync_avg)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;

	/*
	 * Using mutex_tryenter() because if the worker is
	 * holding the mutex, it is already up, no need
	 * to cv_signal()
	 */
	if ((wrc_force_trigger || prev_sync_avg < zfs_dirty_data_sync / 8) &&
	    mutex_tryenter(&wrc_data->wrc_lock)) {
		if (wrc_data->wrc_blocks_count != 0) {
			DTRACE_PROBE1(wrc_trigger_worker, char *,
			    spa->spa_name);
			cv_signal(&wrc_data->wrc_cv);
		}
		mutex_exit(&wrc_data->wrc_lock);
	}
}

static boolean_t
wrc_should_pause_scanblocks(dsl_pool_t *dp,
    wrc_parseblock_cb_t *cbd, const zbookmark_phys_t *zb)
{
	hrtime_t elapsed_ns;

	/*
	 * We know how to resume iteration on level 0
	 * blocks only
	 */
	if (zb->zb_level != 0)
		return (B_FALSE);

	/* We're resuming */
	if (!ZB_IS_ZERO(&cbd->zb))
		return (B_FALSE);

	/*
	 * We should stop if either traversal time
	 * took more than zfs_txg_timeout or it took
	 * more zfs_scan_min_time while somebody is waiting
	 * for our transaction group.
	 */
	elapsed_ns = gethrtime() - cbd->start_time;
	if (elapsed_ns / NANOSEC > zfs_txg_timeout ||
	    (elapsed_ns / MICROSEC > zfs_scan_min_time_ms &&
	    txg_sync_waiting(dp)) || spa_shutting_down(dp->dp_spa))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Callback passed in traversal function. Checks whether block is
 * special and hence should be planned for move
 */
/* ARGSUSED */
int
wrc_traverse_ds_cb(spa_t *spa, zilog_t *zilog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;
	wrc_parseblock_cb_t *cbd = arg;
	wrc_block_t *block, *found_block;
	avl_index_t where = NULL;
	boolean_t increment_counters = B_FALSE;

	/* skip ZIL blocks */
	if (bp == NULL || zb->zb_level == ZB_ZIL_LEVEL)
		return (0);

	if (!BP_IS_SPECIAL(bp))
		return (0);

	mutex_enter(&wrc_data->wrc_lock);

	if (wrc_data->wrc_thr_exit) {
		mutex_exit(&wrc_data->wrc_lock);
		return (ERESTART);
	}

	if (cbd->actv_txg != wrc_data->wrc_finish_txg) {
		mutex_exit(&wrc_data->wrc_lock);
		return (ERESTART);
	}

	if (wrc_should_pause_scanblocks(spa->spa_dsl_pool, cbd, zb)) {
		mutex_exit(&wrc_data->wrc_lock);
		return (ERESTART);
	}

	/*
	 * If dedup is enabled then travesal gives us the original block,
	 * that already moved as part of previous WRC-win.
	 * So just skip it.
	 */
	if (BP_PHYSICAL_BIRTH(bp) < wrc_data->wrc_start_txg) {
		mutex_exit(&wrc_data->wrc_lock);
		return (0);
	}

	block = wrc_create_block(wrc_data, bp);
	if (block == NULL) {
		mutex_exit(&wrc_data->wrc_lock);
		return (ERESTART);
	}

	/*
	 * Before add the block to the tree of planned tree need
	 * to check that:
	 *  - a block with the same DVA is not contained in one of
	 *  out trees (planned of moved)
	 *  - a block is contained in a tree, so need to check that:
	 *		- DVA already freed: need to free the corresponding
	 *		wrc_block and add new wrc_block to
	 *		the tree of planned blocks. This is possible if
	 *		DVA was freed and later allocated for another data.
	 *
	 *		- DVA still allocated: is not required to add
	 *		the new block to the tree of planned blocks,
	 *		so just free it. This is possible if deduplication
	 *		is enabled
	 */
	found_block = avl_find(&wrc_data->wrc_moved_blocks, block, NULL);
	if (found_block != NULL) {
		if (WRCBP_IS_DELETED(found_block)) {
			avl_remove(&wrc_data->wrc_moved_blocks, found_block);
			wrc_free_block(found_block);
			goto insert;
		} else {
			wrc_free_block(block);
			goto out;
		}
	}

	found_block = avl_find(&wrc_data->wrc_blocks, block, &where);
	if (found_block != NULL) {
		if (WRCBP_IS_DELETED(found_block)) {
			avl_remove(&wrc_data->wrc_blocks, found_block);
			wrc_free_block(found_block);
			goto insert;
		} else {
			wrc_free_block(block);
			goto out;
		}
	}

	increment_counters = B_TRUE;

insert:
	avl_insert(&wrc_data->wrc_blocks, block, where);
	cbd->bt_size += WRCBP_GET_PSIZE(block);
	if (increment_counters) {
		wrc_data->wrc_blocks_count++;
		wrc_data->wrc_blocks_in++;
	}

out:
	mutex_exit(&wrc_data->wrc_lock);

	return (0);
}

/*
 * Iterate through data blocks on a "special" device and collect those
 * ones that can be moved to other devices in a pool.
 *
 * XXX: For now we collect as many blocks as possible in order to dispatch
 * them to the taskq later. It may be reasonable to invent a mechanism
 * which will allow not to store the whole `moving` tree in-core
 * (persistent move bookmark, for example)
 */
int
wrc_collect_special_blocks(dsl_pool_t *dp)
{
	spa_t *spa = dp->dp_spa;
	wrc_data_t *wrc_data = &spa->spa_wrc;
	wrc_parseblock_cb_t cb_data;
	int err = 0;
	hrtime_t scan_start;
	uint64_t diff;

	if (!zfs_wrc_schedtmo)
		zfs_wrc_schedtmo = zfs_txg_timeout * 2;

	scan_start = gethrtime();
	diff = scan_start - dp->dp_spec_rtime;
	if (diff / NANOSEC < zfs_wrc_schedtmo)
		return (0);

	cb_data.wrc_data = wrc_data;
	cb_data.zb = spa->spa_lszb;
	cb_data.start_time = scan_start;
	cb_data.actv_txg = wrc_data->wrc_finish_txg;
	cb_data.bt_size = 0ULL;

	/*
	 * Traverse the range of txg to collect blocks
	 */
	if (wrc_data->wrc_walk && wrc_data->wrc_finish_txg) {
		if (krrp_debug) {
			cmn_err(CE_NOTE, "WRC: new window (%llu; %llu)",
			    (unsigned long long)wrc_data->wrc_start_txg,
			    (unsigned long long)wrc_data->wrc_finish_txg);
		}
		err = traverse_pool(spa, wrc_data->wrc_start_txg - 1,
		    wrc_data->wrc_finish_txg + 1,
		    TRAVERSE_PREFETCH_METADATA | TRAVERSE_POST,
		    wrc_traverse_ds_cb, &cb_data, &cb_data.zb);
	}

	spa->spa_lszb = cb_data.zb;
	if (err != ERESTART && err != EAGAIN && (cb_data.bt_size == 0ULL) ||
	    ZB_IS_ZERO(&cb_data.zb)) {
		/*
		 * No more blocks to move or error state
		 */
		mutex_enter(&wrc_data->wrc_lock);
		wrc_data->wrc_walk = B_FALSE;
		if (err) {
			/*
			 * Something went wrong during the traversing
			 */
			if (wrc_data->wrc_thr_exit) {
				mutex_exit(&wrc_data->wrc_lock);
				return (0);
			}

			cmn_err(CE_WARN,
			    "WRC: Can not collect data "
			    "because of error [%d]", err);

			wrc_purge_window(spa, NULL);
			wrc_data->wrc_wait_for_window = B_TRUE;
			mutex_exit(&wrc_data->wrc_lock);

			err = 0;
		} else if (wrc_data->wrc_blocks_in == wrc_data->wrc_blocks_mv &&
		    !wrc_data->wrc_purge) {
			/* Everything is moved, close the window */
			if (wrc_data->wrc_finish_txg != 0)
				wrc_close_window(wrc_data);

			/*
			 * Process of the window closing might be
			 * interrupted by wrc_purge_window()
			 * (e.g., when the pool gets destroyed, etc.)
			 * If this is the case we simply return. New
			 * wrc window will be opened later upon completion
			 * of the purge..
			 */
			if (wrc_data->wrc_purge) {
				mutex_exit(&wrc_data->wrc_lock);
				return (0);
			}


			/* Say to others that walking stopped */
			wrc_data->wrc_walking = B_FALSE;
			wrc_data->wrc_wait_for_window = B_TRUE;
			cv_broadcast(&wrc_data->wrc_cv);

			/* and wait until a new window appears */
			while (!wrc_data->wrc_walk && !wrc_data->wrc_thr_exit) {
				cv_wait(&wrc_data->wrc_cv,
				    &wrc_data->wrc_lock);
			}

			if (wrc_data->wrc_thr_exit) {
				mutex_exit(&wrc_data->wrc_lock);
				return (0);
			}

			mutex_exit(&wrc_data->wrc_lock);

			dsl_sync_task(spa->spa_name, NULL,
			    wrc_write_update_window, spa,
			    ZFS_SPACE_CHECK_NONE, 0);
		} else {
			mutex_exit(&wrc_data->wrc_lock);
		}


	} else if (err == ERESTART) {
		/*
		 * We were interrupted, the iteration will be
		 * resumed later.
		 */
		DTRACE_PROBE2(traverse__intr, spa_t *, spa,
		    wrc_parseblock_cb_t *, &cb_data);
		err = 0;
	}

	dp->dp_spec_rtime = gethrtime();

	return (err);
}

/* WRC-THREAD_CONTROL */

/* Starts wrc threads and set associated structures */
void
wrc_start_thread(spa_t *spa)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;
	boolean_t lock_held;

	ASSERT(strcmp(spa->spa_name, TRYIMPORT_NAME) != 0);
	ASSERT(wrc_data->wrc_isvalid);

	lock_held = MUTEX_HELD(&wrc_data->wrc_lock);
	if (!lock_held)
		mutex_enter(&wrc_data->wrc_lock);

	if (wrc_data->wrc_thread == NULL && wrc_data->wrc_walk_thread == NULL) {
		wrc_data->wrc_thr_exit = B_FALSE;
#ifdef _KERNEL
		wrc_data->wrc_thread = thread_create(NULL, 0,
		    wrc_thread, wrc_data, 0, &p0, TS_RUN, maxclsyspri);
		wrc_data->wrc_walk_thread = thread_create(NULL, 0,
		    wrc_walk_thread, wrc_data, 0, &p0, TS_RUN, maxclsyspri);
		spa_start_perfmon_thread(spa);
#endif
	}

	wrc_data->wrc_wait_for_window = B_TRUE;
	if (!lock_held)
		mutex_exit(&wrc_data->wrc_lock);
}

/* Disables wrc thread and reset associated data structures */
boolean_t
wrc_stop_thread(spa_t *spa)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;
	boolean_t stop = B_FALSE;

	stop |= spa_stop_perfmon_thread(spa);
	mutex_enter(&wrc_data->wrc_lock);

	/*
	 * We do not want to wait the finishing of migration,
	 * because it can take a long time
	 */
	wrc_purge_window(spa, NULL);
	wrc_data->wrc_wait_for_window = B_FALSE;

	if (wrc_data->wrc_thread != NULL || wrc_data->wrc_walk_thread != NULL) {
		wrc_data->wrc_thr_exit = B_TRUE;
		cv_broadcast(&wrc_data->wrc_cv);
		mutex_exit(&wrc_data->wrc_lock);
#ifdef _KERNEL
		if (wrc_data->wrc_thread)
			thread_join(wrc_data->wrc_thread->t_did);
		if (wrc_data->wrc_walk_thread)
			thread_join(wrc_data->wrc_walk_thread->t_did);
#endif
		mutex_enter(&wrc_data->wrc_lock);
		wrc_data->wrc_thread = NULL;
		wrc_data->wrc_walk_thread = NULL;
		stop |= B_TRUE;
	}

	wrc_clean_plan_tree(wrc_data);
	wrc_clean_moved_tree(wrc_data);

	mutex_exit(&wrc_data->wrc_lock);

	return (stop);
}

/* WRC-WND routines */

#define	DMU_POOL_WRC_START_TXG "wrc_start_txg"
#define	DMU_POOL_WRC_FINISH_TXG "wrc_finish_txg"
#define	DMU_POOL_WRC_TO_RELE_TXG "wrc_to_rele_txg"
#define	DMU_POOL_WRC_STATE_DELETE "wrc_state_delete"

/* On-disk wrc parameters alternation */

static void
wrc_set_state_delete(void *void_spa, dmu_tx_t *tx)
{
	uint64_t upd = 1;
	spa_t *spa = void_spa;

	(void) zap_update(spa->spa_dsl_pool->dp_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT,
	    DMU_POOL_WRC_STATE_DELETE, sizeof (uint64_t), 1, &upd, tx);
}

static void
wrc_clean_state_delete(void *void_spa, dmu_tx_t *tx)
{
	uint64_t upd = 0;
	spa_t *spa = void_spa;

	(void) zap_update(spa->spa_dsl_pool->dp_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT,
	    DMU_POOL_WRC_STATE_DELETE, sizeof (uint64_t), 1, &upd, tx);
}

static void
wrc_write_update_window(void *void_spa, dmu_tx_t *tx)
{
	spa_t *spa = void_spa;
	wrc_data_t *wrc_data = &spa->spa_wrc;

	if (wrc_data->wrc_finish_txg == 0) {
		/*
		 * The "delete" state is not valid,
		 * because window has been closed or purged
		 */
		wrc_clean_state_delete(void_spa, tx);
	}

	(void) zap_update(spa->spa_dsl_pool->dp_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT,
	    DMU_POOL_WRC_START_TXG, sizeof (uint64_t), 1,
	    &wrc_data->wrc_start_txg, tx);
	(void) zap_update(spa->spa_dsl_pool->dp_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT,
	    DMU_POOL_WRC_FINISH_TXG, sizeof (uint64_t), 1,
	    &wrc_data->wrc_finish_txg, tx);
	(void) zap_update(spa->spa_dsl_pool->dp_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT,
	    DMU_POOL_WRC_TO_RELE_TXG, sizeof (uint64_t), 1,
	    &wrc_data->wrc_txg_to_rele, tx);
}

static void
wrc_close_window_impl(spa_t *spa, avl_tree_t *tree)
{
	wrc_block_t *node;
	wrc_data_t *wrc_data = &spa->spa_wrc;
	dmu_tx_t *tx;
	int err;
	uint64_t txg;
	void *cookie = NULL;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	wrc_data->wrc_delete = B_TRUE;

	mutex_exit(&wrc_data->wrc_lock);
	/*
	 * Set flag that wrc has finished moving the window and
	 * freeing special dvas now
	 */
	dsl_sync_task(spa->spa_name, NULL,
	    wrc_set_state_delete, spa, 0, ZFS_SPACE_CHECK_NONE);

	tx = dmu_tx_create_dd(spa->spa_dsl_pool->dp_mos_dir);
	err = dmu_tx_assign(tx, TXG_WAIT);

	VERIFY(err == 0);

	txg = tx->tx_txg;

	mutex_enter(&wrc_data->wrc_lock);

	/*
	 * There was a purge while delete state was being written
	 * Everything is reset so no frees are required or allowed
	 */
	if (wrc_data->wrc_delete == B_FALSE) {
		dmu_tx_commit(tx);
		return;
	}

	/*
	 * Clean the tree of moved blocks, free special dva and
	 * wrc_block structure of every block in the tree
	 */
	spa_config_enter(spa, SCL_VDEV, FTAG, RW_READER);
	while ((node = avl_destroy_nodes(tree, &cookie)) != NULL) {
		if (!WRCBP_IS_DELETED(node)) {
			metaslab_free_dva(spa, &node->dva[WRC_SPECIAL_DVA],
			    tx->tx_txg, B_FALSE);
		}

		wrc_free_block(node);
	}
	spa_config_exit(spa, SCL_VDEV, FTAG);

	/* Move left boundary of the window and reset the right one */
	wrc_data->wrc_start_txg = wrc_data->wrc_finish_txg + 1;
	wrc_data->wrc_finish_txg = 0;
	wrc_data->wrc_txg_to_rele = 0;
	wrc_data->wrc_roll_threshold = wrc_mv_cancel_threshold_initial;
	wrc_data->wrc_delete = B_FALSE;

	wrc_data->wrc_blocks_mv_last = wrc_data->wrc_blocks_mv;

	wrc_data->wrc_blocks_in = 0;
	wrc_data->wrc_blocks_out = 0;
	wrc_data->wrc_blocks_mv = 0;

	/* Write down new boundaries */
	dsl_sync_task_nowait(spa->spa_dsl_pool,
	    wrc_write_update_window, spa, 0, ZFS_SPACE_CHECK_NONE, tx);
	dmu_tx_commit(tx);

	mutex_exit(&wrc_data->wrc_lock);

	/* Wait frees and wrc parameters to be synced to disk */
	txg_wait_synced(spa->spa_dsl_pool, txg);

	mutex_enter(&wrc_data->wrc_lock);
}

/* Close the wrc window and release the snapshot of its right boundary */
static void
wrc_close_window(wrc_data_t *wrc_data)
{
	spa_t *spa = wrc_data->wrc_spa;
	uint64_t txg_to_rele = wrc_data->wrc_txg_to_rele;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	ASSERT0(wrc_data->wrc_blocks_count);
	ASSERT(avl_is_empty(&wrc_data->wrc_blocks));

	VERIFY(wrc_data->wrc_finish_txg != 0);

	if (krrp_debug) {
		cmn_err(CE_NOTE, "WRC: window (%llu; %llu) has been completed\n"
		    "WRC: %llu blocks moved",
		    (unsigned long long)wrc_data->wrc_start_txg,
		    (unsigned long long)wrc_data->wrc_finish_txg,
		    (unsigned long long)wrc_data->wrc_blocks_mv);
		VERIFY(wrc_data->wrc_blocks_mv == wrc_data->wrc_blocks_in);
		VERIFY(wrc_data->wrc_blocks_mv == wrc_data->wrc_blocks_out);
	}

	wrc_close_window_impl(spa, &wrc_data->wrc_moved_blocks);

	wrc_rele_autosnaps(wrc_data, txg_to_rele, B_FALSE);
}

/*
 * To fini of a wrc_instance need to inherit wrc_mode.
 * During this operation will be called wrc_process_objset()
 * that will unregister this instance and destroy it
 */
static void
wrc_instance_finalization(void *arg)
{
	wrc_instance_t *wrc_instance = arg;

	ASSERT(wrc_instance->fini_done);

#ifdef _KERNEL
	/*
	 * NVL needs to be populated here, because after
	 * calling dsl_prop_inherit() wrc_instance cannot
	 * be used
	 */
	nvlist_t *event;
	event = fnvlist_alloc();
	fnvlist_add_string(event, "fsname", wrc_instance->ds_name);
#endif

	VERIFY3U(dsl_prop_inherit(wrc_instance->ds_name,
	    zfs_prop_to_name(ZFS_PROP_WRC_MODE),
	    ZPROP_SRC_INHERITED), ==, 0);

#ifdef _KERNEL
	zfs_event_post(ZFS_EC_STATUS, "wrc_done", event);
#endif
}

static void
wrc_rele_autosnaps(wrc_data_t *wrc_data, uint64_t txg_to_rele,
    boolean_t purge)
{
	wrc_instance_t *wrc_instance;

	wrc_instance = avl_first(&wrc_data->wrc_instances);
	while (wrc_instance != NULL) {
		if (wrc_instance->txg_to_rele != 0) {
			VERIFY3U(wrc_instance->txg_to_rele,
			    ==, txg_to_rele);
			if (wrc_instance->fini_migration &&
			    txg_to_rele > wrc_instance->txg_off && !purge) {
				/*
				 * This WRC instance will be terminated in
				 * the preallocated taskq
				 *
				 * WRC instance termination involves writing
				 * and therefore requires sync context.
				 * But since we are here already in the sync
				 * context, the operation is task-dispatched
				 */
				wrc_instance->fini_done = B_TRUE;
				VERIFY(taskq_dispatch(
				    wrc_data->wrc_instance_fini,
				    wrc_instance_finalization, wrc_instance,
				    TQ_SLEEP) != NULL);
			} else if (wrc_instance->fini_migration) {
				autosnap_force_snap_fast(
				    wrc_instance->wrc_autosnap_hdl);
			}

			autosnap_release_snapshots_by_txg(
			    wrc_instance->wrc_autosnap_hdl,
			    txg_to_rele, AUTOSNAP_NO_SNAP);
			wrc_instance->txg_to_rele = 0;
		} else if (wrc_instance->fini_migration) {
			autosnap_force_snap_fast(
			    wrc_instance->wrc_autosnap_hdl);
		}

		wrc_instance = AVL_NEXT(&wrc_data->wrc_instances,
		    wrc_instance);
	}
}

/*
 * Purge pending blocks and reset right boundary.
 * It is used when dataset is deleted or an error
 * occured during traversing. If called in the
 * context of the sync thread, then syncing tx must
 * be passed. Outside the syncing thread NULL is
 * expected instead.
 */
void
wrc_purge_window(spa_t *spa, dmu_tx_t *tx)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;
	uint64_t snap_txg;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	if (wrc_data->wrc_finish_txg == 0)
		return;

	/*
	 * Clean tree with blocks which are not queued
	 * to be moved yet
	 */
	wrc_clean_plan_tree(wrc_data);

	/*
	 * Set purge on to notify move workers to skip all
	 * blocks that are left in queue not to waste time
	 * moving data which will be required to move again.
	 * Wait until all queued blocks are processed.
	 */
	wrc_data->wrc_purge = B_TRUE;

	/*
	 * Reset the deletion flag to make sure
	 * that the purge is appreciated by
	 * dva[0] deleter
	 */
	wrc_data->wrc_delete = B_FALSE;

	while (wrc_data->wrc_blocks_out !=
	    wrc_data->wrc_blocks_mv &&
	    !wrc_data->wrc_thr_exit) {
		(void) cv_timedwait(&wrc_data->wrc_cv,
		    &wrc_data->wrc_lock,
		    ddi_get_lbolt() + 1000);
	}

	/*
	 * Clean the tree of moved blocks
	 */
	wrc_clean_moved_tree(wrc_data);

	wrc_data->wrc_blocks_in = 0;
	wrc_data->wrc_blocks_out = 0;
	wrc_data->wrc_blocks_mv = 0;

	/* Reset bookmark */
	bzero(&spa->spa_lszb, sizeof (spa->spa_lszb));

	snap_txg = wrc_data->wrc_txg_to_rele;

	/*
	 * Reset right boundary and time of latest window
	 * start to catch the closest snapshot which will be
	 * created
	 */
	wrc_data->wrc_finish_txg = 0;
	wrc_data->wrc_txg_to_rele = 0;
	wrc_data->wrc_latest_window_time = 0;
	wrc_data->wrc_roll_threshold =
	    MIN(wrc_data->wrc_roll_threshold + wrc_mv_cancel_threshold_step,
	    wrc_mv_cancel_threshold_cap);

	if (krrp_debug)
		cmn_err(CE_NOTE, "WRC: Right boundary will be moved forward");

	if (tx) {
		dsl_sync_task_nowait(spa->spa_dsl_pool,
		    wrc_write_update_window, spa, 0, ZFS_SPACE_CHECK_NONE, tx);
	} else {
		/*
		 * It is safe to drop the lock as the function has already
		 * set everything it wanted up to the moment and only need
		 * to update on-disk format
		 */
		mutex_exit(&wrc_data->wrc_lock);

		dsl_sync_task(spa->spa_name, NULL,
		    wrc_write_update_window, spa, 0, ZFS_SPACE_CHECK_NONE);
		mutex_enter(&wrc_data->wrc_lock);
	}

	wrc_rele_autosnaps(wrc_data, snap_txg, B_TRUE);

	/* Purge done */
	wrc_data->wrc_purge = B_FALSE;
}

/* Finalize interrupted with power cycle window */
static void
wrc_free_restore(spa_t *spa)
{
	uint64_t ret;
	wrc_data_t *wrc_data = &spa->spa_wrc;
	int err = zap_lookup(spa->spa_dsl_pool->dp_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT,
	    DMU_POOL_WRC_STATE_DELETE, sizeof (uint64_t), 1, &ret);
	boolean_t need_restore = err ? B_FALSE : (!!ret);
	wrc_parseblock_cb_t cb_data = { 0 };

	if (!need_restore) {
		wrc_data->wrc_finish_txg = 0;
		wrc_data->wrc_txg_to_rele = 0;
		return;
	}

	/*
	 * The mutex must be dropped to prevent recursive entry
	 * It is safe as we are the only user of the wrc structures
	 * at the point
	 */
	mutex_exit(&wrc_data->wrc_lock);
	cb_data.wrc_data = wrc_data;
	err = traverse_pool(spa, wrc_data->wrc_start_txg - 1,
	    wrc_data->wrc_finish_txg + 1,
	    TRAVERSE_PREFETCH_METADATA | TRAVERSE_POST,
	    wrc_traverse_ds_cb, &cb_data, &cb_data.zb);

	mutex_enter(&wrc_data->wrc_lock);

	wrc_close_window_impl(spa, &wrc_data->wrc_blocks);
	wrc_data->wrc_blocks_count = 0;
}

/*
 * The bool returned from this function tells to autosnapper
 * whether to take a new autosnapshot or not.
 * The new autosnapshot is used as the right boundary for a new
 * writecache migration window.
 */
/*ARGSUSED*/
static boolean_t
wrc_confirm_cb(const char *name, boolean_t recursive, uint64_t txg, void *arg)
{
	wrc_instance_t *wrc_instance = arg;
	wrc_data_t *wrc_data = wrc_instance->wrc_data;

	/*
	 * The conditions are:
	 * - no active writecache window currently
	 * - writecache is not locked
	 * - used space on special vdev is at or above min-watermark
	 */
	return (wrc_data->wrc_wait_for_window && !wrc_data->wrc_locked &&
	    !wrc_check_space(wrc_data->wrc_spa));
}

uint64_t wrc_window_roll_delay_ms = 0;

static boolean_t
wrc_check_time(wrc_data_t *wrc_data)
{
#ifdef _KERNEL
	if (wrc_window_roll_delay_ms == 0)
		return (B_FALSE);

	uint64_t time_spent =
	    ddi_get_lbolt() - wrc_data->wrc_latest_window_time;
	return (time_spent < drv_usectohz(wrc_window_roll_delay_ms * MILLISEC));
#else
	return (B_FALSE);
#endif
}

/*
 * Returns B_TRUE if the percentage of used space on special vdev
 * is below ZPOOL_PROP_MINWATERMARK ("min-watermark", MIN_WN),
 * otherwise returns B_FALSE.
 *
 * Based on this return wrc_confirm_cb() caller either opens
 * a new writecache window, or not. In the latter case, when
 * the used space remains below min-watermark, writecache migration
 * does not run.
 *
 * Similarly to low-watermark and high-watermark that control
 * special vdev's used space and the rate of its utilization,
 * the min-watermark is a pool's property that can be set via:
 *
 * 'zpool set min-watermark <pool name>'
 *
 */
static boolean_t
wrc_check_space(spa_t *spa)
{
	uint64_t percentage =
	    spa_class_alloc_percentage(spa_special_class(spa));

	return (percentage < spa->spa_minwat);
}

/* Autosnap notification callback */
/*ARGSUSED*/
static boolean_t
wrc_nc_cb(const char *name, boolean_t recursive, boolean_t autosnap,
    uint64_t txg, uint64_t etxg, void *arg)
{
	boolean_t result = B_FALSE;
	wrc_instance_t *wrc_instance = arg;
	wrc_data_t *wrc_data = wrc_instance->wrc_data;

	mutex_enter(&wrc_data->wrc_lock);
	if (!wrc_data->wrc_isvalid || wrc_data->wrc_isfault) {
		mutex_exit(&wrc_data->wrc_lock);
		return (B_FALSE);
	}

	if (wrc_data->wrc_finish_txg != 0) {
		if (wrc_data->wrc_finish_txg == etxg &&
		    !wrc_instance->fini_done) {
			/* Same window-snapshot for another WRC-Instance */
			wrc_instance->txg_to_rele = txg;
			result = B_TRUE;
		}

		mutex_exit(&wrc_data->wrc_lock);
		return (result);
	}

	if (wrc_data->wrc_walking) {
		/* Current window already done, but is not closed yet */
		result = B_FALSE;
	} else if (wrc_data->wrc_locked) {
		/* WRC is locked by an external caller */
		result = B_FALSE;
	} else if (wrc_instance->fini_done) {
		/* Instance already done, so snapshot is not required */
		result = B_FALSE;
	} else {
		/* Accept new windows */
		VERIFY0(wrc_data->wrc_blocks_count);
		VERIFY(avl_is_empty(&wrc_data->wrc_blocks));
		wrc_data->wrc_latest_window_time = ddi_get_lbolt();
		wrc_data->wrc_first_move = B_FALSE;
		wrc_data->wrc_walk = B_TRUE;
		wrc_data->wrc_finish_txg = etxg;
		wrc_data->wrc_txg_to_rele = txg;
		wrc_data->wrc_altered_limit = 0;
		wrc_data->wrc_altered_bytes = 0;
		wrc_data->wrc_window_bytes = 0;
		wrc_data->wrc_fault_moves = 0;
		cv_broadcast(&wrc_data->wrc_cv);
		result = B_TRUE;
		wrc_instance->txg_to_rele = txg;
		wrc_data->wrc_wait_for_window = B_FALSE;
	}

	mutex_exit(&wrc_data->wrc_lock);
	return (result);
}

static void
wrc_err_cb(const char *name, int err, uint64_t txg, void *arg)
{
	wrc_instance_t *wrc_instance = arg;
	wrc_data_t *wrc_data = wrc_instance->wrc_data;

	/* FIXME: ??? error on one wrc_instance will stop whole WRC ??? */
	cmn_err(CE_WARN, "Autosnap can not create a snapshot for writecache at "
	    "txg %llu [%d] of pool '%s'\n", (unsigned long long)txg, err, name);
	wrc_enter_fault_state(wrc_data->wrc_spa);
}

void
wrc_add_bytes(spa_t *spa, uint64_t txg, uint64_t bytes)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;

	mutex_enter(&wrc_data->wrc_lock);

	if (wrc_data->wrc_finish_txg == txg) {
		wrc_data->wrc_window_bytes += bytes;
		wrc_data->wrc_altered_limit =
		    wrc_data->wrc_window_bytes *
		    wrc_data->wrc_roll_threshold / 100;

		DTRACE_PROBE3(wrc_window_size, uint64_t, txg,
		    uint64_t, wrc_data->wrc_window_bytes,
		    uint64_t, wrc_data->wrc_altered_limit);
	}

	mutex_exit(&wrc_data->wrc_lock);
}

/* WRC-INIT routines */

void
wrc_activate(spa_t *spa, boolean_t pool_creation)
{
	if (spa_feature_is_enabled(spa, SPA_FEATURE_WRC))
		wrc_activate_impl(spa, pool_creation);
}

/*
 * This function is callback for dmu_objset_find_dp()
 * that is called during the initialization of WRC.
 *
 * Here we register wrc_instance for the given dataset
 * if WRC is activated for this datasets
 */
/* ARGSUSED */
static int
wrc_activate_instances(dsl_pool_t *dp, dsl_dataset_t *ds, void *arg)
{
	wrc_data_t *wrc_data = arg;
	objset_t *os = NULL;
	wrc_instance_t *wrc_instance = NULL;
	int rc = 0;

	(void) dmu_objset_from_ds(ds, &os);
	VERIFY(os != NULL);

	if (os->os_wrc_mode == ZFS_WRC_MODE_OFF)
		return (0);

	if (os->os_dsl_dataset->ds_object != os->os_wrc_root_ds_obj)
		return (0);

	mutex_enter(&wrc_data->wrc_lock);

	if (wrc_data->wrc_isvalid)
		wrc_instance = wrc_register_instance(wrc_data, os);
	else
		rc = EINTR;

	mutex_exit(&wrc_data->wrc_lock);

	if (wrc_instance != NULL) {
		if (os->os_wrc_mode == ZFS_WRC_MODE_OFF_DELAYED) {
			wrc_instance->fini_migration = B_TRUE;
			wrc_instance->txg_off = os->os_wrc_off_txg;
		}

		autosnap_force_snap_fast(wrc_instance->wrc_autosnap_hdl);
	}

	return (rc);
}

/*
 * Second stage of the WRC initialization.
 *
 * We walk over all DS of the given pool to activate
 * wrc_instances for DSs with activated WRC
 */
static void
wrc_init_thread(void *arg)
{
	wrc_data_t *wrc_data = arg;
	spa_t *spa = wrc_data->wrc_spa;
	dsl_dataset_t *ds_root = NULL;
	uint64_t dd_root_object;
	int err;

	/*
	 * If the feature flag is active then need to
	 * lookup the datasets that have enabled WRC
	 */
	if (spa_feature_is_active(spa, SPA_FEATURE_WRC)) {
		dsl_pool_config_enter(spa_get_dsl(spa), FTAG);

		err = dsl_dataset_hold(spa_get_dsl(spa), spa->spa_name,
		    FTAG, &ds_root);
		if (err != 0) {
			dsl_pool_config_exit(spa_get_dsl(spa), FTAG);
			mutex_enter(&wrc_data->wrc_lock);
			goto out;
		}

		dd_root_object = ds_root->ds_dir->dd_object;
		dsl_dataset_rele(ds_root, FTAG);

		VERIFY0(dmu_objset_find_dp(spa_get_dsl(spa), dd_root_object,
		    wrc_activate_instances, wrc_data, DS_FIND_CHILDREN));

		dsl_pool_config_exit(spa_get_dsl(spa), FTAG);
	}

	mutex_enter(&wrc_data->wrc_lock);

	wrc_data->wrc_ready_to_use = B_TRUE;
	if (avl_numnodes(&wrc_data->wrc_instances) != 0 &&
	    !wrc_data->wrc_thr_exit)
		wrc_start_thread(wrc_data->wrc_spa);

out:
	wrc_data->wrc_init_thread = NULL;
	cv_broadcast(&wrc_data->wrc_cv);
	mutex_exit(&wrc_data->wrc_lock);
}

/*
 * Initialize wrc properties for the given pool.
 */
static void
wrc_activate_impl(spa_t *spa, boolean_t pool_creation)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;
	wrc_stat_t *wrc_stat = &wrc_data->wrc_stat;
	uint64_t spa_children = spa->spa_root_vdev->vdev_children;
	int err = 0;
	boolean_t hold = B_FALSE;

	mutex_enter(&wrc_data->wrc_lock);
	if (wrc_data->wrc_isvalid) {
		mutex_exit(&wrc_data->wrc_lock);
		return;
	}

	/* Reset bookmark */
	bzero(&spa->spa_lszb, sizeof (spa->spa_lszb));

	wrc_data->wrc_roll_threshold = wrc_mv_cancel_threshold_initial;
	wrc_data->wrc_altered_limit = 0;
	wrc_data->wrc_altered_bytes = 0;
	wrc_data->wrc_window_bytes = 0;

	/* Reset statistics */
	wrc_stat->wrc_spa_util = 0;
	wrc_stat->wrc_stat_lbolt = 0;
	wrc_stat->wrc_stat_update = B_FALSE;

	/* Number of wrc block-moving threads - taskq nthreads */
	wrc_data->wrc_move_threads = MIN(wrc_max_move_tasks_count,
	    spa_children * zfs_vdev_async_write_max_active);

	/*
	 * Read wrc parameters to restore
	 * latest wrc window's boundaries
	 */
	if (!rrw_held(&spa->spa_dsl_pool->dp_config_rwlock,
	    RW_WRITER)) {
		rrw_enter(&spa->spa_dsl_pool->dp_config_rwlock,
		    RW_READER, FTAG);
		hold = B_TRUE;
	}

	err = zap_lookup(spa->spa_dsl_pool->dp_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT,
	    DMU_POOL_WRC_START_TXG, sizeof (uint64_t), 1,
	    &wrc_data->wrc_start_txg);
	if (err)
		wrc_data->wrc_start_txg = 4;

	err = zap_lookup(spa->spa_dsl_pool->dp_meta_objset,
	    DMU_POOL_DIRECTORY_OBJECT,
	    DMU_POOL_WRC_FINISH_TXG, sizeof (uint64_t), 1,
	    &wrc_data->wrc_finish_txg);
	if (!err) {
		err = zap_lookup(spa->spa_dsl_pool->dp_meta_objset,
		    DMU_POOL_DIRECTORY_OBJECT,
		    DMU_POOL_WRC_TO_RELE_TXG, sizeof (uint64_t), 1,
		    &wrc_data->wrc_txg_to_rele);
	}

	if (hold)
		rrw_exit(&spa->spa_dsl_pool->dp_config_rwlock, FTAG);

	if (err) {
		wrc_data->wrc_finish_txg = 0;
		wrc_data->wrc_txg_to_rele = 0;
	}

	wrc_data->wrc_latest_window_time = ddi_get_lbolt();

	wrc_data->wrc_ready_to_use = B_FALSE;
	wrc_data->wrc_thr_exit = B_FALSE;
	wrc_data->wrc_purge = B_FALSE;
	wrc_data->wrc_walk = B_TRUE;
	wrc_data->wrc_spa = spa;
	wrc_data->wrc_isvalid = B_TRUE;

	/* Finalize window interrupted by power cycle or reimport */
	wrc_free_restore(spa);

	if (pool_creation) {
		/* On create there is no reason to start init_thread */
		wrc_data->wrc_ready_to_use = B_TRUE;
	} else {
		/*
		 * On import need to restore wrc_instances.
		 * Do this asynchronously.
		 */
		wrc_data->wrc_init_thread = thread_create(NULL, 0,
		    wrc_init_thread, wrc_data, 0, &p0, TS_RUN, maxclsyspri);
	}

	mutex_exit(&wrc_data->wrc_lock);

	DTRACE_PROBE2(wrc_spa_add, char *, spa->spa_name,
	    spa_t *, spa);
}

void
wrc_deactivate(spa_t *spa)
{
	wrc_data_t *wrc_data = &spa->spa_wrc;

	mutex_enter(&wrc_data->wrc_lock);

	if (!spa_has_special(spa) || !wrc_data->wrc_isvalid) {
		mutex_exit(&wrc_data->wrc_lock);
		return;
	}

	DTRACE_PROBE1(wrc_deactiv_start, char *, spa->spa_name);

	wrc_data->wrc_isvalid = B_FALSE;

	while (wrc_data->wrc_init_thread != NULL)
		cv_wait(&wrc_data->wrc_cv, &wrc_data->wrc_lock);

	wrc_unregister_instances(wrc_data);

	VERIFY(avl_is_empty(&wrc_data->wrc_blocks));
	VERIFY(avl_is_empty(&wrc_data->wrc_moved_blocks));

	DTRACE_PROBE1(wrc_deactiv_done, char *, spa->spa_name);

	mutex_exit(&wrc_data->wrc_lock);
}

/*
 * AVL comparison function (callback) for writeback-cached blocks.
 * This function defines the tree's sorting order which is:
 * (vdev, offset) ascending, where vdev and offset are the respective
 * vdev id and offset of the block.
 *
 * Returns -1 if (block1 < block2), 0 if (block1 == block2),
 * and 1 when (block1 > block2).
 */
static int
wrc_blocks_compare(const void *arg1, const void *arg2)
{
	wrc_block_t *block1 = (wrc_block_t *)arg1;
	wrc_block_t *block2 = (wrc_block_t *)arg2;

	/* calculate vdev and offset for block1 and block2 */
	uint64_t vdev1 = DVA_GET_VDEV(&block1->dva[WRC_SPECIAL_DVA]);
	uint64_t offset1 = DVA_GET_OFFSET(&block1->dva[WRC_SPECIAL_DVA]);
	uint64_t vdev2 = DVA_GET_VDEV(&block2->dva[WRC_SPECIAL_DVA]);
	uint64_t offset2 = DVA_GET_OFFSET(&block2->dva[WRC_SPECIAL_DVA]);

	/* compare vdev's and offsets */
	int cmp1 = (vdev1 < vdev2) ? (-1) : (vdev1 == vdev2 ? 0 : 1);
	int cmp2 = (offset1 < offset2) ? (-1) : (offset1 == offset2 ? 0 : 1);
	int cmp = (cmp1 == 0) ? cmp2 : cmp1;

	return (cmp);
}

static int
wrc_instances_compare(const void *arg1, const void *arg2)
{
	const wrc_instance_t *instance1 = arg1;
	const wrc_instance_t *instance2 = arg2;

	if (instance1->ds_object > instance2->ds_object)
		return (1);

	if (instance1->ds_object < instance2->ds_object)
		return (-1);

	return (0);
}

static int
wrc_io(wrc_io_type_t type, wrc_block_t *block, void *data)
{
	zio_t *zio;
	zio_type_t zio_type;
	vdev_t *vd;
	uint64_t bias;
	size_t dva_num;

	if (type == WRC_READ_FROM_SPECIAL) {
		zio_type = ZIO_TYPE_READ;
		dva_num = WRC_SPECIAL_DVA;
	} else {
		ASSERT(type == WRC_WRITE_TO_NORMAL);
		zio_type = ZIO_TYPE_WRITE;
		dva_num = WRC_NORMAL_DVA;
	}

	vd = vdev_lookup_top(block->data->wrc_spa,
	    DVA_GET_VDEV(&block->dva[dva_num]));
	bias = vd->vdev_children == 0 ? VDEV_LABEL_START_SIZE : 0;
	zio = zio_wrc(zio_type, vd, data, WRCBP_GET_PSIZE(block),
	    DVA_GET_OFFSET(&block->dva[dva_num]) + bias);

	return (zio_wait(zio));
}

/*
 * if birth_txg is less than windows, then block is on
 * normal device only otherwise it can be found on
 * special, because deletion goes under lock and until
 * deletion is done, the block is accessible on special
 */
int
wrc_select_dva(wrc_data_t *wrc_data, zio_t *zio)
{
	uint64_t stxg;
	uint64_t ftxg;
	uint64_t btxg;
	int c;

	mutex_enter(&wrc_data->wrc_lock);

	stxg = wrc_data->wrc_start_txg;
	ftxg = wrc_data->wrc_finish_txg;
	btxg = BP_PHYSICAL_BIRTH(zio->io_bp);

	if (ftxg && btxg > ftxg) {
		DTRACE_PROBE(wrc_read_special_after);
		c = WRC_SPECIAL_DVA;
	} else if (btxg >= stxg) {
		if (!ftxg && wrc_data->wrc_delete) {
			DTRACE_PROBE(wrc_read_normal);
			c = WRC_NORMAL_DVA;
		} else {
			DTRACE_PROBE(wrc_read_special_inside);
			c = WRC_SPECIAL_DVA;
		}
	} else {
		DTRACE_PROBE(wrc_read_normal);
		c = WRC_NORMAL_DVA;
	}

	mutex_exit(&wrc_data->wrc_lock);

	return (c);
}

/*
 * 3 cases can be here
 * 1st - birth_txg is less than window - only normal device should be free
 * 2nd - inside window both trees are checked and if both of the trees
 *	haven't this block and deletion in process, then block is already
 *	freed, otherwise both dva are freed
 * 3rd - birth_txg is higher than window - both dva must be freed
 */
int
wrc_first_valid_dva(const blkptr_t *bp,
    wrc_data_t *wrc_data, boolean_t removal)
{
	int start_dva = 0;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	if (BP_PHYSICAL_BIRTH(bp) < wrc_data->wrc_start_txg) {
		start_dva = 1;
	} else if (BP_PHYSICAL_BIRTH(bp) <= wrc_data->wrc_finish_txg) {
		wrc_block_t search, *planned, *moved;

		/* Only DVA[0] is required for search */
		search.dva[WRC_SPECIAL_DVA] = bp->blk_dva[WRC_SPECIAL_DVA];

		moved = avl_find(&wrc_data->wrc_moved_blocks,
		    &search, NULL);
		if (moved != NULL && removal) {
			/*
			 * later WRC will do free for this block
			 */
			mutex_enter(&moved->lock);
			WRCBP_MARK_DELETED(moved);
			mutex_exit(&moved->lock);
		}

		planned = avl_find(&wrc_data->wrc_blocks,
		    &search, NULL);
		if (planned != NULL && removal) {
			avl_remove(&wrc_data->wrc_blocks, planned);
			wrc_free_block(planned);
		}

		if (planned == NULL && moved == NULL && wrc_data->wrc_delete)
			start_dva = 1;
	}

	return (start_dva);
}

/*
 * 1) for each dataset of the given pool at the dataset load time
 * 2) on each change of the wrc_mode property, for the dataset in
 * question and all its children
 *
 * see dsl_prop_register()/dsl_prop_unregister() and
 * dmu_objset_open_impl()/dmu_objset_evict()
 *
 * wrc_mode has 3 states:
 * ON, OFF - for user
 * OFF_DELAYED - for the internal using
 *
 * ON - generation of special BPs and migration
 * OFF_DELAYED - special BPs will not be created, but migration
 * still active to migrate. To migrate all blocks that still on SPECIAL
 * OFF - we migrated all blocks that were on special, so this instance
 * can be destroyed.
 */
void
wrc_mode_changed(void *arg, uint64_t newval)
{
	objset_t *os = arg;
	wrc_data_t *wrc_data = spa_get_wrc_data(os->os_spa);
	wrc_mode_prop_val_t *val =
	    (wrc_mode_prop_val_t *)((uintptr_t)newval);

	if (val->root_ds_object != 0) {
		os->os_wrc_root_ds_obj = val->root_ds_object;
		os->os_wrc_off_txg = val->txg_off;
		if (val->txg_off == 0)
			os->os_wrc_mode = ZFS_WRC_MODE_ON;
		else
			os->os_wrc_mode = ZFS_WRC_MODE_OFF_DELAYED;
	} else {
		if (os->os_wrc_mode == ZFS_WRC_MODE_OFF)
			return;

		os->os_wrc_mode = ZFS_WRC_MODE_OFF;
	}

	DTRACE_PROBE4(wrc_mc,
	    boolean_t, wrc_data->wrc_ready_to_use,
	    uint64_t, os->os_dsl_dataset->ds_object,
	    uint64_t, os->os_wrc_mode,
	    uint64_t, os->os_wrc_root_ds_obj);

	wrc_process_objset(wrc_data, os, B_FALSE);

	if (os->os_wrc_mode == ZFS_WRC_MODE_OFF) {
		os->os_wrc_root_ds_obj = 0;
		os->os_wrc_off_txg = 0;
	}
}

/*
 * This function is called:
 * 1) on change of wrc_mode property
 * 2) on destroying of a DS
 *
 * It processes only top-level DS of a WRC-DS-tree
 */
void
wrc_process_objset(wrc_data_t *wrc_data,
    objset_t *os, boolean_t destroy)
{
	wrc_instance_t *wrc_instance;
	size_t num_nodes_before, num_nodes_after;

	if (os->os_wrc_root_ds_obj == 0)
		return;

	mutex_enter(&wrc_data->wrc_lock);
	/* Do not register instances too early */
	if (!wrc_data->wrc_isvalid || !wrc_data->wrc_ready_to_use) {
		mutex_exit(&wrc_data->wrc_lock);
		return;
	}

	if (os->os_dsl_dataset->ds_object != os->os_wrc_root_ds_obj) {
		wrc_instance = wrc_lookup_instance(wrc_data,
		    os->os_wrc_root_ds_obj, NULL);

		/*
		 * If instance for us does not exist, then wrcache
		 * should not be enabled for this DS
		 */
		if (wrc_instance == NULL)
			os->os_wrc_mode = ZFS_WRC_MODE_OFF;

		mutex_exit(&wrc_data->wrc_lock);
		return;
	}

	num_nodes_before = avl_numnodes(&wrc_data->wrc_instances);

	if (os->os_wrc_mode == ZFS_WRC_MODE_OFF || destroy) {
		wrc_unregister_instance(wrc_data, os, !destroy);
	} else {
		wrc_instance = wrc_register_instance(wrc_data, os);
		if (wrc_instance != NULL &&
		    os->os_wrc_mode == ZFS_WRC_MODE_OFF_DELAYED &&
		    !wrc_instance->fini_migration) {
			wrc_instance->fini_migration = B_TRUE;
			wrc_instance->txg_off = os->os_wrc_off_txg;
			autosnap_force_snap_fast(
			    wrc_instance->wrc_autosnap_hdl);
		}

		if (wrc_instance == NULL) {
			/*
			 * We do not want to write data to special
			 * if the data will not be migrated, because
			 * registration failed
			 */
			os->os_wrc_mode = ZFS_WRC_MODE_OFF;
		}
	}

	num_nodes_after = avl_numnodes(&wrc_data->wrc_instances);

	mutex_exit(&wrc_data->wrc_lock);

	/*
	 * The first instance, so need to
	 * start the collector and the mover
	 */
	if ((num_nodes_after > num_nodes_before) &&
	    (num_nodes_before == 0)) {
		wrc_start_thread(wrc_data->wrc_spa);
	}

	/*
	 * The last instance, so need to
	 * stop the collector and the mover
	 */
	if ((num_nodes_after < num_nodes_before) &&
	    (num_nodes_after == 0)) {
		(void) wrc_stop_thread(wrc_data->wrc_spa);
	}
}

static wrc_instance_t *
wrc_register_instance(wrc_data_t *wrc_data, objset_t *os)
{
	dsl_dataset_t *ds = os->os_dsl_dataset;
	wrc_instance_t *wrc_instance;
	avl_index_t where = NULL;
	zfs_autosnap_t *autosnap;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	/* Is it already registered? */
	wrc_instance = wrc_lookup_instance(wrc_data,
	    ds->ds_object, &where);
	if (wrc_instance != NULL)
		return (wrc_instance);

	wrc_instance = kmem_zalloc(sizeof (wrc_instance_t), KM_SLEEP);
	wrc_instance->ds_object = ds->ds_object;
	wrc_instance->wrc_data = wrc_data;
	dsl_dataset_name(ds, wrc_instance->ds_name);
	autosnap = spa_get_autosnap(wrc_data->wrc_spa);
	wrc_instance->wrc_autosnap_hdl =
	    autosnap_register_handler_impl(autosnap, wrc_instance->ds_name,
	    AUTOSNAP_CREATOR | AUTOSNAP_DESTROYER |
	    AUTOSNAP_RECURSIVE | AUTOSNAP_WRC,
	    wrc_confirm_cb, wrc_nc_cb, wrc_err_cb, wrc_instance);
	if (wrc_instance->wrc_autosnap_hdl == NULL) {
		cmn_err(CE_WARN, "Cannot register autosnap handler "
		    "for WRC-Instance (%s)", wrc_instance->ds_name);
		kmem_free(wrc_instance, sizeof (wrc_instance_t));
		return (NULL);
	}

	DTRACE_PROBE2(register_done,
	    uint64_t, wrc_instance->ds_object,
	    char *, wrc_instance->ds_name);

	avl_insert(&wrc_data->wrc_instances, wrc_instance, where);

	return (wrc_instance);
}

static void
wrc_unregister_instance(wrc_data_t *wrc_data, objset_t *os,
    boolean_t rele_autosnap)
{
	dsl_dataset_t *ds = os->os_dsl_dataset;
	wrc_instance_t *wrc_instance;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	wrc_instance = wrc_lookup_instance(wrc_data, ds->ds_object, NULL);
	if (wrc_instance != NULL) {
		DTRACE_PROBE1(unregister_done,
		    uint64_t, wrc_instance->ds_object);

		avl_remove(&wrc_data->wrc_instances, wrc_instance);
		wrc_unregister_instance_impl(wrc_instance,
		    rele_autosnap && (wrc_instance->txg_to_rele != 0));
	}
}

static void
wrc_unregister_instances(wrc_data_t *wrc_data)
{
	void *cookie = NULL;
	wrc_instance_t *wrc_instance;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	while ((wrc_instance = avl_destroy_nodes(
	    &wrc_data->wrc_instances, &cookie)) != NULL)
		wrc_unregister_instance_impl(wrc_instance, B_FALSE);
}

static void
wrc_unregister_instance_impl(wrc_instance_t *wrc_instance,
    boolean_t rele_autosnap)
{
	if (rele_autosnap) {
		autosnap_release_snapshots_by_txg(
		    wrc_instance->wrc_autosnap_hdl,
		    wrc_instance->txg_to_rele,
		    AUTOSNAP_NO_SNAP);
	}

	autosnap_unregister_handler(wrc_instance->wrc_autosnap_hdl);
	kmem_free(wrc_instance, sizeof (wrc_instance_t));
}

static wrc_instance_t *
wrc_lookup_instance(wrc_data_t *wrc_data,
    uint64_t ds_object, avl_index_t *where)
{
	wrc_instance_t wrc_instance;

	ASSERT(MUTEX_HELD(&wrc_data->wrc_lock));

	wrc_instance.ds_object = ds_object;
	return (avl_find(&wrc_data->wrc_instances,
	    &wrc_instance, where));
}

/*
 * Returns:
 * 0  - the dataset is a top-level (root) writecached dataset
 * EOPNOTSUPP - the dataset is a writecached child
 * ENOTACTIVE - is not writecached
 * other zfs err - cannot open the pool, is busy, etc.
 */
int
wrc_check_dataset(const char *ds_name)
{
	int error;
	spa_t *spa = NULL;
	dsl_dataset_t *ds = NULL;
	objset_t *os = NULL;
	zfs_wrc_mode_t wrc_mode;
	uint64_t wrc_root_object, ds_object;

	error = spa_open(ds_name, &spa, FTAG);
	if (error != 0)
		return (error);

	dsl_pool_config_enter(spa_get_dsl(spa), FTAG);
	error = dsl_dataset_hold(spa_get_dsl(spa), ds_name, FTAG, &ds);
	if (error) {
		dsl_pool_config_exit(spa_get_dsl(spa), FTAG);
		spa_close(spa, FTAG);
		return (error);
	}

	error = dmu_objset_from_ds(ds, &os);
	dsl_pool_config_exit(spa_get_dsl(spa), FTAG);
	if (error) {
		dsl_dataset_rele(ds, FTAG);
		spa_close(spa, FTAG);
		return (error);
	}

	wrc_mode = os->os_wrc_mode;
	wrc_root_object = os->os_wrc_root_ds_obj;
	ds_object = ds->ds_object;
	dsl_dataset_rele(ds, FTAG);
	spa_close(spa, FTAG);

	if (wrc_mode != ZFS_WRC_MODE_OFF) {
		if (wrc_root_object != ds_object) {
			/* The child of writecached ds-tree */
			return (EOPNOTSUPP);
		}

		/* The root of writecached ds-tree */
		return (0);
	}

	/* not writecached */
	return (ENOTACTIVE);
}

/*
 * The function requires that all the writecache
 * instances are already disabled
 */
boolean_t
wrc_try_disable(wrc_data_t *wrc_data)
{
	boolean_t result = B_FALSE;

	mutex_enter(&wrc_data->wrc_lock);

	if (avl_numnodes(&wrc_data->wrc_instances) == 0) {
		wrc_data->wrc_isvalid = B_FALSE;
		result = B_TRUE;
	}

	mutex_exit(&wrc_data->wrc_lock);

	return (result);
}
