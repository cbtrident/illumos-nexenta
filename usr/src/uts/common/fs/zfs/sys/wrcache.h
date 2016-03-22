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

#ifndef	_SYS_WRCACHE_H
#define	_SYS_WRCACHE_H

#include <sys/zfs_context.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/fs/zfs.h>
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_pool.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * write cache special class.
 */

#define	WRCIO_PERC_MIN	(25)
#define	WRCIO_PERC_MAX	(75)

/*
 * field 'blk_prop' of wrc_block_t
 *
 * 64              48               32              16              0
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 *  |      RESERVED    |D(1)|comp(7)|  PSIZE(16)    |     LSIZE(16) |
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 *
 * Legend:
 * D			deleted
 * comp			compression function of payload
 * PSIZE		size of payload after compression, in bytes
 * LSIZE		logical size of payload, in bytes
 *
 * Deleted block is a block whos dva was freed,
 * so this block must not be used by wrc_move_logic
 * and after move has been finished need to free only block-structure
 */
#define	WRCBP_GET_LSIZE(bp)	\
	BF64_GET_SB((bp)->blk_prop, 0, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1)
#define	WRCBP_SET_LSIZE(bp, x)	do { \
	BF64_SET_SB((bp)->blk_prop, \
	    0, SPA_LSIZEBITS, SPA_MINBLOCKSHIFT, 1, x); \
_NOTE(CONSTCOND) } while (0)

#define	WRCBP_GET_PSIZE(bp)	\
	BF64_GET_SB((bp)->blk_prop, 16, SPA_PSIZEBITS, SPA_MINBLOCKSHIFT, 1)
#define	WRCBP_SET_PSIZE(bp, x)	do { \
	BF64_SET_SB((bp)->blk_prop, \
	    16, SPA_PSIZEBITS, SPA_MINBLOCKSHIFT, 1, x); \
_NOTE(CONSTCOND) } while (0)

#define	WRCBP_GET_COMPRESS(bp)		BF64_GET((bp)->blk_prop, 32, 7)
#define	WRCBP_SET_COMPRESS(bp, x)	BF64_SET((bp)->blk_prop, 32, 7, x)

#define	WRCBP_IS_DELETED(wrcbp)		BF64_GET((wrcbp)->blk_prop, 39, 1)
#define	WRCBP_MARK_DELETED(wrcbp)	BF64_SET((wrcbp)->blk_prop, 39, 1, 1)

typedef struct wrc_data wrc_data_t;

/*
 * WRC Instance is a dataset (DS) and
 * all the children DSs of that DS.
 */
typedef struct wrc_instance {
	avl_node_t	node;

	wrc_data_t	*wrc_data;
	void		*wrc_autosnap_hdl;
	char		ds_name[MAXNAMELEN];

	/* copy of dsl_dataset_t->ds_object */
	uint64_t	ds_object;

	/*
	 * TXG of the right boundary WRC-window
	 * can be 0 if this instance is 'idle'
	 */
	uint64_t	txg_to_rele;

	/*
	 * txg of the specific TXG sync that
	 * executed 'off' on this instance
	 */
	uint64_t	txg_off;

	boolean_t	fini_migration;
	boolean_t	fini_done;
} wrc_instance_t;

/*
 * wrc statistics
 */
typedef struct wrc_stat {
	uint64_t	wrc_spa_util;		/* spa average utilization */
	clock_t		wrc_stat_lbolt;		/* last statistics update */
	boolean_t	wrc_stat_update;	/* statstics update flag */
} wrc_stat_t;

/*
 * wrc_data is a global per ZFS pool structure contains all
 * information associated with write cache and
 * is attached to spa structure.
 */
struct wrc_data {
	kthread_t	*wrc_init_thread;
	kthread_t	*wrc_thread;		/* move thread */
	kthread_t	*wrc_walk_thread;	/* collector thread */

	kmutex_t	wrc_lock;
	kcondvar_t	wrc_cv;

	/* TASKQ that does async finalization of wrc_instances */
	taskq_t		*wrc_instance_fini;

	uint64_t	wrc_instance_fini_cnt;

	avl_tree_t	wrc_blocks;		/* collected blocks */
	avl_tree_t	wrc_moved_blocks;	/* moved blocks */

	uint64_t	wrc_window_bytes;	/* bytes in current wnd */
	uint64_t	wrc_altered_bytes;	/* bytes altered in new wnd */
	uint64_t	wrc_roll_threshold;	/* max percent can be altered */
	uint64_t	wrc_altered_limit;	/* max bytes can be altered */

	uint64_t	wrc_blocks_count;	/* amount of blocks */

	taskq_t		*wrc_move_taskq;	/* pending blocks taskq */
	uint64_t	wrc_move_threads;	/* taskq number of threads */

	uint64_t	wrc_start_txg;		/* left boundary */
	uint64_t	wrc_finish_txg;		/* right boundary */
	uint64_t	wrc_txg_to_rele;	/* txg to rele */
	uint64_t	wrc_blocks_in;		/* collected */
	uint64_t	wrc_blocks_out;		/* planned */
	uint64_t	wrc_blocks_mv;		/* moved */
	uint64_t	wrc_blocks_mv_last; /* latest number of moved blocks */

	uint64_t	wrc_latest_window_time;

	/* Tree of watched datasets and corresponding data */
	avl_tree_t	wrc_instances;
	boolean_t	wrc_ready_to_use;

	spa_t		*wrc_spa;		/* parent spa */
	wrc_stat_t	wrc_stat;		/* wrc statistics */

	uint64_t	wrc_fault_moves;	/* amount of fault moves */

	boolean_t	wrc_purge;	/* should purge queued blocks */
	boolean_t	wrc_walk;	/* should walk */
	boolean_t	wrc_locked;	/* do not walk while locked */
	boolean_t	wrc_walking;	/* currently walking */
	boolean_t	wrc_wait_for_window;

	boolean_t	wrc_delete;	/* delete state */

	boolean_t	wrc_thr_exit;	/* exit flag */
	boolean_t	wrc_isvalid;	/* wrc is inited */
	boolean_t	wrc_isfault;	/* wrc is fault */
	boolean_t	wrc_first_move; /* TRUE until the 1 WRC-win opened */
};

/* !!! Do not change these constants !!! */
#define	WRC_SPECIAL_DVA 0
#define	WRC_NORMAL_DVA 1

/*
 * In-core representation of a block which will be moved
 */
typedef struct wrc_block {
	avl_node_t	node;

	/* associated wrc */
	wrc_data_t	*data;

	/*
	 * size, compression
	 */
	uint64_t	blk_prop;

	/* birth txg for arc lookup */
	uint64_t	btxg;

	/* dvas of blocks to move */
	dva_t		dva[2];

	kmutex_t	lock;
} wrc_block_t;

typedef struct wrc_parseblock_cb {
	wrc_data_t	*wrc_data;

	/*
	 * A bookmark for resume
	 */
	zbookmark_phys_t	zb;

	/*
	 * Total size of all collected blocks
	 */
	uint64_t	bt_size;

	/*
	 * The time we started traversal process
	 */
	hrtime_t	start_time;

	uint64_t	actv_txg;
} wrc_parseblock_cb_t;

/*
 * This structure describes ZFS_PROP_WRC_MODE property
 */
typedef struct {
	/*
	 * copy of dsl_dataset_t->ds_object of dataset
	 * for which user does wrc_mode=on
	 */
	uint64_t	root_ds_object;

	/*
	 * TXG when user did 'wrc_mode=off'
	 */
	uint64_t	txg_off;

	/*
	 * Flags. Now is not used.
	 */
	uint64_t	flags;
} wrc_mode_prop_val_t;

#define	WRC_MODE_PROP_VAL_SZ (sizeof (wrc_mode_prop_val_t) / sizeof (uint64_t))

void wrc_init(wrc_data_t *wrc_data, spa_t *spa);
void wrc_fini(wrc_data_t *wrc_data);

void wrc_activate(spa_t *spa, boolean_t pool_creation);
void wrc_deactivate(spa_t *spa);
void wrc_enter_fault_state(spa_t *spa);

int wrc_select_dva(wrc_data_t *wrc_data, zio_t *zio);
int wrc_first_valid_dva(const blkptr_t *bp,
    wrc_data_t *wrc_data, boolean_t removal);

wrc_data_t *spa_get_wrc_data(spa_t *spa);

void wrc_add_bytes(spa_t *spa, uint64_t txg, uint64_t bytes);

/*
 * write cache thread.
 */
void wrc_start_thread(spa_t *);
boolean_t wrc_stop_thread(spa_t *);
void wrc_trigger_wrcthread(spa_t *, uint64_t);

/*
 * callback function for traverse_dataset which validates
 * the block pointer and adds to the list.
 */
blkptr_cb_t	wrc_traverse_ds_cb;

boolean_t wrc_check_parseblocks_hold(spa_t *);
void wrc_check_parseblocks_rele(spa_t *spa);
boolean_t wrc_try_hold(spa_t *);
int wrc_walk_lock(spa_t *);
void wrc_walk_unlock(spa_t *);

void wrc_process_objset(wrc_data_t *wrc_data, objset_t *os, boolean_t destroy);
void wrc_mode_changed(void *arg, uint64_t newval);
int wrc_check_dataset(const char *ds_name);

boolean_t wrc_try_disable(wrc_data_t *wrc_data);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_WRCACHE_H */
