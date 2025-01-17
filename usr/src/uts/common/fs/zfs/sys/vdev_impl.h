/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, 2015 by Delphix. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef _SYS_VDEV_IMPL_H
#define	_SYS_VDEV_IMPL_H

#include <sys/avl.h>
#include <sys/dmu.h>
#include <sys/metaslab.h>
#include <sys/nvpair.h>
#include <sys/space_map.h>
#include <sys/vdev.h>
#include <sys/dkio.h>
#include <sys/uberblock_impl.h>
#include <sys/fs/zfs.h>
#include <sys/cos.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Virtual device descriptors.
 *
 * All storage pool operations go through the virtual device framework,
 * which provides data replication and I/O scheduling.
 */

/*
 * Forward declarations that lots of things need.
 */
typedef struct vdev_queue vdev_queue_t;
typedef struct vdev_cache vdev_cache_t;
typedef struct vdev_cache_entry vdev_cache_entry_t;
struct abd;

extern int zfs_vdev_queue_depth_pct;
extern uint32_t zfs_vdev_async_write_max_active;

/*
 * Virtual device operations
 */
typedef int	vdev_open_func_t(vdev_t *vd, uint64_t *size, uint64_t *max_size,
    uint64_t *ashift);
typedef void	vdev_close_func_t(vdev_t *vd);
typedef uint64_t vdev_asize_func_t(vdev_t *vd, uint64_t psize);
typedef void	vdev_io_start_func_t(zio_t *zio);
typedef void	vdev_io_done_func_t(zio_t *zio);
typedef void	vdev_state_change_func_t(vdev_t *vd, int, int);
typedef void	vdev_hold_func_t(vdev_t *vd);
typedef void	vdev_rele_func_t(vdev_t *vd);
typedef void	vdev_trim_func_t(vdev_t *vd, zio_t *pio, void *trim_exts);

typedef struct vdev_ops {
	vdev_open_func_t		*vdev_op_open;
	vdev_close_func_t		*vdev_op_close;
	vdev_asize_func_t		*vdev_op_asize;
	vdev_io_start_func_t		*vdev_op_io_start;
	vdev_io_done_func_t		*vdev_op_io_done;
	vdev_state_change_func_t	*vdev_op_state_change;
	vdev_hold_func_t		*vdev_op_hold;
	vdev_rele_func_t		*vdev_op_rele;
	vdev_trim_func_t		*vdev_op_trim;
	char				vdev_op_type[16];
	boolean_t			vdev_op_leaf;
} vdev_ops_t;

/*
 * Virtual device properties
 */
struct vdev_cache_entry {
	struct abd	*ve_abd;
	uint64_t	ve_offset;
	uint64_t	ve_lastused;
	avl_node_t	ve_offset_node;
	avl_node_t	ve_lastused_node;
	uint32_t	ve_hits;
	uint16_t	ve_missed_update;
	zio_t		*ve_fill_io;
};

struct vdev_cache {
	avl_tree_t	vc_offset_tree;
	avl_tree_t	vc_lastused_tree;
	kmutex_t	vc_lock;
};

/*
 * Macros for conversion between zio priorities and vdev properties.
 * These rely on the specific corresponding order of the zio_priority_t
 * and vdev_prop_t enum definitions to simplify the conversion.
 */
#define	VDEV_PROP_TO_ZIO_PRIO_MIN(prp)	((prp) - VDEV_PROP_READ_MINACTIVE)
#define	VDEV_ZIO_PRIO_TO_PROP_MIN(pri)	((pri) + VDEV_PROP_READ_MINACTIVE)
#define	VDEV_PROP_MIN_VALID(prp)		\
	(((prp) >= VDEV_PROP_READ_MINACTIVE) &&	\
	((prp) <= VDEV_PROP_SCRUB_MINACTIVE))
#define	VDEV_PROP_TO_ZIO_PRIO_MAX(prp)	((prp) - VDEV_PROP_READ_MAXACTIVE)
#define	VDEV_ZIO_PRIO_TO_PROP_MAX(pri)	((pri) + VDEV_PROP_READ_MAXACTIVE)
#define	VDEV_PROP_MAX_VALID(prp)		\
	(((prp) >= VDEV_PROP_READ_MAXACTIVE) &&	\
	((prp) <= VDEV_PROP_SCRUB_MAXACTIVE))

typedef struct vdev_queue_class {
	uint32_t	vqc_active;

	/*
	 * If min/max active values are zero, we fall back on the global
	 * corresponding tunables defined in vdev_queue.c; non-zero values
	 * override the global tunables
	 */
	uint32_t	vqc_min_active; /* min concurently active IOs */
	uint32_t	vqc_max_active; /* max concurently active IOs */

	/*
	 * Sorted by offset or timestamp, depending on if the queue is
	 * LBA-ordered vs FIFO.
	 */
	avl_tree_t	vqc_queued_tree;
} vdev_queue_class_t;

struct vdev_queue {
	vdev_t		*vq_vdev;

	vdev_queue_class_t vq_class[ZIO_PRIORITY_NUM_QUEUEABLE];
	cos_t		*vq_cos;		/* assigned class of storage */
	uint64_t	vq_preferred_read;	/* property setting */

	avl_tree_t	vq_active_tree;
	avl_tree_t	vq_read_offset_tree;
	avl_tree_t	vq_write_offset_tree;
	uint64_t	vq_last_offset;
	hrtime_t	vq_io_complete_ts;	/* time last i/o completed */
	kmutex_t	vq_lock;
};

/*
 * vdev auxiliary kstat I/O statistics:
 * updates every spa_special_stat_update_ticks interval
 * it is used for adjust special vs normal data routing
 */
typedef struct vdev_aux_stat {
	uint64_t nread;		/* number of bytes read */
	uint64_t nwritten;	/* number of bytes written */
	uint64_t reads;		/* number of read operations */
	uint64_t writes;	/* number of write operations */
	uint64_t rtime;		/* cumulative run (service) time */
	uint64_t wtime;		/* cumulative wait (pre-service) time */
	uint64_t rlentime;	/* cumulative run length*time product */
	uint64_t wlentime;	/* cumulative wait length*time product */
	uint64_t rlastupdate;	/* last time run queue changed */
	uint64_t wlastupdate;	/* last time wait queue changed */
	uint64_t rcnt;		/* count of elements in run state */
	uint64_t wcnt;		/* count of elements in wait state */
} vdev_aux_stat_t;

/*
 * Virtual device descriptor
 */
struct vdev {
	/*
	 * Common to all vdev types.
	 */
	uint64_t	vdev_id;	/* child number in vdev parent	*/
	uint64_t	vdev_guid;	/* unique ID for this vdev	*/
	uint64_t	vdev_guid_sum;	/* self guid + all child guids	*/
	uint64_t	vdev_orig_guid;	/* orig. guid prior to remove	*/
	uint64_t	vdev_asize;	/* allocatable device capacity	*/
	uint64_t	vdev_min_asize;	/* min acceptable asize		*/
	uint64_t	vdev_max_asize;	/* max acceptable asize		*/
	uint64_t	vdev_ashift;	/* block alignment shift	*/
	uint64_t	vdev_state;	/* see VDEV_STATE_* #defines	*/
	uint64_t	vdev_prevstate;	/* used when reopening a vdev	*/
	vdev_ops_t	*vdev_ops;	/* vdev operations		*/
	spa_t		*vdev_spa;	/* spa for this vdev		*/
	void		*vdev_tsd;	/* type-specific data		*/
	vnode_t		*vdev_name_vp;	/* vnode for pathname		*/
	vnode_t		*vdev_devid_vp;	/* vnode for devid		*/
	vdev_t		*vdev_top;	/* top-level vdev		*/
	vdev_t		*vdev_parent;	/* parent vdev			*/
	vdev_t		**vdev_child;	/* array of children		*/
	uint64_t	vdev_children;	/* number of children		*/
	vdev_stat_t	vdev_stat;	/* virtual device statistics	*/
	boolean_t	vdev_expanding;	/* expand the vdev?		*/
	boolean_t	vdev_reopening;	/* reopen in progress?		*/
	int		vdev_open_error; /* error on last open		*/
	kthread_t	*vdev_open_thread; /* thread opening children	*/
	uint64_t	vdev_crtxg;	/* txg when top-level was added */

	/*
	 * Top-level vdev state.
	 */
	uint64_t	vdev_ms_array;	/* metaslab array object	*/
	uint64_t	vdev_ms_shift;	/* metaslab size shift		*/
	uint64_t	vdev_ms_count;	/* number of metaslabs		*/
	metaslab_group_t *vdev_mg;	/* metaslab group		*/
	metaslab_t	**vdev_ms;	/* metaslab array		*/
	txg_list_t	vdev_ms_list;	/* per-txg dirty metaslab lists	*/
	txg_list_t	vdev_dtl_list;	/* per-txg dirty DTL lists	*/
	txg_node_t	vdev_txg_node;	/* per-txg dirty vdev linkage	*/
	boolean_t	vdev_remove_wanted; /* async remove wanted?	*/
	boolean_t	vdev_probe_wanted; /* async probe wanted?	*/
	list_node_t	vdev_config_dirty_node; /* config dirty list	*/
	list_node_t	vdev_state_dirty_node; /* state dirty list	*/
	uint64_t	vdev_deflate_ratio; /* deflation ratio (x512)	*/
	uint64_t	vdev_islog;	/* is an intent log device	*/
	uint64_t	vdev_removing;	/* device is being removed?	*/
	boolean_t	vdev_ishole;	/* is a hole in the namespace	*/
	uint64_t	vdev_top_zap;
	uint64_t	vdev_isspecial;	/* is a special device	*/

	boolean_t	vdev_man_trimming; /* manual trim is ongoing	*/
	uint64_t	vdev_trim_prog;	/* trim progress in bytes	*/

	/*
	 * Protects the vdev_scan_io_queue field itself as well as the
	 * structure's contents (when present). The scn_status_lock in
	 * dsl_scan_t must only ever be acquired stand-alone or inside
	 * of vdev_scan_queue_lock, never in reverse.
	 */
	kmutex_t			vdev_scan_io_queue_lock;
	struct dsl_scan_io_queue	*vdev_scan_io_queue;

	/*
	 * The queue depth parameters determine how many async writes are
	 * still pending (i.e. allocated by net yet issued to disk) per
	 * top-level (vdev_async_write_queue_depth) and the maximum allowed
	 * (vdev_max_async_write_queue_depth). These values only apply to
	 * top-level vdevs.
	 */
	uint64_t	vdev_async_write_queue_depth;
	uint64_t	vdev_max_async_write_queue_depth;

	/*
	 * Leaf vdev state.
	 */
	range_tree_t	*vdev_dtl[DTL_TYPES]; /* dirty time logs	*/
	space_map_t	*vdev_dtl_sm;	/* dirty time log space map	*/
	txg_node_t	vdev_dtl_node;	/* per-txg dirty DTL linkage	*/
	uint64_t	vdev_dtl_object; /* DTL object			*/
	uint64_t	vdev_psize;	/* physical device capacity	*/
	uint64_t	vdev_wholedisk;	/* true if this is a whole disk */
	uint64_t	vdev_offline;	/* persistent offline state	*/
	uint64_t	vdev_faulted;	/* persistent faulted state	*/
	uint64_t	vdev_degraded;	/* persistent degraded state	*/
	uint64_t	vdev_removed;	/* persistent removed state	*/
	uint64_t	vdev_resilver_txg; /* persistent resilvering state */
	uint64_t	vdev_nparity;	/* number of parity devices for raidz */
	uint64_t	vdev_l2ad_ddt;	/* L2ARC vdev is used to cache DDT */
	char		*vdev_path;	/* vdev path (if any)		*/
	char		*vdev_devid;	/* vdev devid (if any)		*/
	char		*vdev_physpath;	/* vdev device path (if any)	*/
	char		*vdev_fru;	/* physical FRU location	*/
	int64_t		vdev_weight;	/* dynamic weight */
	uint64_t	vdev_not_present; /* not present during import	*/
	uint64_t	vdev_unspare;	/* unspare when resilvering done */
	boolean_t	vdev_nowritecache; /* true if flushwritecache failed */
	boolean_t	vdev_notrim;	/* true if Unmap/TRIM is unsupported */
	boolean_t	vdev_checkremove; /* temporary online test	*/
	boolean_t	vdev_forcefault; /* force online fault		*/
	boolean_t	vdev_splitting;	/* split or repair in progress  */
	boolean_t	vdev_delayed_close; /* delayed device close?	*/
	boolean_t	vdev_tmpoffline; /* device taken offline temporarily? */
	boolean_t	vdev_detached;	/* device detached?		*/
	boolean_t	vdev_cant_read;	/* vdev is failing all reads	*/
	boolean_t	vdev_cant_write; /* vdev is failing all writes	*/
	boolean_t	vdev_isspare;	/* was a hot spare		*/
	boolean_t	vdev_isl2cache;	/* was a l2cache device		*/
	boolean_t	vdev_isspecial_child; /* a child of top-level special */
	vdev_queue_t	vdev_queue;	/* I/O deadline schedule queue	*/
	vdev_cache_t	vdev_cache;	/* physical block cache		*/
	spa_aux_vdev_t	*vdev_aux;	/* for l2cache and spares vdevs	*/
	zio_t		*vdev_probe_zio; /* root of current probe	*/
	vdev_aux_t	vdev_label_aux;	/* on-disk aux state		*/
	uint64_t	vdev_leaf_zap;
	boolean_t	vdev_is_ssd;	/* is solid state device	*/

	char		*vdev_spare_group; /* spare group name */

	struct kstat	*vdev_iokstat; /* vdev kstat I/O statistics */
	vdev_aux_stat_t	vdev_aux_stat; /* auxiliary vdev kstat I/O statistics */
	/*
	 * For DTrace to work in userland (libzpool) context, these fields must
	 * remain at the end of the structure.  DTrace will use the kernel's
	 * CTF definition for 'struct vdev', and since the size of a kmutex_t is
	 * larger in userland, the offsets for the rest of the fields would be
	 * incorrect.
	 */
	kmutex_t	vdev_dtl_lock;	/* vdev_dtl_{map,resilver}	*/
	kmutex_t	vdev_stat_lock;	/* vdev_stat			*/
	kmutex_t	vdev_probe_lock; /* protects vdev_probe_zio	*/
	krwlock_t	vdev_tsd_lock;	/* protects vdev_tsd */
};

#define	VDEV_RAIDZ_MAXPARITY	3

#define	VDEV_PAD_SIZE		(8 << 10)
/* 2 padding areas (vl_pad1 and vl_pad2) to skip */
#define	VDEV_SKIP_SIZE		VDEV_PAD_SIZE * 2
#define	VDEV_PHYS_SIZE		(112 << 10)
#define	VDEV_UBERBLOCK_RING	(128 << 10)

/* The largest uberblock we support is 8k. */
#define	MAX_UBERBLOCK_SHIFT (13)
#define	VDEV_UBERBLOCK_SHIFT(vd)	\
	MIN(MAX((vd)->vdev_top->vdev_ashift, UBERBLOCK_SHIFT), \
	    MAX_UBERBLOCK_SHIFT)
#define	VDEV_UBERBLOCK_COUNT(vd)	\
	(VDEV_UBERBLOCK_RING >> VDEV_UBERBLOCK_SHIFT(vd))
#define	VDEV_UBERBLOCK_OFFSET(vd, n)	\
	offsetof(vdev_label_t, vl_uberblock[(n) << VDEV_UBERBLOCK_SHIFT(vd)])
#define	VDEV_UBERBLOCK_SIZE(vd)		(1ULL << VDEV_UBERBLOCK_SHIFT(vd))

typedef struct vdev_phys {
	char		vp_nvlist[VDEV_PHYS_SIZE - sizeof (zio_eck_t)];
	zio_eck_t	vp_zbt;
} vdev_phys_t;

typedef struct vdev_label {
	char		vl_pad1[VDEV_PAD_SIZE];			/*  8K */
	char		vl_pad2[VDEV_PAD_SIZE];			/*  8K */
	vdev_phys_t	vl_vdev_phys;				/* 112K	*/
	char		vl_uberblock[VDEV_UBERBLOCK_RING];	/* 128K	*/
} vdev_label_t;							/* 256K total */

/*
 * vdev_dirty() flags
 */
#define	VDD_METASLAB	0x01
#define	VDD_DTL		0x02

/* Offset of embedded boot loader region on each label */
#define	VDEV_BOOT_OFFSET	(2 * sizeof (vdev_label_t))
/*
 * Size of embedded boot loader region on each label.
 * The total size of the first two labels plus the boot area is 4MB.
 */
#define	VDEV_BOOT_SIZE		(7ULL << 19)			/* 3.5M */

/*
 * Size of label regions at the start and end of each leaf device.
 */
#define	VDEV_LABEL_START_SIZE	(2 * sizeof (vdev_label_t) + VDEV_BOOT_SIZE)
#define	VDEV_LABEL_END_SIZE	(2 * sizeof (vdev_label_t))
#define	VDEV_LABELS		4
#define	VDEV_BEST_LABEL		VDEV_LABELS

#define	VDEV_ALLOC_LOAD		0
#define	VDEV_ALLOC_ADD		1
#define	VDEV_ALLOC_SPARE	2
#define	VDEV_ALLOC_L2CACHE	3
#define	VDEV_ALLOC_ROOTPOOL	4
#define	VDEV_ALLOC_SPLIT	5
#define	VDEV_ALLOC_ATTACH	6

/*
 * Allocate or free a vdev
 */
extern vdev_t *vdev_alloc_common(spa_t *spa, uint_t id, uint64_t guid,
    vdev_ops_t *ops);
extern int vdev_alloc(spa_t *spa, vdev_t **vdp, nvlist_t *config,
    vdev_t *parent, uint_t id, int alloctype);
extern void vdev_free(vdev_t *vd);

/*
 * Add or remove children and parents
 */
extern void vdev_add_child(vdev_t *pvd, vdev_t *cvd);
extern void vdev_remove_child(vdev_t *pvd, vdev_t *cvd);
extern void vdev_compact_children(vdev_t *pvd);
extern vdev_t *vdev_add_parent(vdev_t *cvd, vdev_ops_t *ops);
extern void vdev_remove_parent(vdev_t *cvd);

/*
 * vdev sync load and sync
 */
extern void vdev_load_log_state(vdev_t *nvd, vdev_t *ovd);
extern boolean_t vdev_log_state_valid(vdev_t *vd);
extern void vdev_load(vdev_t *vd);
extern int vdev_dtl_load(vdev_t *vd);
extern void vdev_sync(vdev_t *vd, uint64_t txg);
extern void vdev_sync_done(vdev_t *vd, uint64_t txg);
extern void vdev_dirty(vdev_t *vd, int flags, void *arg, uint64_t txg);
extern void vdev_dirty_leaves(vdev_t *vd, int flags, uint64_t txg);

/*
 * Available vdev types.
 */
extern vdev_ops_t vdev_root_ops;
extern vdev_ops_t vdev_mirror_ops;
extern vdev_ops_t vdev_replacing_ops;
extern vdev_ops_t vdev_raidz_ops;
extern vdev_ops_t vdev_disk_ops;
extern vdev_ops_t vdev_file_ops;
extern vdev_ops_t vdev_missing_ops;
extern vdev_ops_t vdev_hole_ops;
extern vdev_ops_t vdev_spare_ops;

extern uint_t vdev_count_leaf_vdevs(vdev_t *root);

/*
 * Common size functions
 */
extern uint64_t vdev_default_asize(vdev_t *vd, uint64_t psize);
extern uint64_t vdev_get_min_asize(vdev_t *vd);
extern void vdev_set_min_asize(vdev_t *vd);


/*
 * Wrapper for getting vdev-specific properties that enforces proper
 * overriding: vdev-specific properties override CoS properties
 *
 * The value of 0 indicates that the property is not set (default).
 */
extern uint64_t vdev_queue_get_prop_uint64(vdev_queue_t *vq, vdev_prop_t prop);

/*
 * Global variables
 */
/* zdb uses this tunable, so it must be declared here to make lint happy. */
extern int zfs_vdev_cache_size;

/*
 * The vdev_buf_t is used to translate between zio_t and buf_t, and back again.
 */
typedef struct vdev_buf {
	buf_t	vb_buf;		/* buffer that describes the io */
	zio_t	*vb_io;		/* pointer back to the original zio_t */
} vdev_buf_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VDEV_IMPL_H */
