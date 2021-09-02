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
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright (c) 2011, 2018 by Delphix. All rights reserved.
 * Copyright (c) 2014 by Saso Kiselkov. All rights reserved.
 * Copyright 2019 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * DVA-based Adjustable Replacement Cache
 *
 * While much of the theory of operation used here is
 * based on the self-tuning, low overhead replacement cache
 * presented by Megiddo and Modha at FAST 2003, there are some
 * significant differences:
 *
 * 1. The Megiddo and Modha model assumes any page is evictable.
 * Pages in its cache cannot be "locked" into memory.  This makes
 * the eviction algorithm simple: evict the last page in the list.
 * This also make the performance characteristics easy to reason
 * about.  Our cache is not so simple.  At any given moment, some
 * subset of the blocks in the cache are un-evictable because we
 * have handed out a reference to them.  Blocks are only evictable
 * when there are no external references active.  This makes
 * eviction far more problematic:  we choose to evict the evictable
 * blocks that are the "lowest" in the list.
 *
 * There are times when it is not possible to evict the requested
 * space.  In these circumstances we are unable to adjust the cache
 * size.  To prevent the cache growing unbounded at these times we
 * implement a "cache throttle" that slows the flow of new data
 * into the cache until we can make space available.
 *
 * 2. The Megiddo and Modha model assumes a fixed cache size.
 * Pages are evicted when the cache is full and there is a cache
 * miss.  Our model has a variable sized cache.  It grows with
 * high use, but also tries to react to memory pressure from the
 * operating system: decreasing its size when system memory is
 * tight.
 *
 * 3. The Megiddo and Modha model assumes a fixed page size. All
 * elements of the cache are therefore exactly the same size.  So
 * when adjusting the cache size following a cache miss, its simply
 * a matter of choosing a single page to evict.  In our model, we
 * have variable sized cache blocks (rangeing from 512 bytes to
 * 128K bytes).  We therefore choose a set of blocks to evict to make
 * space for a cache miss that approximates as closely as possible
 * the space used by the new block.
 *
 * See also:  "ARC: A Self-Tuning, Low Overhead Replacement Cache"
 * by N. Megiddo & D. Modha, FAST 2003
 */

/*
 * The locking model:
 *
 * A new reference to a cache buffer can be obtained in two
 * ways: 1) via a hash table lookup using the DVA as a key,
 * or 2) via one of the ARC lists.  The arc_read() interface
 * uses method 1, while the internal ARC algorithms for
 * adjusting the cache use method 2.  We therefore provide two
 * types of locks: 1) the hash table lock array, and 2) the
 * ARC list locks.
 *
 * Buffers do not have their own mutexes, rather they rely on the
 * hash table mutexes for the bulk of their protection (i.e. most
 * fields in the arc_buf_hdr_t are protected by these mutexes).
 *
 * buf_hash_find() returns the appropriate mutex (held) when it
 * locates the requested buffer in the hash table.  It returns
 * NULL for the mutex if the buffer was not in the table.
 *
 * buf_hash_remove() expects the appropriate hash mutex to be
 * already held before it is invoked.
 *
 * Each ARC state also has a mutex which is used to protect the
 * buffer list associated with the state.  When attempting to
 * obtain a hash table lock while holding an ARC list lock you
 * must use: mutex_tryenter() to avoid deadlock.  Also note that
 * the active state mutex must be held before the ghost state mutex.
 *
 * Note that the majority of the performance stats are manipulated
 * with atomic operations.
 *
 * The L2ARC uses the l2ad_mtx on each vdev for the following:
 *
 *	- L2ARC buflist creation
 *	- L2ARC buflist eviction
 *	- L2ARC write completion, which walks L2ARC buflists
 *	- ARC header destruction, as it removes from L2ARC buflists
 *	- ARC header release, as it removes from L2ARC buflists
 */

/*
 * ARC operation:
 *
 * Every block that is in the ARC is tracked by an arc_buf_hdr_t structure.
 * This structure can point either to a block that is still in the cache or to
 * one that is only accessible in an L2 ARC device, or it can provide
 * information about a block that was recently evicted. If a block is
 * only accessible in the L2ARC, then the arc_buf_hdr_t only has enough
 * information to retrieve it from the L2ARC device. This information is
 * stored in the l2arc_buf_hdr_t sub-structure of the arc_buf_hdr_t. A block
 * that is in this state cannot access the data directly.
 *
 * Blocks that are actively being referenced or have not been evicted
 * are cached in the L1ARC. The L1ARC (l1arc_buf_hdr_t) is a structure within
 * the arc_buf_hdr_t that will point to the data block in memory. A block can
 * only be read by a consumer if it has an l1arc_buf_hdr_t. The L1ARC
 * caches data in two ways -- in a list of ARC buffers (arc_buf_t) and
 * also in the arc_buf_hdr_t's private physical data block pointer (b_pabd).
 *
 * The L1ARC's data pointer may or may not be uncompressed. The ARC has the
 * ability to store the physical data (b_pabd) associated with the DVA of the
 * arc_buf_hdr_t. Since the b_pabd is a copy of the on-disk physical block,
 * it will match its on-disk compression characteristics. This behavior can be
 * disabled by setting 'zfs_compressed_arc_enabled' to B_FALSE. When the
 * compressed ARC functionality is disabled, the b_pabd will point to an
 * uncompressed version of the on-disk data.
 *
 * Data in the L1ARC is not accessed by consumers of the ARC directly. Each
 * arc_buf_hdr_t can have multiple ARC buffers (arc_buf_t) which reference it.
 * Each ARC buffer (arc_buf_t) is being actively accessed by a specific ARC
 * consumer. The ARC will provide references to this data and will keep it
 * cached until it is no longer in use. The ARC caches only the L1ARC's physical
 * data block and will evict any arc_buf_t that is no longer referenced. The
 * amount of memory consumed by the arc_buf_ts' data buffers can be seen via the
 * "overhead_size" kstat.
 *
 * Depending on the consumer, an arc_buf_t can be requested in uncompressed or
 * compressed form. The typical case is that consumers will want uncompressed
 * data, and when that happens a new data buffer is allocated where the data is
 * decompressed for them to use. Currently the only consumer who wants
 * compressed arc_buf_t's is "zfs send", when it streams data exactly as it
 * exists on disk. When this happens, the arc_buf_t's data buffer is shared
 * with the arc_buf_hdr_t.
 *
 * Here is a diagram showing an arc_buf_hdr_t referenced by two arc_buf_t's. The
 * first one is owned by a compressed send consumer (and therefore references
 * the same compressed data buffer as the arc_buf_hdr_t) and the second could be
 * used by any other consumer (and has its own uncompressed copy of the data
 * buffer).
 *
 *   arc_buf_hdr_t
 *   +-----------+
 *   | fields    |
 *   | common to |
 *   | L1- and   |
 *   | L2ARC     |
 *   +-----------+
 *   | l2arc_buf_hdr_t
 *   |           |
 *   +-----------+
 *   | l1arc_buf_hdr_t
 *   |           |              arc_buf_t
 *   | b_buf     +------------>+-----------+      arc_buf_t
 *   | b_pabd    +-+           |b_next     +---->+-----------+
 *   +-----------+ |           |-----------|     |b_next     +-->NULL
 *                 |           |b_comp = T |     +-----------+
 *                 |           |b_data     +-+   |b_comp = F |
 *                 |           +-----------+ |   |b_data     +-+
 *                 +->+------+               |   +-----------+ |
 *        compressed  |      |               |                 |
 *           data     |      |<--------------+                 | uncompressed
 *                    +------+          compressed,            |     data
 *                                        shared               +-->+------+
 *                                         data                    |      |
 *                                                                 |      |
 *                                                                 +------+
 *
 * When a consumer reads a block, the ARC must first look to see if the
 * arc_buf_hdr_t is cached. If the hdr is cached then the ARC allocates a new
 * arc_buf_t and either copies uncompressed data into a new data buffer from an
 * existing uncompressed arc_buf_t, decompresses the hdr's b_pabd buffer into a
 * new data buffer, or shares the hdr's b_pabd buffer, depending on whether the
 * hdr is compressed and the desired compression characteristics of the
 * arc_buf_t consumer. If the arc_buf_t ends up sharing data with the
 * arc_buf_hdr_t and both of them are uncompressed then the arc_buf_t must be
 * the last buffer in the hdr's b_buf list, however a shared compressed buf can
 * be anywhere in the hdr's list.
 *
 * The diagram below shows an example of an uncompressed ARC hdr that is
 * sharing its data with an arc_buf_t (note that the shared uncompressed buf is
 * the last element in the buf list):
 *
 *                arc_buf_hdr_t
 *                +-----------+
 *                |           |
 *                |           |
 *                |           |
 *                +-----------+
 * l2arc_buf_hdr_t|           |
 *                |           |
 *                +-----------+
 * l1arc_buf_hdr_t|           |
 *                |           |                 arc_buf_t    (shared)
 *                |    b_buf  +------------>+---------+      arc_buf_t
 *                |           |             |b_next   +---->+---------+
 *                |  b_pabd   +-+           |---------|     |b_next   +-->NULL
 *                +-----------+ |           |         |     +---------+
 *                              |           |b_data   +-+   |         |
 *                              |           +---------+ |   |b_data   +-+
 *                              +->+------+             |   +---------+ |
 *                                 |      |             |               |
 *                   uncompressed  |      |             |               |
 *                        data     +------+             |               |
 *                                    ^                 +->+------+     |
 *                                    |       uncompressed |      |     |
 *                                    |           data     |      |     |
 *                                    |                    +------+     |
 *                                    +---------------------------------+
 *
 * Writing to the ARC requires that the ARC first discard the hdr's b_pabd
 * since the physical block is about to be rewritten. The new data contents
 * will be contained in the arc_buf_t. As the I/O pipeline performs the write,
 * it may compress the data before writing it to disk. The ARC will be called
 * with the transformed data and will bcopy the transformed on-disk block into
 * a newly allocated b_pabd. Writes are always done into buffers which have
 * either been loaned (and hence are new and don't have other readers) or
 * buffers which have been released (and hence have their own hdr, if there
 * were originally other readers of the buf's original hdr). This ensures that
 * the ARC only needs to update a single buf and its hdr after a write occurs.
 *
 * When the L2ARC is in use, it will also take advantage of the b_pabd. The
 * L2ARC will always write the contents of b_pabd to the L2ARC. This means
 * that when compressed ARC is enabled that the L2ARC blocks are identical
 * to the on-disk block in the main data pool. This provides a significant
 * advantage since the ARC can leverage the bp's checksum when reading from the
 * L2ARC to determine if the contents are valid. However, if the compressed
 * ARC is disabled, then the L2ARC's block must be transformed to look
 * like the physical block in the main data pool before comparing the
 * checksum and determining its validity.
 */

#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/zio.h>
#include <sys/spa_impl.h>
#include <sys/zio_compress.h>
#include <sys/zio_checksum.h>
#include <sys/zfs_context.h>
#include <sys/arc.h>
#include <sys/refcount.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>
#include <sys/dsl_pool.h>
#include <sys/zio_checksum.h>
#include <sys/multilist.h>
#include <sys/abd.h>
#ifdef _KERNEL
#include <sys/vmsystm.h>
#include <vm/anon.h>
#include <sys/fs/swapnode.h>
#include <sys/dnlc.h>
#endif
#include <sys/callb.h>
#include <sys/kstat.h>
#include <zfs_fletcher.h>
#include <sys/byteorder.h>
#include <sys/aggsum.h>
#include <sys/cityhash.h>

#ifndef _KERNEL
/* set with ZFS_DEBUG=watch, to enable watchpoints on frozen buffers */
boolean_t arc_watch = B_FALSE;
int arc_procfd;
#endif

static kmutex_t		arc_reclaim_lock;
static kcondvar_t	arc_reclaim_thread_cv;
static boolean_t	arc_reclaim_thread_exit;
static kcondvar_t	arc_reclaim_waiters_cv;

uint_t arc_reduce_dnlc_percent = 3;

/*
 * The number of headers to evict in arc_evict_state_impl() before
 * dropping the sublist lock and evicting from another sublist. A lower
 * value means we're more likely to evict the "correct" header (i.e. the
 * oldest header in the arc state), but comes with higher overhead
 * (i.e. more invocations of arc_evict_state_impl()).
 */
int zfs_arc_evict_batch_limit = 10;

/* number of seconds before growing cache again */
static int		arc_grow_retry = 60;

/* number of milliseconds before attempting a kmem-cache-reap */
static int		arc_kmem_cache_reap_retry_ms = 1000;

/* shift of arc_c for calculating overflow limit in arc_get_data_impl */
int		zfs_arc_overflow_shift = 8;

/* shift of arc_c for calculating both min and max arc_p */
static int		arc_p_min_shift = 4;

/* log2(fraction of arc to reclaim) */
static int		arc_shrink_shift = 7;

/*
 * log2(fraction of ARC which must be free to allow growing).
 * I.e. If there is less than arc_c >> arc_no_grow_shift free memory,
 * when reading a new block into the ARC, we will evict an equal-sized block
 * from the ARC.
 *
 * This must be less than arc_shrink_shift, so that when we shrink the ARC,
 * we will still not allow it to grow.
 */
int			arc_no_grow_shift = 5;


/*
 * minimum lifespan of a prefetch block in clock ticks
 * (initialized in arc_init())
 */
static int		arc_min_prefetch_lifespan;

/*
 * If this percent of memory is free, don't throttle.
 */
int arc_lotsfree_percent = 10;

static int arc_dead;

/*
 * The arc has filled available memory and has now warmed up.
 */
static boolean_t arc_warm;

/*
 * log2 fraction of the zio arena to keep free.
 */
int arc_zio_arena_free_shift = 2;

/*
 * These tunables are for performance analysis.
 */
uint64_t zfs_arc_max;
uint64_t zfs_arc_min;
uint64_t zfs_arc_meta_limit = 0;
uint64_t zfs_arc_meta_min = 0;
uint64_t zfs_arc_ddt_limit = 0;
/*
 * Tunable to control "dedup ceiling"
 * Possible values:
 *  DDT_NO_LIMIT	- default behaviour, ie no ceiling
 *  DDT_LIMIT_TO_ARC	- stop DDT growth if DDT is bigger than it's "ARC space"
 *  DDT_LIMIT_TO_L2ARC	- stop DDT growth when DDT size is bigger than the
 *			  L2ARC DDT dev(s) for that pool
 */
zfs_ddt_limit_t zfs_ddt_limit_type = DDT_LIMIT_TO_ARC;
/*
 * Alternative to the above way of controlling "dedup ceiling":
 * Stop DDT growth when in core DDTs size is above the below tunable.
 * This tunable overrides the zfs_ddt_limit_type tunable.
 */
uint64_t zfs_ddt_byte_ceiling = 0;
boolean_t zfs_arc_segregate_ddt = B_TRUE;
int zfs_arc_grow_retry = 0;
int zfs_arc_shrink_shift = 0;
int zfs_arc_p_min_shift = 0;
int zfs_arc_average_blocksize = 8 * 1024; /* 8KB */

/* Tuneable, default is 64, which is essentially arbitrary */
int zfs_flush_ntasks = 64;

boolean_t zfs_compressed_arc_enabled = B_TRUE;

/*
 * Note that buffers can be in one of 6 states:
 *	ARC_anon	- anonymous (discussed below)
 *	ARC_mru		- recently used, currently cached
 *	ARC_mru_ghost	- recentely used, no longer in cache
 *	ARC_mfu		- frequently used, currently cached
 *	ARC_mfu_ghost	- frequently used, no longer in cache
 *	ARC_l2c_only	- exists in L2ARC but not other states
 * When there are no active references to the buffer, they are
 * are linked onto a list in one of these arc states.  These are
 * the only buffers that can be evicted or deleted.  Within each
 * state there are multiple lists, one for meta-data and one for
 * non-meta-data.  Meta-data (indirect blocks, blocks of dnodes,
 * etc.) is tracked separately so that it can be managed more
 * explicitly: favored over data, limited explicitly.
 *
 * Anonymous buffers are buffers that are not associated with
 * a DVA.  These are buffers that hold dirty block copies
 * before they are written to stable storage.  By definition,
 * they are "ref'd" and are considered part of arc_mru
 * that cannot be freed.  Generally, they will aquire a DVA
 * as they are written and migrate onto the arc_mru list.
 *
 * The ARC_l2c_only state is for buffers that are in the second
 * level ARC but no longer in any of the ARC_m* lists.  The second
 * level ARC itself may also contain buffers that are in any of
 * the ARC_m* states - meaning that a buffer can exist in two
 * places.  The reason for the ARC_l2c_only state is to keep the
 * buffer header in the hash table, so that reads that hit the
 * second level ARC benefit from these fast lookups.
 */

typedef struct arc_state {
	/*
	 * list of evictable buffers
	 */
	multilist_t *arcs_list[ARC_BUFC_NUMTYPES];
	/*
	 * total amount of evictable data in this state
	 */
	refcount_t arcs_esize[ARC_BUFC_NUMTYPES];
	/*
	 * total amount of data in this state; this includes: evictable,
	 * non-evictable, ARC_BUFC_DATA, ARC_BUFC_METADATA and ARC_BUFC_DDT.
	 * ARC_BUFC_DDT list is only populated when zfs_arc_segregate_ddt is
	 * true.
	 */
	refcount_t arcs_size;
} arc_state_t;

/*
 * We loop through these in l2arc_write_buffers() starting from
 * PRIORITY_MFU_DDT until we reach PRIORITY_NUMTYPES or the buffer that we
 * will be writing to L2ARC dev gets full.
 */
enum l2arc_priorities {
	PRIORITY_MFU_DDT,
	PRIORITY_MRU_DDT,
	PRIORITY_MFU_META,
	PRIORITY_MRU_META,
	PRIORITY_MFU_DATA,
	PRIORITY_MRU_DATA,
	PRIORITY_NUMTYPES,
};

/* The 6 states: */
static arc_state_t ARC_anon;
static arc_state_t ARC_mru;
static arc_state_t ARC_mru_ghost;
static arc_state_t ARC_mfu;
static arc_state_t ARC_mfu_ghost;
static arc_state_t ARC_l2c_only;

typedef struct arc_stats {
	kstat_named_t arcstat_hits;
	kstat_named_t arcstat_ddt_hits;
	kstat_named_t arcstat_misses;
	kstat_named_t arcstat_demand_data_hits;
	kstat_named_t arcstat_demand_data_misses;
	kstat_named_t arcstat_demand_metadata_hits;
	kstat_named_t arcstat_demand_metadata_misses;
	kstat_named_t arcstat_demand_ddt_hits;
	kstat_named_t arcstat_demand_ddt_misses;
	kstat_named_t arcstat_prefetch_data_hits;
	kstat_named_t arcstat_prefetch_data_misses;
	kstat_named_t arcstat_prefetch_metadata_hits;
	kstat_named_t arcstat_prefetch_metadata_misses;
	kstat_named_t arcstat_prefetch_ddt_hits;
	kstat_named_t arcstat_prefetch_ddt_misses;
	kstat_named_t arcstat_mru_hits;
	kstat_named_t arcstat_mru_ghost_hits;
	kstat_named_t arcstat_mfu_hits;
	kstat_named_t arcstat_mfu_ghost_hits;
	kstat_named_t arcstat_deleted;
	/*
	 * Number of buffers that could not be evicted because the hash lock
	 * was held by another thread.  The lock may not necessarily be held
	 * by something using the same buffer, since hash locks are shared
	 * by multiple buffers.
	 */
	kstat_named_t arcstat_mutex_miss;
	/*
	 * Number of buffers skipped when updating the access state due to the
	 * header having already been released after acquiring the hash lock.
	 */
	kstat_named_t arcstat_access_skip;
	/*
	 * Number of buffers skipped because they have I/O in progress, are
	 * indirect prefetch buffers that have not lived long enough, or are
	 * not from the spa we're trying to evict from.
	 */
	kstat_named_t arcstat_evict_skip;
	/*
	 * Number of times arc_evict_state() was unable to evict enough
	 * buffers to reach it's target amount.
	 */
	kstat_named_t arcstat_evict_not_enough;
	kstat_named_t arcstat_evict_l2_cached;
	kstat_named_t arcstat_evict_l2_eligible;
	kstat_named_t arcstat_evict_l2_ineligible;
	kstat_named_t arcstat_evict_l2_skip;
	kstat_named_t arcstat_hash_elements;
	kstat_named_t arcstat_hash_elements_max;
	kstat_named_t arcstat_hash_collisions;
	kstat_named_t arcstat_hash_chains;
	kstat_named_t arcstat_hash_chain_max;
	kstat_named_t arcstat_p;
	kstat_named_t arcstat_c;
	kstat_named_t arcstat_c_min;
	kstat_named_t arcstat_c_max;
	/* Not updated directly; only synced in arc_kstat_update. */
	kstat_named_t arcstat_size;
	/*
	 * Number of compressed bytes stored in the arc_buf_hdr_t's b_pabd.
	 * Note that the compressed bytes may match the uncompressed bytes
	 * if the block is either not compressed or compressed arc is disabled.
	 */
	kstat_named_t arcstat_compressed_size;
	/*
	 * Uncompressed size of the data stored in b_pabd. If compressed
	 * arc is disabled then this value will be identical to the stat
	 * above.
	 */
	kstat_named_t arcstat_uncompressed_size;
	/*
	 * Number of bytes stored in all the arc_buf_t's. This is classified
	 * as "overhead" since this data is typically short-lived and will
	 * be evicted from the arc when it becomes unreferenced unless the
	 * zfs_keep_uncompressed_metadata or zfs_keep_uncompressed_level
	 * values have been set (see comment in dbuf.c for more information).
	 */
	kstat_named_t arcstat_overhead_size;
	/*
	 * Number of bytes consumed by internal ARC structures necessary
	 * for tracking purposes; these structures are not actually
	 * backed by ARC buffers. This includes arc_buf_hdr_t structures
	 * (allocated via arc_buf_hdr_t_full and arc_buf_hdr_t_l2only
	 * caches), and arc_buf_t structures (allocated via arc_buf_t
	 * cache).
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_hdr_size;
	/*
	 * Number of bytes consumed by ARC buffers of type equal to
	 * ARC_BUFC_DATA. This is generally consumed by buffers backing
	 * on disk user data (e.g. plain file contents).
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_data_size;
	/*
	 * Number of bytes consumed by ARC buffers of type equal to
	 * ARC_BUFC_METADATA. This is generally consumed by buffers
	 * backing on disk data that is used for internal ZFS
	 * structures (e.g. ZAP, dnode, indirect blocks, etc).
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_metadata_size;
	/*
	 * Number of bytes consumed by ARC buffers of type equal to
	 * ARC_BUFC_DDT. This is consumed by buffers backing on disk data
	 * that is used to store DDT (ZAP, ddt stats).
	 * Only used if zfs_arc_segregate_ddt is true.
	 */
	kstat_named_t arcstat_ddt_size;
	/*
	 * Number of bytes consumed by various buffers and structures
	 * not actually backed with ARC buffers. This includes bonus
	 * buffers (allocated directly via zio_buf_* functions),
	 * dmu_buf_impl_t structures (allocated via dmu_buf_impl_t
	 * cache), and dnode_t structures (allocated via dnode_t cache).
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_other_size;
	/*
	 * Total number of bytes consumed by ARC buffers residing in the
	 * arc_anon state. This includes *all* buffers in the arc_anon
	 * state; e.g. data, metadata, evictable, and unevictable buffers
	 * are all included in this value.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_anon_size;
	/*
	 * Number of bytes consumed by ARC buffers that meet the
	 * following criteria: backing buffers of type ARC_BUFC_DATA,
	 * residing in the arc_anon state, and are eligible for eviction
	 * (e.g. have no outstanding holds on the buffer).
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_anon_evictable_data;
	/*
	 * Number of bytes consumed by ARC buffers that meet the
	 * following criteria: backing buffers of type ARC_BUFC_METADATA,
	 * residing in the arc_anon state, and are eligible for eviction
	 * (e.g. have no outstanding holds on the buffer).
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_anon_evictable_metadata;
	/*
	 * Number of bytes consumed by ARC buffers that meet the
	 * following criteria: backing buffers of type ARC_BUFC_DDT,
	 * residing in the arc_anon state, and are eligible for eviction
	 * Only used if zfs_arc_segregate_ddt is true.
	 */
	kstat_named_t arcstat_anon_evictable_ddt;
	/*
	 * Total number of bytes consumed by ARC buffers residing in the
	 * arc_mru state. This includes *all* buffers in the arc_mru
	 * state; e.g. data, metadata, evictable, and unevictable buffers
	 * are all included in this value.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mru_size;
	/*
	 * Number of bytes consumed by ARC buffers that meet the
	 * following criteria: backing buffers of type ARC_BUFC_DATA,
	 * residing in the arc_mru state, and are eligible for eviction
	 * (e.g. have no outstanding holds on the buffer).
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mru_evictable_data;
	/*
	 * Number of bytes consumed by ARC buffers that meet the
	 * following criteria: backing buffers of type ARC_BUFC_METADATA,
	 * residing in the arc_mru state, and are eligible for eviction
	 * (e.g. have no outstanding holds on the buffer).
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mru_evictable_metadata;
	/*
	 * Number of bytes consumed by ARC buffers that meet the
	 * following criteria: backing buffers of type ARC_BUFC_DDT,
	 * residing in the arc_mru state, and are eligible for eviction
	 * (e.g. have no outstanding holds on the buffer).
	 * Only used if zfs_arc_segregate_ddt is true.
	 */
	kstat_named_t arcstat_mru_evictable_ddt;
	/*
	 * Total number of bytes that *would have been* consumed by ARC
	 * buffers in the arc_mru_ghost state. The key thing to note
	 * here, is the fact that this size doesn't actually indicate
	 * RAM consumption. The ghost lists only consist of headers and
	 * don't actually have ARC buffers linked off of these headers.
	 * Thus, *if* the headers had associated ARC buffers, these
	 * buffers *would have* consumed this number of bytes.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mru_ghost_size;
	/*
	 * Number of bytes that *would have been* consumed by ARC
	 * buffers that are eligible for eviction, of type
	 * ARC_BUFC_DATA, and linked off the arc_mru_ghost state.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mru_ghost_evictable_data;
	/*
	 * Number of bytes that *would have been* consumed by ARC
	 * buffers that are eligible for eviction, of type
	 * ARC_BUFC_METADATA, and linked off the arc_mru_ghost state.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mru_ghost_evictable_metadata;
	/*
	 * Number of bytes that *would have been* consumed by ARC
	 * buffers that are eligible for eviction, of type
	 * ARC_BUFC_DDT, and linked off the arc_mru_ghost state.
	 * Only used if zfs_arc_segregate_ddt is true.
	 */
	kstat_named_t arcstat_mru_ghost_evictable_ddt;
	/*
	 * Total number of bytes consumed by ARC buffers residing in the
	 * arc_mfu state. This includes *all* buffers in the arc_mfu
	 * state; e.g. data, metadata, evictable, and unevictable buffers
	 * are all included in this value.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mfu_size;
	/*
	 * Number of bytes consumed by ARC buffers that are eligible for
	 * eviction, of type ARC_BUFC_DATA, and reside in the arc_mfu
	 * state.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mfu_evictable_data;
	/*
	 * Number of bytes consumed by ARC buffers that are eligible for
	 * eviction, of type ARC_BUFC_METADATA, and reside in the
	 * arc_mfu state.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mfu_evictable_metadata;
	/*
	 * Number of bytes consumed by ARC buffers that are eligible for
	 * eviction, of type ARC_BUFC_DDT, and reside in the
	 * arc_mfu state.
	 * Only used if zfs_arc_segregate_ddt is true.
	 */
	kstat_named_t arcstat_mfu_evictable_ddt;
	/*
	 * Total number of bytes that *would have been* consumed by ARC
	 * buffers in the arc_mfu_ghost state. See the comment above
	 * arcstat_mru_ghost_size for more details.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mfu_ghost_size;
	/*
	 * Number of bytes that *would have been* consumed by ARC
	 * buffers that are eligible for eviction, of type
	 * ARC_BUFC_DATA, and linked off the arc_mfu_ghost state.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mfu_ghost_evictable_data;
	/*
	 * Number of bytes that *would have been* consumed by ARC
	 * buffers that are eligible for eviction, of type
	 * ARC_BUFC_METADATA, and linked off the arc_mru_ghost state.
	 * Not updated directly; only synced in arc_kstat_update.
	 */
	kstat_named_t arcstat_mfu_ghost_evictable_metadata;
	/*
	 * Number of bytes that *would have been* consumed by ARC
	 * buffers that are eligible for eviction, of type
	 * ARC_BUFC_DDT, and linked off the arc_mru_ghost state.
	 * Only used if zfs_arc_segregate_ddt is true.
	 */
	kstat_named_t arcstat_mfu_ghost_evictable_ddt;
	kstat_named_t arcstat_l2_hits;
	kstat_named_t arcstat_l2_ddt_hits;
	kstat_named_t arcstat_l2_misses;
	kstat_named_t arcstat_l2_feeds;
	kstat_named_t arcstat_l2_rw_clash;
	kstat_named_t arcstat_l2_read_bytes;
	kstat_named_t arcstat_l2_ddt_read_bytes;
	kstat_named_t arcstat_l2_write_bytes;
	kstat_named_t arcstat_l2_ddt_write_bytes;
	kstat_named_t arcstat_l2_writes_sent;
	kstat_named_t arcstat_l2_writes_done;
	kstat_named_t arcstat_l2_writes_error;
	kstat_named_t arcstat_l2_writes_lock_retry;
	kstat_named_t arcstat_l2_evict_lock_retry;
	kstat_named_t arcstat_l2_evict_reading;
	kstat_named_t arcstat_l2_evict_l1cached;
	kstat_named_t arcstat_l2_free_on_write;
	kstat_named_t arcstat_l2_abort_lowmem;
	kstat_named_t arcstat_l2_cksum_bad;
	kstat_named_t arcstat_l2_io_error;
	kstat_named_t arcstat_l2_lsize;
	kstat_named_t arcstat_l2_psize;
	/* Not updated directly; only synced in arc_kstat_update. */
	kstat_named_t arcstat_l2_hdr_size;
	kstat_named_t arcstat_l2_log_blk_writes;
	kstat_named_t arcstat_l2_log_blk_avg_size;
	kstat_named_t arcstat_l2_data_to_meta_ratio;
	kstat_named_t arcstat_l2_rebuild_successes;
	kstat_named_t arcstat_l2_rebuild_abort_unsupported;
	kstat_named_t arcstat_l2_rebuild_abort_io_errors;
	kstat_named_t arcstat_l2_rebuild_abort_cksum_errors;
	kstat_named_t arcstat_l2_rebuild_abort_loop_errors;
	kstat_named_t arcstat_l2_rebuild_abort_lowmem;
	kstat_named_t arcstat_l2_rebuild_size;
	kstat_named_t arcstat_l2_rebuild_bufs;
	kstat_named_t arcstat_l2_rebuild_bufs_precached;
	kstat_named_t arcstat_l2_rebuild_psize;
	kstat_named_t arcstat_l2_rebuild_log_blks;
	kstat_named_t arcstat_memory_throttle_count;
	/* Not updated directly; only synced in arc_kstat_update. */
	kstat_named_t arcstat_meta_used;
	kstat_named_t arcstat_meta_limit;
	kstat_named_t arcstat_meta_max;
	kstat_named_t arcstat_meta_min;
	kstat_named_t arcstat_ddt_limit;
	kstat_named_t arcstat_sync_wait_for_async;
	kstat_named_t arcstat_demand_hit_predictive_prefetch;
} arc_stats_t;

static arc_stats_t arc_stats = {
	{ "hits",			KSTAT_DATA_UINT64 },
	{ "ddt_hits",			KSTAT_DATA_UINT64 },
	{ "misses",			KSTAT_DATA_UINT64 },
	{ "demand_data_hits",		KSTAT_DATA_UINT64 },
	{ "demand_data_misses",		KSTAT_DATA_UINT64 },
	{ "demand_metadata_hits",	KSTAT_DATA_UINT64 },
	{ "demand_metadata_misses",	KSTAT_DATA_UINT64 },
	{ "demand_ddt_hits",		KSTAT_DATA_UINT64 },
	{ "demand_ddt_misses",		KSTAT_DATA_UINT64 },
	{ "prefetch_data_hits",		KSTAT_DATA_UINT64 },
	{ "prefetch_data_misses",	KSTAT_DATA_UINT64 },
	{ "prefetch_metadata_hits",	KSTAT_DATA_UINT64 },
	{ "prefetch_metadata_misses",	KSTAT_DATA_UINT64 },
	{ "prefetch_ddt_hits",		KSTAT_DATA_UINT64 },
	{ "prefetch_ddt_misses",	KSTAT_DATA_UINT64 },
	{ "mru_hits",			KSTAT_DATA_UINT64 },
	{ "mru_ghost_hits",		KSTAT_DATA_UINT64 },
	{ "mfu_hits",			KSTAT_DATA_UINT64 },
	{ "mfu_ghost_hits",		KSTAT_DATA_UINT64 },
	{ "deleted",			KSTAT_DATA_UINT64 },
	{ "mutex_miss",			KSTAT_DATA_UINT64 },
	{ "access_skip",		KSTAT_DATA_UINT64 },
	{ "evict_skip",			KSTAT_DATA_UINT64 },
	{ "evict_not_enough",		KSTAT_DATA_UINT64 },
	{ "evict_l2_cached",		KSTAT_DATA_UINT64 },
	{ "evict_l2_eligible",		KSTAT_DATA_UINT64 },
	{ "evict_l2_ineligible",	KSTAT_DATA_UINT64 },
	{ "evict_l2_skip",		KSTAT_DATA_UINT64 },
	{ "hash_elements",		KSTAT_DATA_UINT64 },
	{ "hash_elements_max",		KSTAT_DATA_UINT64 },
	{ "hash_collisions",		KSTAT_DATA_UINT64 },
	{ "hash_chains",		KSTAT_DATA_UINT64 },
	{ "hash_chain_max",		KSTAT_DATA_UINT64 },
	{ "p",				KSTAT_DATA_UINT64 },
	{ "c",				KSTAT_DATA_UINT64 },
	{ "c_min",			KSTAT_DATA_UINT64 },
	{ "c_max",			KSTAT_DATA_UINT64 },
	{ "size",			KSTAT_DATA_UINT64 },
	{ "compressed_size",		KSTAT_DATA_UINT64 },
	{ "uncompressed_size",		KSTAT_DATA_UINT64 },
	{ "overhead_size",		KSTAT_DATA_UINT64 },
	{ "hdr_size",			KSTAT_DATA_UINT64 },
	{ "data_size",			KSTAT_DATA_UINT64 },
	{ "metadata_size",		KSTAT_DATA_UINT64 },
	{ "ddt_size",			KSTAT_DATA_UINT64 },
	{ "other_size",			KSTAT_DATA_UINT64 },
	{ "anon_size",			KSTAT_DATA_UINT64 },
	{ "anon_evictable_data",	KSTAT_DATA_UINT64 },
	{ "anon_evictable_metadata",	KSTAT_DATA_UINT64 },
	{ "anon_evictable_ddt",		KSTAT_DATA_UINT64 },
	{ "mru_size",			KSTAT_DATA_UINT64 },
	{ "mru_evictable_data",		KSTAT_DATA_UINT64 },
	{ "mru_evictable_metadata",	KSTAT_DATA_UINT64 },
	{ "mru_evictable_ddt",		KSTAT_DATA_UINT64 },
	{ "mru_ghost_size",		KSTAT_DATA_UINT64 },
	{ "mru_ghost_evictable_data",	KSTAT_DATA_UINT64 },
	{ "mru_ghost_evictable_metadata", KSTAT_DATA_UINT64 },
	{ "mru_ghost_evictable_ddt",	KSTAT_DATA_UINT64 },
	{ "mfu_size",			KSTAT_DATA_UINT64 },
	{ "mfu_evictable_data",		KSTAT_DATA_UINT64 },
	{ "mfu_evictable_metadata",	KSTAT_DATA_UINT64 },
	{ "mfu_evictable_ddt",		KSTAT_DATA_UINT64 },
	{ "mfu_ghost_size",		KSTAT_DATA_UINT64 },
	{ "mfu_ghost_evictable_data",	KSTAT_DATA_UINT64 },
	{ "mfu_ghost_evictable_metadata", KSTAT_DATA_UINT64 },
	{ "mfu_ghost_evictable_ddt",	KSTAT_DATA_UINT64 },
	{ "l2_hits",			KSTAT_DATA_UINT64 },
	{ "l2_ddt_hits",		KSTAT_DATA_UINT64 },
	{ "l2_misses",			KSTAT_DATA_UINT64 },
	{ "l2_feeds",			KSTAT_DATA_UINT64 },
	{ "l2_rw_clash",		KSTAT_DATA_UINT64 },
	{ "l2_read_bytes",		KSTAT_DATA_UINT64 },
	{ "l2_ddt_read_bytes",		KSTAT_DATA_UINT64 },
	{ "l2_write_bytes",		KSTAT_DATA_UINT64 },
	{ "l2_ddt_write_bytes",		KSTAT_DATA_UINT64 },
	{ "l2_writes_sent",		KSTAT_DATA_UINT64 },
	{ "l2_writes_done",		KSTAT_DATA_UINT64 },
	{ "l2_writes_error",		KSTAT_DATA_UINT64 },
	{ "l2_writes_lock_retry",	KSTAT_DATA_UINT64 },
	{ "l2_evict_lock_retry",	KSTAT_DATA_UINT64 },
	{ "l2_evict_reading",		KSTAT_DATA_UINT64 },
	{ "l2_evict_l1cached",		KSTAT_DATA_UINT64 },
	{ "l2_free_on_write",		KSTAT_DATA_UINT64 },
	{ "l2_abort_lowmem",		KSTAT_DATA_UINT64 },
	{ "l2_cksum_bad",		KSTAT_DATA_UINT64 },
	{ "l2_io_error",		KSTAT_DATA_UINT64 },
	{ "l2_size",			KSTAT_DATA_UINT64 },
	{ "l2_asize",			KSTAT_DATA_UINT64 },
	{ "l2_hdr_size",		KSTAT_DATA_UINT64 },
	{ "l2_log_blk_writes",		KSTAT_DATA_UINT64 },
	{ "l2_log_blk_avg_size",	KSTAT_DATA_UINT64 },
	{ "l2_data_to_meta_ratio",	KSTAT_DATA_UINT64 },
	{ "l2_rebuild_successes",	KSTAT_DATA_UINT64 },
	{ "l2_rebuild_unsupported",	KSTAT_DATA_UINT64 },
	{ "l2_rebuild_io_errors",	KSTAT_DATA_UINT64 },
	{ "l2_rebuild_cksum_errors",	KSTAT_DATA_UINT64 },
	{ "l2_rebuild_loop_errors",	KSTAT_DATA_UINT64 },
	{ "l2_rebuild_lowmem",		KSTAT_DATA_UINT64 },
	{ "l2_rebuild_size",		KSTAT_DATA_UINT64 },
	{ "l2_rebuild_bufs",		KSTAT_DATA_UINT64 },
	{ "l2_rebuild_bufs_precached",	KSTAT_DATA_UINT64 },
	{ "l2_rebuild_psize",		KSTAT_DATA_UINT64 },
	{ "l2_rebuild_log_blks",	KSTAT_DATA_UINT64 },
	{ "memory_throttle_count",	KSTAT_DATA_UINT64 },
	{ "arc_meta_used",		KSTAT_DATA_UINT64 },
	{ "arc_meta_limit",		KSTAT_DATA_UINT64 },
	{ "arc_meta_max",		KSTAT_DATA_UINT64 },
	{ "arc_meta_min",		KSTAT_DATA_UINT64 },
	{ "arc_ddt_limit",		KSTAT_DATA_UINT64 },
	{ "sync_wait_for_async",	KSTAT_DATA_UINT64 },
	{ "demand_hit_predictive_prefetch", KSTAT_DATA_UINT64 },
};

#define	ARCSTAT(stat)	(arc_stats.stat.value.ui64)

#define	ARCSTAT_INCR(stat, val) \
	atomic_add_64(&arc_stats.stat.value.ui64, (val))

#define	ARCSTAT_BUMP(stat)	ARCSTAT_INCR(stat, 1)
#define	ARCSTAT_BUMPDOWN(stat)	ARCSTAT_INCR(stat, -1)

#define	ARCSTAT_MAX(stat, val) {					\
	uint64_t m;							\
	while ((val) > (m = arc_stats.stat.value.ui64) &&		\
	    (m != atomic_cas_64(&arc_stats.stat.value.ui64, m, (val))))	\
		continue;						\
}

#define	ARCSTAT_MAXSTAT(stat) \
	ARCSTAT_MAX(stat##_max, arc_stats.stat.value.ui64)

/*
 * We define a macro to allow ARC hits/misses to be easily broken down by
 * two separate conditions, giving a total of four different subtypes for
 * each of hits and misses (so eight statistics total).
 */
#define	ARCSTAT_CONDSTAT(cond1, stat1, notstat1, cond2, stat2, notstat2, stat) \
	if (cond1) {							\
		if (cond2) {						\
			ARCSTAT_BUMP(arcstat_##stat1##_##stat##_##stat2); \
		} else {						\
			ARCSTAT_BUMP(arcstat_##stat1##_##stat##_##notstat2); \
		}							\
	} else {							\
		if (cond2) {						\
			ARCSTAT_BUMP(arcstat_##notstat1##_##stat##_##stat2); \
		} else {						\
			ARCSTAT_BUMP(arcstat_##notstat1##_##stat##_##notstat2);\
		}							\
	}

/*
 * This macro allows us to use kstats as floating averages. Each time we
 * update this kstat, we first factor it and the update value by
 * ARCSTAT_AVG_FACTOR to shrink the new value's contribution to the overall
 * average. This macro assumes that integer loads and stores are atomic, but
 * is not safe for multiple writers updating the kstat in parallel (only the
 * last writer's update will remain).
 */
#define	ARCSTAT_F_AVG_FACTOR	3
#define	ARCSTAT_F_AVG(stat, value) \
	do { \
		uint64_t x = ARCSTAT(stat); \
		x = x - x / ARCSTAT_F_AVG_FACTOR + \
		    (value) / ARCSTAT_F_AVG_FACTOR; \
		ARCSTAT(stat) = x; \
		_NOTE(CONSTCOND) \
	} while (0)

kstat_t			*arc_ksp;
static arc_state_t	*arc_anon;
static arc_state_t	*arc_mru;
static arc_state_t	*arc_mru_ghost;
static arc_state_t	*arc_mfu;
static arc_state_t	*arc_mfu_ghost;
static arc_state_t	*arc_l2c_only;

/*
 * There are several ARC variables that are critical to export as kstats --
 * but we don't want to have to grovel around in the kstat whenever we wish to
 * manipulate them.  For these variables, we therefore define them to be in
 * terms of the statistic variable.  This assures that we are not introducing
 * the possibility of inconsistency by having shadow copies of the variables,
 * while still allowing the code to be readable.
 */
#define	arc_p		ARCSTAT(arcstat_p)	/* target size of MRU */
#define	arc_c		ARCSTAT(arcstat_c)	/* target size of cache */
#define	arc_c_min	ARCSTAT(arcstat_c_min)	/* min target cache size */
#define	arc_c_max	ARCSTAT(arcstat_c_max)	/* max target cache size */
#define	arc_meta_limit	ARCSTAT(arcstat_meta_limit) /* max size for metadata */
#define	arc_meta_min	ARCSTAT(arcstat_meta_min) /* min size for metadata */
#define	arc_meta_max	ARCSTAT(arcstat_meta_max) /* max size of metadata */
#define	arc_ddt_limit	ARCSTAT(arcstat_ddt_limit) /* ddt in arc size limit */

/*
 * Used int zio.c to optionally keep DDT cached in ARC
 */
uint64_t const *arc_ddt_evict_threshold;

/* compressed size of entire arc */
#define	arc_compressed_size	ARCSTAT(arcstat_compressed_size)
/* uncompressed size of entire arc */
#define	arc_uncompressed_size	ARCSTAT(arcstat_uncompressed_size)
/* number of bytes in the arc from arc_buf_t's */
#define	arc_overhead_size	ARCSTAT(arcstat_overhead_size)

/*
 * There are also some ARC variables that we want to export, but that are
 * updated so often that having the canonical representation be the statistic
 * variable causes a performance bottleneck. We want to use aggsum_t's for these
 * instead, but still be able to export the kstat in the same way as before.
 * The solution is to always use the aggsum version, except in the kstat update
 * callback.
 */
aggsum_t arc_size;
aggsum_t arc_meta_used;
aggsum_t astat_data_size;
aggsum_t astat_metadata_size;
aggsum_t astat_ddt_size;
aggsum_t astat_hdr_size;
aggsum_t astat_other_size;
aggsum_t astat_l2_hdr_size;

static int		arc_no_grow;	/* Don't try to grow cache size */
static uint64_t		arc_tempreserve;
static uint64_t		arc_loaned_bytes;

typedef struct arc_callback arc_callback_t;

struct arc_callback {
	void			*acb_private;
	arc_done_func_t		*acb_done;
	arc_buf_t		*acb_buf;
	boolean_t		acb_compressed;
	zio_t			*acb_zio_dummy;
	arc_callback_t		*acb_next;
};

typedef struct arc_write_callback arc_write_callback_t;

struct arc_write_callback {
	void		*awcb_private;
	arc_done_func_t	*awcb_ready;
	arc_done_func_t	*awcb_children_ready;
	arc_done_func_t	*awcb_physdone;
	arc_done_func_t	*awcb_done;
	arc_buf_t	*awcb_buf;
};

/*
 * ARC buffers are separated into multiple structs as a memory saving measure:
 *   - Common fields struct, always defined, and embedded within it:
 *       - L2-only fields, always allocated but undefined when not in L2ARC
 *       - L1-only fields, only allocated when in L1ARC
 *
 *           Buffer in L1                     Buffer only in L2
 *    +------------------------+          +------------------------+
 *    | arc_buf_hdr_t          |          | arc_buf_hdr_t          |
 *    |                        |          |                        |
 *    |                        |          |                        |
 *    |                        |          |                        |
 *    +------------------------+          +------------------------+
 *    | l2arc_buf_hdr_t        |          | l2arc_buf_hdr_t        |
 *    | (undefined if L1-only) |          |                        |
 *    +------------------------+          +------------------------+
 *    | l1arc_buf_hdr_t        |
 *    |                        |
 *    |                        |
 *    |                        |
 *    |                        |
 *    +------------------------+
 *
 * Because it's possible for the L2ARC to become extremely large, we can wind
 * up eating a lot of memory in L2ARC buffer headers, so the size of a header
 * is minimized by only allocating the fields necessary for an L1-cached buffer
 * when a header is actually in the L1 cache. The sub-headers (l1arc_buf_hdr and
 * l2arc_buf_hdr) are embedded rather than allocated separately to save a couple
 * words in pointers. arc_hdr_realloc() is used to switch a header between
 * these two allocation states.
 */
typedef struct l1arc_buf_hdr {
	kmutex_t		b_freeze_lock;
#ifdef ZFS_DEBUG
	/*
	 * Used for debugging with kmem_flags - by allocating and freeing
	 * b_thawed when the buffer is thawed, we get a record of the stack
	 * trace that thawed it.
	 */
	void			*b_thawed;
#endif

	/* number of short-holds using this buffer */
	uint64_t		b_short_holders;

	arc_buf_t		*b_buf;
	uint32_t		b_bufcnt;
	/* for waiting on writes to complete */
	kcondvar_t		b_cv;
	uint8_t			b_byteswap;

	/* protected by arc state mutex */
	arc_state_t		*b_state;
	multilist_node_t	b_arc_node;

	/* updated atomically */
	clock_t			b_arc_access;

	/* self protecting */
	refcount_t		b_refcnt;

	arc_callback_t		*b_acb;
	abd_t			*b_pabd;
} l1arc_buf_hdr_t;

typedef struct l2arc_dev l2arc_dev_t;

typedef struct l2arc_buf_hdr {
	/* protected by arc_buf_hdr mutex */
	l2arc_dev_t		*b_dev;		/* L2ARC device */
	uint64_t		b_daddr;	/* disk address, offset byte */

	list_node_t		b_l2node;
} l2arc_buf_hdr_t;

struct arc_buf_hdr {
	/* protected by hash lock */
	dva_t			b_dva;
	uint64_t		b_birth;

	/*
	 * Even though this checksum is only set/verified when a buffer is in
	 * the L1 cache, it needs to be in the set of common fields because it
	 * must be preserved from the time before a buffer is written out to
	 * L2ARC until after it is read back in.
	 */
	zio_cksum_t		*b_freeze_cksum;

	arc_buf_contents_t	b_type;
	arc_buf_hdr_t		*b_hash_next;
	arc_flags_t		b_flags;

	/*
	 * This field stores the size of the data buffer after
	 * compression, and is set in the arc's zio completion handlers.
	 * It is in units of SPA_MINBLOCKSIZE (e.g. 1 == 512 bytes).
	 *
	 * While the block pointers can store up to 32MB in their psize
	 * field, we can only store up to 32MB minus 512B. This is due
	 * to the bp using a bias of 1, whereas we use a bias of 0 (i.e.
	 * a field of zeros represents 512B in the bp). We can't use a
	 * bias of 1 since we need to reserve a psize of zero, here, to
	 * represent holes and embedded blocks.
	 *
	 * This isn't a problem in practice, since the maximum size of a
	 * buffer is limited to 16MB, so we never need to store 32MB in
	 * this field. Even in the upstream illumos code base, the
	 * maximum size of a buffer is limited to 16MB.
	 */
	uint16_t		b_psize;

	/*
	 * This field stores the size of the data buffer before
	 * compression, and cannot change once set. It is in units
	 * of SPA_MINBLOCKSIZE (e.g. 2 == 1024 bytes)
	 */
	uint16_t		b_lsize;	/* immutable */
	uint64_t		b_spa;		/* immutable */

	/* L2ARC fields. Undefined when not in L2ARC. */
	l2arc_buf_hdr_t		b_l2hdr;
	/* L1ARC fields. Undefined when in l2arc_only state */
	l1arc_buf_hdr_t		b_l1hdr;
};

#define	GHOST_STATE(state)	\
	((state) == arc_mru_ghost || (state) == arc_mfu_ghost ||	\
	(state) == arc_l2c_only)

#define	HDR_IN_HASH_TABLE(hdr)	((hdr)->b_flags & ARC_FLAG_IN_HASH_TABLE)
#define	HDR_IO_IN_PROGRESS(hdr)	((hdr)->b_flags & ARC_FLAG_IO_IN_PROGRESS)
#define	HDR_IO_ERROR(hdr)	((hdr)->b_flags & ARC_FLAG_IO_ERROR)
#define	HDR_PREFETCH(hdr)	((hdr)->b_flags & ARC_FLAG_PREFETCH)
#define	HDR_COMPRESSION_ENABLED(hdr)	\
	((hdr)->b_flags & ARC_FLAG_COMPRESSED_ARC)

#define	HDR_L2CACHE(hdr)	((hdr)->b_flags & ARC_FLAG_L2CACHE)
#define	HDR_L2_READING(hdr)	\
	(((hdr)->b_flags & ARC_FLAG_IO_IN_PROGRESS) &&	\
	((hdr)->b_flags & ARC_FLAG_HAS_L2HDR))
#define	HDR_L2_WRITING(hdr)	((hdr)->b_flags & ARC_FLAG_L2_WRITING)
#define	HDR_L2_EVICTED(hdr)	((hdr)->b_flags & ARC_FLAG_L2_EVICTED)
#define	HDR_L2_WRITE_HEAD(hdr)	((hdr)->b_flags & ARC_FLAG_L2_WRITE_HEAD)
#define	HDR_SHARED_DATA(hdr)	((hdr)->b_flags & ARC_FLAG_SHARED_DATA)

#define	HDR_ISTYPE_DDT(hdr)	\
	    ((hdr)->b_flags & ARC_FLAG_BUFC_DDT)
#define	HDR_ISTYPE_METADATA(hdr)	\
	((hdr)->b_flags & ARC_FLAG_BUFC_METADATA)
#define	HDR_ISTYPE_DATA(hdr)	(!HDR_ISTYPE_METADATA(hdr) && \
	!HDR_ISTYPE_DDT(hdr))

#define	HDR_HAS_L1HDR(hdr)	((hdr)->b_flags & ARC_FLAG_HAS_L1HDR)
#define	HDR_HAS_L2HDR(hdr)	((hdr)->b_flags & ARC_FLAG_HAS_L2HDR)

/* For storing compression mode in b_flags */
#define	HDR_COMPRESS_OFFSET	(highbit64(ARC_FLAG_COMPRESS_0) - 1)

#define	HDR_GET_COMPRESS(hdr)	((enum zio_compress)BF32_GET((hdr)->b_flags, \
	HDR_COMPRESS_OFFSET, SPA_COMPRESSBITS))
#define	HDR_SET_COMPRESS(hdr, cmp) BF32_SET((hdr)->b_flags, \
	HDR_COMPRESS_OFFSET, SPA_COMPRESSBITS, (cmp));

#define	ARC_BUF_LAST(buf)	((buf)->b_next == NULL)
#define	ARC_BUF_SHARED(buf)	((buf)->b_flags & ARC_BUF_FLAG_SHARED)
#define	ARC_BUF_COMPRESSED(buf)	((buf)->b_flags & ARC_BUF_FLAG_COMPRESSED)

/*
 * Other sizes
 */

#define	HDR_FULL_SIZE ((int64_t)sizeof (arc_buf_hdr_t))
#define	HDR_L2ONLY_SIZE ((int64_t)offsetof(arc_buf_hdr_t, b_l1hdr))

/*
 * Hash table routines
 */

struct ht_table {
	arc_buf_hdr_t	*hdr;
	kmutex_t	lock;
};

typedef struct buf_hash_table {
	uint64_t ht_mask;
	struct ht_table *ht_table;
} buf_hash_table_t;

#pragma align 64(buf_hash_table)
static buf_hash_table_t buf_hash_table;

#define	BUF_HASH_INDEX(spa, dva, birth) \
	(buf_hash(spa, dva, birth) & buf_hash_table.ht_mask)
#define	BUF_HASH_LOCK(idx) (&buf_hash_table.ht_table[idx].lock)
#define	HDR_LOCK(hdr) \
	(BUF_HASH_LOCK(BUF_HASH_INDEX(hdr->b_spa, &hdr->b_dva, hdr->b_birth)))

uint64_t zfs_crc64_table[256];

/*
 * Level 2 ARC
 */

#define	L2ARC_WRITE_SIZE	(8 * 1024 * 1024)	/* initial write max */
#define	L2ARC_HEADROOM		2			/* num of writes */
/*
 * If we discover during ARC scan any buffers to be compressed, we boost
 * our headroom for the next scanning cycle by this percentage multiple.
 */
#define	L2ARC_HEADROOM_BOOST	200
#define	L2ARC_FEED_SECS		1		/* caching interval secs */
#define	L2ARC_FEED_MIN_MS	200		/* min caching interval ms */

#define	l2arc_writes_sent	ARCSTAT(arcstat_l2_writes_sent)
#define	l2arc_writes_done	ARCSTAT(arcstat_l2_writes_done)

/* L2ARC Performance Tunables */
uint64_t l2arc_write_max = L2ARC_WRITE_SIZE;	/* default max write size */
uint64_t l2arc_write_boost = L2ARC_WRITE_SIZE;	/* extra write during warmup */
uint64_t l2arc_headroom = L2ARC_HEADROOM;	/* number of dev writes */
uint64_t l2arc_headroom_boost = L2ARC_HEADROOM_BOOST;
uint64_t l2arc_feed_secs = L2ARC_FEED_SECS;	/* interval seconds */
uint64_t l2arc_feed_min_ms = L2ARC_FEED_MIN_MS;	/* min interval milliseconds */
boolean_t l2arc_noprefetch = B_TRUE;		/* don't cache prefetch bufs */
boolean_t l2arc_feed_again = B_TRUE;		/* turbo warmup */
boolean_t l2arc_norw = B_TRUE;			/* no reads during writes */

static list_t L2ARC_dev_list;			/* device list */
static list_t *l2arc_dev_list;			/* device list pointer */
static kmutex_t l2arc_dev_mtx;			/* device list mutex */
static l2arc_dev_t *l2arc_dev_last;		/* last device used */
static l2arc_dev_t *l2arc_ddt_dev_last;		/* last DDT device used */
static list_t L2ARC_free_on_write;		/* free after write buf list */
static list_t *l2arc_free_on_write;		/* free after write list ptr */
static kmutex_t l2arc_free_on_write_mtx;	/* mutex for list */
static uint64_t l2arc_ndev;			/* number of devices */

typedef struct l2arc_read_callback {
	arc_buf_hdr_t		*l2rcb_hdr;		/* read header */
	blkptr_t		l2rcb_bp;		/* original blkptr */
	zbookmark_phys_t	l2rcb_zb;		/* original bookmark */
	int			l2rcb_flags;		/* original flags */
	abd_t			*l2rcb_abd;		/* temporary buffer */
} l2arc_read_callback_t;

typedef struct l2arc_write_callback {
	l2arc_dev_t	*l2wcb_dev;		/* device info */
	arc_buf_hdr_t	*l2wcb_head;		/* head of write buflist */
	list_t		l2wcb_log_blk_buflist;	/* in-flight log blocks */
} l2arc_write_callback_t;

typedef struct l2arc_data_free {
	/* protected by l2arc_free_on_write_mtx */
	abd_t		*l2df_abd;
	size_t		l2df_size;
	arc_buf_contents_t l2df_type;
	list_node_t	l2df_list_node;
} l2arc_data_free_t;

static kmutex_t l2arc_feed_thr_lock;
static kcondvar_t l2arc_feed_thr_cv;
static uint8_t l2arc_thread_exit;

static abd_t *arc_get_data_abd(arc_buf_hdr_t *, uint64_t, void *);
static void *arc_get_data_buf(arc_buf_hdr_t *, uint64_t, void *);
static void arc_get_data_impl(arc_buf_hdr_t *, uint64_t, void *);
static void arc_free_data_abd(arc_buf_hdr_t *, abd_t *, uint64_t, void *);
static void arc_free_data_buf(arc_buf_hdr_t *, void *, uint64_t, void *);
static void arc_free_data_impl(arc_buf_hdr_t *hdr, uint64_t size, void *tag);
static void arc_hdr_free_pabd(arc_buf_hdr_t *);
static void arc_hdr_alloc_pabd(arc_buf_hdr_t *);
static void arc_access(arc_buf_hdr_t *, kmutex_t *);
static boolean_t arc_is_overflowing();
static void arc_buf_watch(arc_buf_t *);
static l2arc_dev_t *l2arc_vdev_get(vdev_t *vd);

static arc_buf_contents_t arc_buf_type(arc_buf_hdr_t *);
static uint32_t arc_bufc_to_flags(arc_buf_contents_t);
static arc_buf_contents_t arc_flags_to_bufc(uint32_t);
static inline void arc_hdr_set_flags(arc_buf_hdr_t *hdr, arc_flags_t flags);
static inline void arc_hdr_clear_flags(arc_buf_hdr_t *hdr, arc_flags_t flags);

static boolean_t l2arc_write_eligible(uint64_t, arc_buf_hdr_t *);
static void l2arc_read_done(zio_t *);

static void
arc_update_hit_stat(arc_buf_hdr_t *hdr, boolean_t hit)
{
	boolean_t pf = !HDR_PREFETCH(hdr);
	switch (arc_buf_type(hdr)) {
	case ARC_BUFC_DATA:
		ARCSTAT_CONDSTAT(pf, demand, prefetch,
		    hit, hits, misses, data);
		break;
	case ARC_BUFC_METADATA:
		ARCSTAT_CONDSTAT(pf, demand, prefetch,
		    hit, hits, misses, metadata);
		break;
	case ARC_BUFC_DDT:
		ARCSTAT_CONDSTAT(pf, demand, prefetch,
		    hit, hits, misses, ddt);
		break;
	default:
		break;
	}
}

enum {
	L2ARC_DEV_HDR_EVICT_FIRST = (1 << 0)	/* mirror of l2ad_first */
};

/*
 * Pointer used in persistent L2ARC (for pointing to log blocks & ARC buffers).
 */
typedef struct l2arc_log_blkptr {
	uint64_t	lbp_daddr;	/* device address of log */
	/*
	 * lbp_prop is the same format as the blk_prop in blkptr_t:
	 *	* logical size (in sectors)
	 *	* physical size (in sectors)
	 *	* checksum algorithm (used for lbp_cksum)
	 *	* object type & level (unused for now)
	 */
	uint64_t	lbp_prop;
	zio_cksum_t	lbp_cksum;	/* fletcher4 of log */
} l2arc_log_blkptr_t;

/*
 * The persistent L2ARC device header.
 * Byte order of magic determines whether 64-bit bswap of fields is necessary.
 */
typedef struct l2arc_dev_hdr_phys {
	uint64_t	dh_magic;	/* L2ARC_DEV_HDR_MAGIC_Vx */
	zio_cksum_t	dh_self_cksum;	/* fletcher4 of fields below */

	/*
	 * Global L2ARC device state and metadata.
	 */
	uint64_t	dh_spa_guid;
	uint64_t	dh_alloc_space;		/* vdev space alloc status */
	uint64_t	dh_flags;		/* l2arc_dev_hdr_flags_t */

	/*
	 * Start of log block chain. [0] -> newest log, [1] -> one older (used
	 * for initiating prefetch).
	 */
	l2arc_log_blkptr_t	dh_start_lbps[2];

	const uint64_t	dh_pad[44];		/* pad to 512 bytes */
} l2arc_dev_hdr_phys_t;
CTASSERT(sizeof (l2arc_dev_hdr_phys_t) == SPA_MINBLOCKSIZE);

/*
 * A single ARC buffer header entry in a l2arc_log_blk_phys_t.
 */
typedef struct l2arc_log_ent_phys {
	dva_t			le_dva;	/* dva of buffer */
	uint64_t		le_birth;	/* birth txg of buffer */
	zio_cksum_t		le_freeze_cksum;
	/*
	 * le_prop is the same format as the blk_prop in blkptr_t:
	 *	* logical size (in sectors)
	 *	* physical size (in sectors)
	 *	* checksum algorithm (used for b_freeze_cksum)
	 *	* object type & level (used to restore arc_buf_contents_t)
	 */
	uint64_t		le_prop;
	uint64_t		le_daddr;	/* buf location on l2dev */
	const uint64_t		le_pad[7];	/* resv'd for future use */
} l2arc_log_ent_phys_t;

/*
 * These design limits give us the following metadata overhead (before
 * compression):
 *	avg_blk_sz	overhead
 *	1k		12.51 %
 *	2k		 6.26 %
 *	4k		 3.13 %
 *	8k		 1.56 %
 *	16k		 0.78 %
 *	32k		 0.39 %
 *	64k		 0.20 %
 *	128k		 0.10 %
 * Compression should be able to sequeeze these down by about a factor of 2x.
 */
#define	L2ARC_LOG_BLK_SIZE			(128 * 1024)	/* 128k */
#define	L2ARC_LOG_BLK_HEADER_LEN		(128)
#define	L2ARC_LOG_BLK_ENTRIES			/* 1023 entries */	\
	((L2ARC_LOG_BLK_SIZE - L2ARC_LOG_BLK_HEADER_LEN) /		\
	sizeof (l2arc_log_ent_phys_t))
/*
 * Maximum amount of data in an l2arc log block (used to terminate rebuilding
 * before we hit the write head and restore potentially corrupted blocks).
 */
#define	L2ARC_LOG_BLK_MAX_PAYLOAD_SIZE	\
	(SPA_MAXBLOCKSIZE * L2ARC_LOG_BLK_ENTRIES)
/*
 * For the persistency and rebuild algorithms to operate reliably we need
 * the L2ARC device to at least be able to hold 3 full log blocks (otherwise
 * excessive log block looping might confuse the log chain end detection).
 * Under normal circumstances this is not a problem, since this is somewhere
 * around only 400 MB.
 */
#define	L2ARC_PERSIST_MIN_SIZE	(3 * L2ARC_LOG_BLK_MAX_PAYLOAD_SIZE)

/*
 * A log block of up to 1023 ARC buffer log entries, chained into the
 * persistent L2ARC metadata linked list. Byte order of magic determines
 * whether 64-bit bswap of fields is necessary.
 */
typedef struct l2arc_log_blk_phys {
	/* Header - see L2ARC_LOG_BLK_HEADER_LEN above */
	uint64_t		lb_magic;	/* L2ARC_LOG_BLK_MAGIC */
	l2arc_log_blkptr_t	lb_back2_lbp;	/* back 2 steps in chain */
	uint64_t		lb_pad[9];	/* resv'd for future use */
	/* Payload */
	l2arc_log_ent_phys_t	lb_entries[L2ARC_LOG_BLK_ENTRIES];
} l2arc_log_blk_phys_t;

CTASSERT(sizeof (l2arc_log_blk_phys_t) == L2ARC_LOG_BLK_SIZE);
CTASSERT(offsetof(l2arc_log_blk_phys_t, lb_entries) -
    offsetof(l2arc_log_blk_phys_t, lb_magic) == L2ARC_LOG_BLK_HEADER_LEN);

/*
 * These structures hold in-flight l2arc_log_blk_phys_t's as they're being
 * written to the L2ARC device. They may be compressed, hence the uint8_t[].
 */
typedef struct l2arc_log_blk_buf {
	uint8_t		lbb_log_blk[sizeof (l2arc_log_blk_phys_t)];
	list_node_t	lbb_node;
} l2arc_log_blk_buf_t;

/* Macros for the manipulation fields in the blk_prop format of blkptr_t */
#define	BLKPROP_GET_LSIZE(_obj, _field)		\
	BF64_GET_SB((_obj)->_field, 0, 16, SPA_MINBLOCKSHIFT, 1)
#define	BLKPROP_SET_LSIZE(_obj, _field, x)	\
	BF64_SET_SB((_obj)->_field, 0, 16, SPA_MINBLOCKSHIFT, 1, x)
#define	BLKPROP_GET_PSIZE(_obj, _field)		\
	BF64_GET_SB((_obj)->_field, 16, 16, SPA_MINBLOCKSHIFT, 0)
#define	BLKPROP_SET_PSIZE(_obj, _field, x)	\
	BF64_SET_SB((_obj)->_field, 16, 16, SPA_MINBLOCKSHIFT, 0, x)
#define	BLKPROP_GET_COMPRESS(_obj, _field)	\
	BF64_GET((_obj)->_field, 32, 7)
#define	BLKPROP_SET_COMPRESS(_obj, _field, x)	\
	BF64_SET((_obj)->_field, 32, 7, x)
#define	BLKPROP_GET_ARC_COMPRESS(_obj, _field)	\
	BF64_GET((_obj)->_field, 39, 1)
#define	BLKPROP_SET_ARC_COMPRESS(_obj, _field, x)	\
	BF64_SET((_obj)->_field, 39, 1, x)
#define	BLKPROP_GET_CHECKSUM(_obj, _field)	\
	BF64_GET((_obj)->_field, 40, 8)
#define	BLKPROP_SET_CHECKSUM(_obj, _field, x)	\
	BF64_SET((_obj)->_field, 40, 8, x)
#define	BLKPROP_GET_TYPE(_obj, _field)		\
	BF64_GET((_obj)->_field, 48, 8)
#define	BLKPROP_SET_TYPE(_obj, _field, x)	\
	BF64_SET((_obj)->_field, 48, 8, x)

/* Macros for manipulating a l2arc_log_blkptr_t->lbp_prop field */
#define	LBP_GET_LSIZE(_add)		BLKPROP_GET_LSIZE(_add, lbp_prop)
#define	LBP_SET_LSIZE(_add, x)		BLKPROP_SET_LSIZE(_add, lbp_prop, x)
#define	LBP_GET_PSIZE(_add)		BLKPROP_GET_PSIZE(_add, lbp_prop)
#define	LBP_SET_PSIZE(_add, x)		BLKPROP_SET_PSIZE(_add, lbp_prop, x)
#define	LBP_GET_COMPRESS(_add)		BLKPROP_GET_COMPRESS(_add, lbp_prop)
#define	LBP_SET_COMPRESS(_add, x)	BLKPROP_SET_COMPRESS(_add, lbp_prop, x)
#define	LBP_GET_CHECKSUM(_add)		BLKPROP_GET_CHECKSUM(_add, lbp_prop)
#define	LBP_SET_CHECKSUM(_add, x)	BLKPROP_SET_CHECKSUM(_add, lbp_prop, x)
#define	LBP_GET_TYPE(_add)		BLKPROP_GET_TYPE(_add, lbp_prop)
#define	LBP_SET_TYPE(_add, x)		BLKPROP_SET_TYPE(_add, lbp_prop, x)

/* Macros for manipulating a l2arc_log_ent_phys_t->le_prop field */
#define	LE_GET_LSIZE(_le)	BLKPROP_GET_LSIZE(_le, le_prop)
#define	LE_SET_LSIZE(_le, x)	BLKPROP_SET_LSIZE(_le, le_prop, x)
#define	LE_GET_PSIZE(_le)	BLKPROP_GET_PSIZE(_le, le_prop)
#define	LE_SET_PSIZE(_le, x)	BLKPROP_SET_PSIZE(_le, le_prop, x)
#define	LE_GET_COMPRESS(_le)	BLKPROP_GET_COMPRESS(_le, le_prop)
#define	LE_SET_COMPRESS(_le, x)	BLKPROP_SET_COMPRESS(_le, le_prop, x)
#define	LE_GET_ARC_COMPRESS(_le)	BLKPROP_GET_ARC_COMPRESS(_le, le_prop)
#define	LE_SET_ARC_COMPRESS(_le, x)	BLKPROP_SET_ARC_COMPRESS(_le, le_prop, x)
#define	LE_GET_CHECKSUM(_le)	BLKPROP_GET_CHECKSUM(_le, le_prop)
#define	LE_SET_CHECKSUM(_le, x)	BLKPROP_SET_CHECKSUM(_le, le_prop, x)
#define	LE_GET_TYPE(_le)	BLKPROP_GET_TYPE(_le, le_prop)
#define	LE_SET_TYPE(_le, x)	BLKPROP_SET_TYPE(_le, le_prop, x)

#define	PTR_SWAP(x, y)		\
	do {			\
		void *tmp = (x);\
		x = y;		\
		y = tmp;	\
		_NOTE(CONSTCOND)\
	} while (0)

/*
 * Sadly, after compressed ARC integration older kernels would panic
 * when trying to rebuild persistent L2ARC created by the new code.
 */
#define	L2ARC_DEV_HDR_MAGIC_V1	0x4c32415243763031LLU	/* ASCII: "L2ARCv01" */
#define	L2ARC_LOG_BLK_MAGIC	0x4c4f47424c4b4844LLU	/* ASCII: "LOGBLKHD" */

/*
 * Performance tuning of L2ARC persistency:
 *
 * l2arc_rebuild_enabled : Controls whether L2ARC device adds (either at
 *		pool import or when adding one manually later) will attempt
 *		to rebuild L2ARC buffer contents. In special circumstances,
 *		the administrator may want to set this to B_FALSE, if they
 *		are having trouble importing a pool or attaching an L2ARC
 *		device (e.g. the L2ARC device is slow to read in stored log
 *		metadata, or the metadata has become somehow
 *		fragmented/unusable).
 */
boolean_t l2arc_rebuild_enabled = B_TRUE;

/* L2ARC persistency rebuild control routines. */
static void l2arc_dev_rebuild_start(l2arc_dev_t *dev);
static int l2arc_rebuild(l2arc_dev_t *dev);

/* L2ARC persistency read I/O routines. */
static int l2arc_dev_hdr_read(l2arc_dev_t *dev);
static int l2arc_log_blk_read(l2arc_dev_t *dev,
    const l2arc_log_blkptr_t *this_lp, const l2arc_log_blkptr_t *next_lp,
    l2arc_log_blk_phys_t *this_lb, l2arc_log_blk_phys_t *next_lb,
    uint8_t *this_lb_buf, uint8_t *next_lb_buf,
    zio_t *this_io, zio_t **next_io);
static zio_t *l2arc_log_blk_prefetch(vdev_t *vd,
    const l2arc_log_blkptr_t *lp, uint8_t *lb_buf);
static void l2arc_log_blk_prefetch_abort(zio_t *zio);

/* L2ARC persistency block restoration routines. */
static void l2arc_log_blk_restore(l2arc_dev_t *dev, uint64_t load_guid,
    const l2arc_log_blk_phys_t *lb, uint64_t lb_psize);
static void l2arc_hdr_restore(const l2arc_log_ent_phys_t *le,
    l2arc_dev_t *dev, uint64_t guid);

/* L2ARC persistency write I/O routines. */
static void l2arc_dev_hdr_update(l2arc_dev_t *dev, zio_t *pio);
static void l2arc_log_blk_commit(l2arc_dev_t *dev, zio_t *pio,
    l2arc_write_callback_t *cb);

/* L2ARC persistency auxilliary routines. */
static boolean_t l2arc_log_blkptr_valid(l2arc_dev_t *dev,
    const l2arc_log_blkptr_t *lp);
static void l2arc_dev_hdr_checksum(const l2arc_dev_hdr_phys_t *hdr,
    zio_cksum_t *cksum);
static boolean_t l2arc_log_blk_insert(l2arc_dev_t *dev,
    const arc_buf_hdr_t *ab);
static inline boolean_t l2arc_range_check_overlap(uint64_t bottom,
    uint64_t top, uint64_t check);

/*
 * L2ARC Internals
 */
struct l2arc_dev {
	vdev_t			*l2ad_vdev;	/* vdev */
	spa_t			*l2ad_spa;	/* spa */
	uint64_t		l2ad_hand;	/* next write location */
	uint64_t		l2ad_start;	/* first addr on device */
	uint64_t		l2ad_end;	/* last addr on device */
	boolean_t		l2ad_first;	/* first sweep through */
	boolean_t		l2ad_writing;	/* currently writing */
	kmutex_t		l2ad_mtx;	/* lock for buffer list */
	list_t			l2ad_buflist;	/* buffer list */
	list_node_t		l2ad_node;	/* device list node */
	refcount_t		l2ad_alloc;	/* allocated bytes */
	l2arc_dev_hdr_phys_t	*l2ad_dev_hdr;	/* persistent device header */
	uint64_t		l2ad_dev_hdr_asize; /* aligned hdr size */
	l2arc_log_blk_phys_t	l2ad_log_blk;	/* currently open log block */
	int			l2ad_log_ent_idx; /* index into cur log blk */
	/* number of bytes in current log block's payload */
	uint64_t		l2ad_log_blk_payload_asize;
	/* flag indicating whether a rebuild is scheduled or is going on */
	boolean_t		l2ad_rebuild;
	boolean_t		l2ad_rebuild_cancel;
	kt_did_t		l2ad_rebuild_did;
};


/*
 * We use Cityhash for this. It's fast, and has good hash properties without
 * requiring any large static buffers.
 */
static uint64_t
buf_hash(uint64_t spa, const dva_t *dva, uint64_t birth)
{
	return (cityhash4(spa, dva->dva_word[0], dva->dva_word[1], birth));
}

#define	HDR_EMPTY(hdr)						\
	((hdr)->b_dva.dva_word[0] == 0 &&			\
	(hdr)->b_dva.dva_word[1] == 0)

#define	HDR_EQUAL(spa, dva, birth, hdr)				\
	((hdr)->b_dva.dva_word[0] == (dva)->dva_word[0]) &&	\
	((hdr)->b_dva.dva_word[1] == (dva)->dva_word[1]) &&	\
	((hdr)->b_birth == birth) && ((hdr)->b_spa == spa)

static void
buf_discard_identity(arc_buf_hdr_t *hdr)
{
	hdr->b_dva.dva_word[0] = 0;
	hdr->b_dva.dva_word[1] = 0;
	hdr->b_birth = 0;
}

static arc_buf_hdr_t *
buf_hash_find(uint64_t spa, const blkptr_t *bp, kmutex_t **lockp)
{
	const dva_t *dva = BP_IDENTITY(bp);
	uint64_t birth = BP_PHYSICAL_BIRTH(bp);
	uint64_t idx = BUF_HASH_INDEX(spa, dva, birth);
	kmutex_t *hash_lock = BUF_HASH_LOCK(idx);
	arc_buf_hdr_t *hdr;

	mutex_enter(hash_lock);
	for (hdr = buf_hash_table.ht_table[idx].hdr; hdr != NULL;
	    hdr = hdr->b_hash_next) {
		if (HDR_EQUAL(spa, dva, birth, hdr)) {
			*lockp = hash_lock;
			return (hdr);
		}
	}
	mutex_exit(hash_lock);
	*lockp = NULL;
	return (NULL);
}

/*
 * Insert an entry into the hash table.  If there is already an element
 * equal to elem in the hash table, then the already existing element
 * will be returned and the new element will not be inserted.
 * Otherwise returns NULL.
 * If lockp == NULL, the caller is assumed to already hold the hash lock.
 */
static arc_buf_hdr_t *
buf_hash_insert(arc_buf_hdr_t *hdr, kmutex_t **lockp)
{
	uint64_t idx = BUF_HASH_INDEX(hdr->b_spa, &hdr->b_dva, hdr->b_birth);
	kmutex_t *hash_lock = BUF_HASH_LOCK(idx);
	arc_buf_hdr_t *fhdr;
	uint32_t i;

	ASSERT(!DVA_IS_EMPTY(&hdr->b_dva));
	ASSERT(hdr->b_birth != 0);
	ASSERT(!HDR_IN_HASH_TABLE(hdr));

	if (lockp != NULL) {
		*lockp = hash_lock;
		mutex_enter(hash_lock);
	} else {
		ASSERT(MUTEX_HELD(hash_lock));
	}

	for (fhdr = buf_hash_table.ht_table[idx].hdr, i = 0; fhdr != NULL;
	    fhdr = fhdr->b_hash_next, i++) {
		if (HDR_EQUAL(hdr->b_spa, &hdr->b_dva, hdr->b_birth, fhdr))
			return (fhdr);
	}

	hdr->b_hash_next = buf_hash_table.ht_table[idx].hdr;
	buf_hash_table.ht_table[idx].hdr = hdr;
	arc_hdr_set_flags(hdr, ARC_FLAG_IN_HASH_TABLE);

	/* collect some hash table performance data */
	if (i > 0) {
		ARCSTAT_BUMP(arcstat_hash_collisions);
		if (i == 1)
			ARCSTAT_BUMP(arcstat_hash_chains);

		ARCSTAT_MAX(arcstat_hash_chain_max, i);
	}

	ARCSTAT_BUMP(arcstat_hash_elements);
	ARCSTAT_MAXSTAT(arcstat_hash_elements);

	return (NULL);
}

static void
buf_hash_remove(arc_buf_hdr_t *hdr)
{
	arc_buf_hdr_t *fhdr, **hdrp;
	uint64_t idx = BUF_HASH_INDEX(hdr->b_spa, &hdr->b_dva, hdr->b_birth);

	ASSERT(MUTEX_HELD(BUF_HASH_LOCK(idx)));
	ASSERT(HDR_IN_HASH_TABLE(hdr));

	hdrp = &buf_hash_table.ht_table[idx].hdr;
	while ((fhdr = *hdrp) != hdr) {
		ASSERT3P(fhdr, !=, NULL);
		hdrp = &fhdr->b_hash_next;
	}
	*hdrp = hdr->b_hash_next;
	hdr->b_hash_next = NULL;
	arc_hdr_clear_flags(hdr, ARC_FLAG_IN_HASH_TABLE);

	/* collect some hash table performance data */
	ARCSTAT_BUMPDOWN(arcstat_hash_elements);

	if (buf_hash_table.ht_table[idx].hdr &&
	    buf_hash_table.ht_table[idx].hdr->b_hash_next == NULL)
		ARCSTAT_BUMPDOWN(arcstat_hash_chains);
}

/*
 * Global data structures and functions for the buf kmem cache.
 */
static kmem_cache_t *hdr_full_cache;
static kmem_cache_t *hdr_l2only_cache;
static kmem_cache_t *buf_cache;

static void
buf_fini(void)
{
	int i;

	for (i = 0; i < buf_hash_table.ht_mask + 1; i++)
		mutex_destroy(&buf_hash_table.ht_table[i].lock);
	kmem_free(buf_hash_table.ht_table,
	    (buf_hash_table.ht_mask + 1) * sizeof (struct ht_table));
	kmem_cache_destroy(hdr_full_cache);
	kmem_cache_destroy(hdr_l2only_cache);
	kmem_cache_destroy(buf_cache);
}

/*
 * Constructor callback - called when the cache is empty
 * and a new buf is requested.
 */
/* ARGSUSED */
static int
hdr_full_cons(void *vbuf, void *unused, int kmflag)
{
	arc_buf_hdr_t *hdr = vbuf;

	bzero(hdr, HDR_FULL_SIZE);
	cv_init(&hdr->b_l1hdr.b_cv, NULL, CV_DEFAULT, NULL);
	refcount_create(&hdr->b_l1hdr.b_refcnt);
	mutex_init(&hdr->b_l1hdr.b_freeze_lock, NULL, MUTEX_DEFAULT, NULL);
	multilist_link_init(&hdr->b_l1hdr.b_arc_node);
	arc_space_consume(HDR_FULL_SIZE, ARC_SPACE_HDRS);

	return (0);
}

/* ARGSUSED */
static int
hdr_l2only_cons(void *vbuf, void *unused, int kmflag)
{
	arc_buf_hdr_t *hdr = vbuf;

	bzero(hdr, HDR_L2ONLY_SIZE);
	arc_space_consume(HDR_L2ONLY_SIZE, ARC_SPACE_L2HDRS);

	return (0);
}

/* ARGSUSED */
static int
buf_cons(void *vbuf, void *unused, int kmflag)
{
	arc_buf_t *buf = vbuf;

	bzero(buf, sizeof (arc_buf_t));
	mutex_init(&buf->b_evict_lock, NULL, MUTEX_DEFAULT, NULL);
	arc_space_consume(sizeof (arc_buf_t), ARC_SPACE_HDRS);

	return (0);
}

/*
 * Destructor callback - called when a cached buf is
 * no longer required.
 */
/* ARGSUSED */
static void
hdr_full_dest(void *vbuf, void *unused)
{
	arc_buf_hdr_t *hdr = vbuf;

	ASSERT(HDR_EMPTY(hdr));
	cv_destroy(&hdr->b_l1hdr.b_cv);
	refcount_destroy(&hdr->b_l1hdr.b_refcnt);
	mutex_destroy(&hdr->b_l1hdr.b_freeze_lock);
	ASSERT(!multilist_link_active(&hdr->b_l1hdr.b_arc_node));
	arc_space_return(HDR_FULL_SIZE, ARC_SPACE_HDRS);
}

/* ARGSUSED */
static void
hdr_l2only_dest(void *vbuf, void *unused)
{
	arc_buf_hdr_t *hdr = vbuf;

	ASSERT(HDR_EMPTY(hdr));
	arc_space_return(HDR_L2ONLY_SIZE, ARC_SPACE_L2HDRS);
}

/* ARGSUSED */
static void
buf_dest(void *vbuf, void *unused)
{
	arc_buf_t *buf = vbuf;

	mutex_destroy(&buf->b_evict_lock);
	arc_space_return(sizeof (arc_buf_t), ARC_SPACE_HDRS);
}

/*
 * Reclaim callback -- invoked when memory is low.
 */
/* ARGSUSED */
static void
hdr_recl(void *unused)
{
	dprintf("hdr_recl called\n");
	/*
	 * umem calls the reclaim func when we destroy the buf cache,
	 * which is after we do arc_fini().
	 */
	if (!arc_dead)
		cv_signal(&arc_reclaim_thread_cv);
}

static void
buf_init(void)
{
	uint64_t *ct;
	uint64_t hsize = 1ULL << 12;
	int i, j;

	/*
	 * The hash table is big enough to fill all of physical memory
	 * with an average block size of zfs_arc_average_blocksize (default 8K).
	 * By default, the table will take up
	 * totalmem * sizeof(void*) / 8K (1MB per GB with 8-byte pointers).
	 */
	while (hsize * zfs_arc_average_blocksize < physmem * PAGESIZE)
		hsize <<= 1;
retry:
	buf_hash_table.ht_mask = hsize - 1;
	buf_hash_table.ht_table =
	    kmem_zalloc(hsize * sizeof (struct ht_table), KM_NOSLEEP);
	if (buf_hash_table.ht_table == NULL) {
		ASSERT(hsize > (1ULL << 8));
		hsize >>= 1;
		goto retry;
	}

	hdr_full_cache = kmem_cache_create("arc_buf_hdr_t_full", HDR_FULL_SIZE,
	    0, hdr_full_cons, hdr_full_dest, hdr_recl, NULL, NULL, 0);
	hdr_l2only_cache = kmem_cache_create("arc_buf_hdr_t_l2only",
	    HDR_L2ONLY_SIZE, 0, hdr_l2only_cons, hdr_l2only_dest, hdr_recl,
	    NULL, NULL, 0);
	buf_cache = kmem_cache_create("arc_buf_t", sizeof (arc_buf_t),
	    0, buf_cons, buf_dest, NULL, NULL, NULL, 0);

	for (i = 0; i < 256; i++)
		for (ct = zfs_crc64_table + i, *ct = i, j = 8; j > 0; j--)
			*ct = (*ct >> 1) ^ (-(*ct & 1) & ZFS_CRC64_POLY);

	for (i = 0; i < hsize; i++) {
		mutex_init(&buf_hash_table.ht_table[i].lock,
		    NULL, MUTEX_DEFAULT, NULL);
	}
}

/*
 * Short holders are the consumers, that hold the buf for
 * a short period of time to copy its data to somewhere
 * For now only WBC uses the functionality.
 */
static inline void
arc_wait_for_short_holders(arc_buf_hdr_t *hdr)
{
	while (HDR_HAS_L1HDR(hdr) && hdr->b_l1hdr.b_short_holders != 0)
		cv_wait(&hdr->b_l1hdr.b_cv, HDR_LOCK(hdr));
}

/*
 * This is the size that the buf occupies in memory. If the buf is compressed,
 * it will correspond to the compressed size. You should use this method of
 * getting the buf size unless you explicitly need the logical size.
 */
int32_t
arc_buf_size(arc_buf_t *buf)
{
	return (ARC_BUF_COMPRESSED(buf) ?
	    HDR_GET_PSIZE(buf->b_hdr) : HDR_GET_LSIZE(buf->b_hdr));
}

int32_t
arc_buf_lsize(arc_buf_t *buf)
{
	return (HDR_GET_LSIZE(buf->b_hdr));
}

enum zio_compress
arc_get_compression(arc_buf_t *buf)
{
	return (ARC_BUF_COMPRESSED(buf) ?
	    HDR_GET_COMPRESS(buf->b_hdr) : ZIO_COMPRESS_OFF);
}

#define	ARC_MINTIME	(hz>>4) /* 62 ms */

static inline boolean_t
arc_buf_is_shared(arc_buf_t *buf)
{
	boolean_t shared = (buf->b_data != NULL &&
	    buf->b_hdr->b_l1hdr.b_pabd != NULL &&
	    abd_is_linear(buf->b_hdr->b_l1hdr.b_pabd) &&
	    buf->b_data == abd_to_buf(buf->b_hdr->b_l1hdr.b_pabd));
	IMPLY(shared, HDR_SHARED_DATA(buf->b_hdr));
	IMPLY(shared, ARC_BUF_SHARED(buf));
	IMPLY(shared, ARC_BUF_COMPRESSED(buf) || ARC_BUF_LAST(buf));

	/*
	 * It would be nice to assert arc_can_share() too, but the "hdr isn't
	 * already being shared" requirement prevents us from doing that.
	 */

	return (shared);
}

/*
 * Free the checksum associated with this header. If there is no checksum, this
 * is a no-op.
 */
static inline void
arc_cksum_free(arc_buf_hdr_t *hdr)
{
	ASSERT(HDR_HAS_L1HDR(hdr));
	mutex_enter(&hdr->b_l1hdr.b_freeze_lock);
	if (hdr->b_freeze_cksum != NULL) {
		kmem_free(hdr->b_freeze_cksum, sizeof (zio_cksum_t));
		hdr->b_freeze_cksum = NULL;
	}
	mutex_exit(&hdr->b_l1hdr.b_freeze_lock);
}

/*
 * Return true iff at least one of the bufs on hdr is not compressed.
 */
static boolean_t
arc_hdr_has_uncompressed_buf(arc_buf_hdr_t *hdr)
{
	for (arc_buf_t *b = hdr->b_l1hdr.b_buf; b != NULL; b = b->b_next) {
		if (!ARC_BUF_COMPRESSED(b)) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * If we've turned on the ZFS_DEBUG_MODIFY flag, verify that the buf's data
 * matches the checksum that is stored in the hdr. If there is no checksum,
 * or if the buf is compressed, this is a no-op.
 */
static void
arc_cksum_verify(arc_buf_t *buf)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	zio_cksum_t zc;

	if (!(zfs_flags & ZFS_DEBUG_MODIFY))
		return;

	if (ARC_BUF_COMPRESSED(buf)) {
		ASSERT(hdr->b_freeze_cksum == NULL ||
		    arc_hdr_has_uncompressed_buf(hdr));
		return;
	}

	ASSERT(HDR_HAS_L1HDR(hdr));

	mutex_enter(&hdr->b_l1hdr.b_freeze_lock);
	if (hdr->b_freeze_cksum == NULL || HDR_IO_ERROR(hdr)) {
		mutex_exit(&hdr->b_l1hdr.b_freeze_lock);
		return;
	}

	fletcher_2_native(buf->b_data, arc_buf_size(buf), NULL, &zc);
	if (!ZIO_CHECKSUM_EQUAL(*hdr->b_freeze_cksum, zc))
		panic("buffer modified while frozen!");
	mutex_exit(&hdr->b_l1hdr.b_freeze_lock);
}

static boolean_t
arc_cksum_is_equal(arc_buf_hdr_t *hdr, zio_t *zio)
{
	enum zio_compress compress = BP_GET_COMPRESS(zio->io_bp);
	boolean_t valid_cksum;

	ASSERT(!BP_IS_EMBEDDED(zio->io_bp));
	VERIFY3U(BP_GET_PSIZE(zio->io_bp), ==, HDR_GET_PSIZE(hdr));

	/*
	 * We rely on the blkptr's checksum to determine if the block
	 * is valid or not. When compressed arc is enabled, the l2arc
	 * writes the block to the l2arc just as it appears in the pool.
	 * This allows us to use the blkptr's checksum to validate the
	 * data that we just read off of the l2arc without having to store
	 * a separate checksum in the arc_buf_hdr_t. However, if compressed
	 * arc is disabled, then the data written to the l2arc is always
	 * uncompressed and won't match the block as it exists in the main
	 * pool. When this is the case, we must first compress it if it is
	 * compressed on the main pool before we can validate the checksum.
	 */
	if (!HDR_COMPRESSION_ENABLED(hdr) && compress != ZIO_COMPRESS_OFF) {
		ASSERT3U(HDR_GET_COMPRESS(hdr), ==, ZIO_COMPRESS_OFF);
		uint64_t lsize = HDR_GET_LSIZE(hdr);
		uint64_t csize;

		void *cbuf = zio_buf_alloc(HDR_GET_PSIZE(hdr));
		csize = zio_compress_data(compress, zio->io_abd, cbuf, lsize);
		abd_t *cdata = abd_get_from_buf(cbuf, HDR_GET_PSIZE(hdr));
		abd_take_ownership_of_buf(cdata, B_TRUE);

		ASSERT3U(csize, <=, HDR_GET_PSIZE(hdr));
		if (csize < HDR_GET_PSIZE(hdr)) {
			/*
			 * Compressed blocks are always a multiple of the
			 * smallest ashift in the pool. Ideally, we would
			 * like to round up the csize to the next
			 * spa_min_ashift but that value may have changed
			 * since the block was last written. Instead,
			 * we rely on the fact that the hdr's psize
			 * was set to the psize of the block when it was
			 * last written. We set the csize to that value
			 * and zero out any part that should not contain
			 * data.
			 */
			abd_zero_off(cdata, csize, HDR_GET_PSIZE(hdr) - csize);
			csize = HDR_GET_PSIZE(hdr);
		}
		zio_push_transform(zio, cdata, csize, HDR_GET_PSIZE(hdr), NULL);
	}

	/*
	 * Block pointers always store the checksum for the logical data.
	 * If the block pointer has the gang bit set, then the checksum
	 * it represents is for the reconstituted data and not for an
	 * individual gang member. The zio pipeline, however, must be able to
	 * determine the checksum of each of the gang constituents so it
	 * treats the checksum comparison differently than what we need
	 * for l2arc blocks. This prevents us from using the
	 * zio_checksum_error() interface directly. Instead we must call the
	 * zio_checksum_error_impl() so that we can ensure the checksum is
	 * generated using the correct checksum algorithm and accounts for the
	 * logical I/O size and not just a gang fragment.
	 */
	valid_cksum = (zio_checksum_error_impl(zio->io_spa, zio->io_bp,
	    BP_GET_CHECKSUM(zio->io_bp), zio->io_abd, zio->io_size,
	    zio->io_offset, NULL) == 0);
	zio_pop_transforms(zio);
	return (valid_cksum);
}

/*
 * Given a buf full of data, if ZFS_DEBUG_MODIFY is enabled this computes a
 * checksum and attaches it to the buf's hdr so that we can ensure that the buf
 * isn't modified later on. If buf is compressed or there is already a checksum
 * on the hdr, this is a no-op (we only checksum uncompressed bufs).
 */
static void
arc_cksum_compute(arc_buf_t *buf)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;

	if (!(zfs_flags & ZFS_DEBUG_MODIFY))
		return;

	ASSERT(HDR_HAS_L1HDR(hdr));

	mutex_enter(&buf->b_hdr->b_l1hdr.b_freeze_lock);
	if (hdr->b_freeze_cksum != NULL) {
		ASSERT(arc_hdr_has_uncompressed_buf(hdr));
		mutex_exit(&hdr->b_l1hdr.b_freeze_lock);
		return;
	} else if (ARC_BUF_COMPRESSED(buf)) {
		mutex_exit(&hdr->b_l1hdr.b_freeze_lock);
		return;
	}

	ASSERT(!ARC_BUF_COMPRESSED(buf));
	hdr->b_freeze_cksum = kmem_alloc(sizeof (zio_cksum_t),
	    KM_SLEEP);
	fletcher_2_native(buf->b_data, arc_buf_size(buf), NULL,
	    hdr->b_freeze_cksum);
	mutex_exit(&hdr->b_l1hdr.b_freeze_lock);
	arc_buf_watch(buf);
}

#ifndef _KERNEL
typedef struct procctl {
	long cmd;
	prwatch_t prwatch;
} procctl_t;
#endif

/* ARGSUSED */
static void
arc_buf_unwatch(arc_buf_t *buf)
{
#ifndef _KERNEL
	if (arc_watch) {
		int result;
		procctl_t ctl;
		ctl.cmd = PCWATCH;
		ctl.prwatch.pr_vaddr = (uintptr_t)buf->b_data;
		ctl.prwatch.pr_size = 0;
		ctl.prwatch.pr_wflags = 0;
		result = write(arc_procfd, &ctl, sizeof (ctl));
		ASSERT3U(result, ==, sizeof (ctl));
	}
#endif
}

/* ARGSUSED */
static void
arc_buf_watch(arc_buf_t *buf)
{
#ifndef _KERNEL
	if (arc_watch) {
		int result;
		procctl_t ctl;
		ctl.cmd = PCWATCH;
		ctl.prwatch.pr_vaddr = (uintptr_t)buf->b_data;
		ctl.prwatch.pr_size = arc_buf_size(buf);
		ctl.prwatch.pr_wflags = WA_WRITE;
		result = write(arc_procfd, &ctl, sizeof (ctl));
		ASSERT3U(result, ==, sizeof (ctl));
	}
#endif
}

static arc_buf_contents_t
arc_buf_type(arc_buf_hdr_t *hdr)
{
	arc_buf_contents_t type;

	if (HDR_ISTYPE_METADATA(hdr)) {
		type = ARC_BUFC_METADATA;
	} else if (HDR_ISTYPE_DDT(hdr)) {
		type = ARC_BUFC_DDT;
	} else {
		type = ARC_BUFC_DATA;
	}
	VERIFY3U(hdr->b_type, ==, type);
	return (type);
}

boolean_t
arc_is_metadata(arc_buf_t *buf)
{
	return (HDR_ISTYPE_METADATA(buf->b_hdr) != 0);
}

static uint32_t
arc_bufc_to_flags(arc_buf_contents_t type)
{
	switch (type) {
	case ARC_BUFC_DATA:
		/* metadata field is 0 if buffer contains normal data */
		return (0);
	case ARC_BUFC_METADATA:
		return (ARC_FLAG_BUFC_METADATA);
	case ARC_BUFC_DDT:
		return (ARC_FLAG_BUFC_DDT);
	default:
		break;
	}
	panic("undefined ARC buffer type!");
	return ((uint32_t)-1);
}

static arc_buf_contents_t
arc_flags_to_bufc(uint32_t flags)
{
	if (flags & ARC_FLAG_BUFC_DDT)
		return (ARC_BUFC_DDT);
	if (flags & ARC_FLAG_BUFC_METADATA)
		return (ARC_BUFC_METADATA);
	return (ARC_BUFC_DATA);
}

void
arc_buf_thaw(arc_buf_t *buf)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;

	ASSERT3P(hdr->b_l1hdr.b_state, ==, arc_anon);
	ASSERT(!HDR_IO_IN_PROGRESS(hdr));

	arc_cksum_verify(buf);

	/*
	 * Compressed buffers do not manipulate the b_freeze_cksum or
	 * allocate b_thawed.
	 */
	if (ARC_BUF_COMPRESSED(buf)) {
		ASSERT(hdr->b_freeze_cksum == NULL ||
		    arc_hdr_has_uncompressed_buf(hdr));
		return;
	}

	ASSERT(HDR_HAS_L1HDR(hdr));
	arc_cksum_free(hdr);

	mutex_enter(&hdr->b_l1hdr.b_freeze_lock);
#ifdef ZFS_DEBUG
	if (zfs_flags & ZFS_DEBUG_MODIFY) {
		if (hdr->b_l1hdr.b_thawed != NULL)
			kmem_free(hdr->b_l1hdr.b_thawed, 1);
		hdr->b_l1hdr.b_thawed = kmem_alloc(1, KM_SLEEP);
	}
#endif

	mutex_exit(&hdr->b_l1hdr.b_freeze_lock);

	arc_buf_unwatch(buf);
}

void
arc_buf_freeze(arc_buf_t *buf)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	kmutex_t *hash_lock;

	if (!(zfs_flags & ZFS_DEBUG_MODIFY))
		return;

	if (ARC_BUF_COMPRESSED(buf)) {
		ASSERT(hdr->b_freeze_cksum == NULL ||
		    arc_hdr_has_uncompressed_buf(hdr));
		return;
	}

	hash_lock = HDR_LOCK(hdr);
	mutex_enter(hash_lock);

	ASSERT(HDR_HAS_L1HDR(hdr));
	ASSERT(hdr->b_freeze_cksum != NULL ||
	    hdr->b_l1hdr.b_state == arc_anon);
	arc_cksum_compute(buf);
	mutex_exit(hash_lock);
}

/*
 * The arc_buf_hdr_t's b_flags should never be modified directly. Instead,
 * the following functions should be used to ensure that the flags are
 * updated in a thread-safe way. When manipulating the flags either
 * the hash_lock must be held or the hdr must be undiscoverable. This
 * ensures that we're not racing with any other threads when updating
 * the flags.
 */
static inline void
arc_hdr_set_flags(arc_buf_hdr_t *hdr, arc_flags_t flags)
{
	ASSERT(MUTEX_HELD(HDR_LOCK(hdr)) || HDR_EMPTY(hdr));
	hdr->b_flags |= flags;
}

static inline void
arc_hdr_clear_flags(arc_buf_hdr_t *hdr, arc_flags_t flags)
{
	ASSERT(MUTEX_HELD(HDR_LOCK(hdr)) || HDR_EMPTY(hdr));
	hdr->b_flags &= ~flags;
}

/*
 * Setting the compression bits in the arc_buf_hdr_t's b_flags is
 * done in a special way since we have to clear and set bits
 * at the same time. Consumers that wish to set the compression bits
 * must use this function to ensure that the flags are updated in
 * thread-safe manner.
 */
static void
arc_hdr_set_compress(arc_buf_hdr_t *hdr, enum zio_compress cmp)
{
	ASSERT(MUTEX_HELD(HDR_LOCK(hdr)) || HDR_EMPTY(hdr));

	/*
	 * Holes and embedded blocks will always have a psize = 0 so
	 * we ignore the compression of the blkptr and set the
	 * arc_buf_hdr_t's compression to ZIO_COMPRESS_OFF.
	 * Holes and embedded blocks remain anonymous so we don't
	 * want to uncompress them. Mark them as uncompressed.
	 */
	if (!zfs_compressed_arc_enabled || HDR_GET_PSIZE(hdr) == 0) {
		arc_hdr_clear_flags(hdr, ARC_FLAG_COMPRESSED_ARC);
		HDR_SET_COMPRESS(hdr, ZIO_COMPRESS_OFF);
		ASSERT(!HDR_COMPRESSION_ENABLED(hdr));
		ASSERT3U(HDR_GET_COMPRESS(hdr), ==, ZIO_COMPRESS_OFF);
	} else {
		arc_hdr_set_flags(hdr, ARC_FLAG_COMPRESSED_ARC);
		HDR_SET_COMPRESS(hdr, cmp);
		ASSERT3U(HDR_GET_COMPRESS(hdr), ==, cmp);
		ASSERT(HDR_COMPRESSION_ENABLED(hdr));
	}
}

/*
 * Looks for another buf on the same hdr which has the data decompressed, copies
 * from it, and returns true. If no such buf exists, returns false.
 */
static boolean_t
arc_buf_try_copy_decompressed_data(arc_buf_t *buf)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	boolean_t copied = B_FALSE;

	ASSERT(HDR_HAS_L1HDR(hdr));
	ASSERT3P(buf->b_data, !=, NULL);
	ASSERT(!ARC_BUF_COMPRESSED(buf));

	for (arc_buf_t *from = hdr->b_l1hdr.b_buf; from != NULL;
	    from = from->b_next) {
		/* can't use our own data buffer */
		if (from == buf) {
			continue;
		}

		if (!ARC_BUF_COMPRESSED(from)) {
			bcopy(from->b_data, buf->b_data, arc_buf_size(buf));
			copied = B_TRUE;
			break;
		}
	}

	/*
	 * There were no decompressed bufs, so there should not be a
	 * checksum on the hdr either.
	 */
	EQUIV(!copied, hdr->b_freeze_cksum == NULL);

	return (copied);
}

/*
 * Given a buf that has a data buffer attached to it, this function will
 * efficiently fill the buf with data of the specified compression setting from
 * the hdr and update the hdr's b_freeze_cksum if necessary. If the buf and hdr
 * are already sharing a data buf, no copy is performed.
 *
 * If the buf is marked as compressed but uncompressed data was requested, this
 * will allocate a new data buffer for the buf, remove that flag, and fill the
 * buf with uncompressed data. You can't request a compressed buf on a hdr with
 * uncompressed data, and (since we haven't added support for it yet) if you
 * want compressed data your buf must already be marked as compressed and have
 * the correct-sized data buffer.
 */
static int
arc_buf_fill(arc_buf_t *buf, boolean_t compressed)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	boolean_t hdr_compressed = (HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF);
	dmu_object_byteswap_t bswap = hdr->b_l1hdr.b_byteswap;

	ASSERT3P(buf->b_data, !=, NULL);
	IMPLY(compressed, hdr_compressed);
	IMPLY(compressed, ARC_BUF_COMPRESSED(buf));

	if (hdr_compressed == compressed) {
		if (!arc_buf_is_shared(buf)) {
			abd_copy_to_buf(buf->b_data, hdr->b_l1hdr.b_pabd,
			    arc_buf_size(buf));
		}
	} else {
		ASSERT(hdr_compressed);
		ASSERT(!compressed);
		ASSERT3U(HDR_GET_LSIZE(hdr), !=, HDR_GET_PSIZE(hdr));

		/*
		 * If the buf is sharing its data with the hdr, unlink it and
		 * allocate a new data buffer for the buf.
		 */
		if (arc_buf_is_shared(buf)) {
			ASSERT(ARC_BUF_COMPRESSED(buf));

			/* We need to give the buf it's own b_data */
			buf->b_flags &= ~ARC_BUF_FLAG_SHARED;
			buf->b_data =
			    arc_get_data_buf(hdr, HDR_GET_LSIZE(hdr), buf);
			arc_hdr_clear_flags(hdr, ARC_FLAG_SHARED_DATA);

			/* Previously overhead was 0; just add new overhead */
			ARCSTAT_INCR(arcstat_overhead_size, HDR_GET_LSIZE(hdr));
		} else if (ARC_BUF_COMPRESSED(buf)) {
			/* We need to reallocate the buf's b_data */
			arc_free_data_buf(hdr, buf->b_data, HDR_GET_PSIZE(hdr),
			    buf);
			buf->b_data =
			    arc_get_data_buf(hdr, HDR_GET_LSIZE(hdr), buf);

			/* We increased the size of b_data; update overhead */
			ARCSTAT_INCR(arcstat_overhead_size,
			    HDR_GET_LSIZE(hdr) - HDR_GET_PSIZE(hdr));
		}

		/*
		 * Regardless of the buf's previous compression settings, it
		 * should not be compressed at the end of this function.
		 */
		buf->b_flags &= ~ARC_BUF_FLAG_COMPRESSED;

		/*
		 * Try copying the data from another buf which already has a
		 * decompressed version. If that's not possible, it's time to
		 * bite the bullet and decompress the data from the hdr.
		 */
		if (arc_buf_try_copy_decompressed_data(buf)) {
			/* Skip byteswapping and checksumming (already done) */
			ASSERT3P(hdr->b_freeze_cksum, !=, NULL);
			return (0);
		} else {
			int error = zio_decompress_data(HDR_GET_COMPRESS(hdr),
			    hdr->b_l1hdr.b_pabd, buf->b_data,
			    HDR_GET_PSIZE(hdr), HDR_GET_LSIZE(hdr));

			/*
			 * Absent hardware errors or software bugs, this should
			 * be impossible, but log it anyway so we can debug it.
			 */
			if (error != 0) {
				zfs_dbgmsg(
				    "hdr %p, compress %d, psize %d, lsize %d",
				    hdr, HDR_GET_COMPRESS(hdr),
				    HDR_GET_PSIZE(hdr), HDR_GET_LSIZE(hdr));
				return (SET_ERROR(EIO));
			}
		}
	}

	/* Byteswap the buf's data if necessary */
	if (bswap != DMU_BSWAP_NUMFUNCS) {
		ASSERT(!HDR_SHARED_DATA(hdr));
		ASSERT3U(bswap, <, DMU_BSWAP_NUMFUNCS);
		dmu_ot_byteswap[bswap].ob_func(buf->b_data, HDR_GET_LSIZE(hdr));
	}

	/* Compute the hdr's checksum if necessary */
	arc_cksum_compute(buf);

	return (0);
}

int
arc_decompress(arc_buf_t *buf)
{
	return (arc_buf_fill(buf, B_FALSE));
}

/*
 * Return the size of the block, b_pabd, that is stored in the arc_buf_hdr_t.
 */
static uint64_t
arc_hdr_size(arc_buf_hdr_t *hdr)
{
	uint64_t size;

	if (HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF &&
	    HDR_GET_PSIZE(hdr) > 0) {
		size = HDR_GET_PSIZE(hdr);
	} else {
		ASSERT3U(HDR_GET_LSIZE(hdr), !=, 0);
		size = HDR_GET_LSIZE(hdr);
	}
	return (size);
}

/*
 * Increment the amount of evictable space in the arc_state_t's refcount.
 * We account for the space used by the hdr and the arc buf individually
 * so that we can add and remove them from the refcount individually.
 */
static void
arc_evictable_space_increment(arc_buf_hdr_t *hdr, arc_state_t *state)
{
	arc_buf_contents_t type = arc_buf_type(hdr);

	ASSERT(HDR_HAS_L1HDR(hdr));

	if (GHOST_STATE(state)) {
		ASSERT0(hdr->b_l1hdr.b_bufcnt);
		ASSERT3P(hdr->b_l1hdr.b_buf, ==, NULL);
		ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);
		(void) refcount_add_many(&state->arcs_esize[type],
		    HDR_GET_LSIZE(hdr), hdr);
		return;
	}

	ASSERT(!GHOST_STATE(state));
	if (hdr->b_l1hdr.b_pabd != NULL) {
		(void) refcount_add_many(&state->arcs_esize[type],
		    arc_hdr_size(hdr), hdr);
	}
	for (arc_buf_t *buf = hdr->b_l1hdr.b_buf; buf != NULL;
	    buf = buf->b_next) {
		if (arc_buf_is_shared(buf))
			continue;
		(void) refcount_add_many(&state->arcs_esize[type],
		    arc_buf_size(buf), buf);
	}
}

/*
 * Decrement the amount of evictable space in the arc_state_t's refcount.
 * We account for the space used by the hdr and the arc buf individually
 * so that we can add and remove them from the refcount individually.
 */
static void
arc_evictable_space_decrement(arc_buf_hdr_t *hdr, arc_state_t *state)
{
	arc_buf_contents_t type = arc_buf_type(hdr);

	ASSERT(HDR_HAS_L1HDR(hdr));

	if (GHOST_STATE(state)) {
		ASSERT0(hdr->b_l1hdr.b_bufcnt);
		ASSERT3P(hdr->b_l1hdr.b_buf, ==, NULL);
		ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);
		(void) refcount_remove_many(&state->arcs_esize[type],
		    HDR_GET_LSIZE(hdr), hdr);
		return;
	}

	ASSERT(!GHOST_STATE(state));
	if (hdr->b_l1hdr.b_pabd != NULL) {
		(void) refcount_remove_many(&state->arcs_esize[type],
		    arc_hdr_size(hdr), hdr);
	}
	for (arc_buf_t *buf = hdr->b_l1hdr.b_buf; buf != NULL;
	    buf = buf->b_next) {
		if (arc_buf_is_shared(buf))
			continue;
		(void) refcount_remove_many(&state->arcs_esize[type],
		    arc_buf_size(buf), buf);
	}
}

/*
 * Add a reference to this hdr indicating that someone is actively
 * referencing that memory. When the refcount transitions from 0 to 1,
 * we remove it from the respective arc_state_t list to indicate that
 * it is not evictable.
 */
static void
add_reference(arc_buf_hdr_t *hdr, void *tag)
{
	ASSERT(HDR_HAS_L1HDR(hdr));
	if (!MUTEX_HELD(HDR_LOCK(hdr))) {
		ASSERT(hdr->b_l1hdr.b_state == arc_anon);
		ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt));
		ASSERT3P(hdr->b_l1hdr.b_buf, ==, NULL);
	}

	arc_state_t *state = hdr->b_l1hdr.b_state;

	if ((refcount_add(&hdr->b_l1hdr.b_refcnt, tag) == 1) &&
	    (state != arc_anon)) {
		/* We don't use the L2-only state list. */
		if (state != arc_l2c_only) {
			multilist_remove(state->arcs_list[arc_buf_type(hdr)],
			    hdr);
			arc_evictable_space_decrement(hdr, state);
		}
		/* remove the prefetch flag if we get a reference */
		arc_hdr_clear_flags(hdr, ARC_FLAG_PREFETCH);
	}
}

/*
 * Remove a reference from this hdr. When the reference transitions from
 * 1 to 0 and we're not anonymous, then we add this hdr to the arc_state_t's
 * list making it eligible for eviction.
 */
static int
remove_reference(arc_buf_hdr_t *hdr, kmutex_t *hash_lock, void *tag)
{
	int cnt;
	arc_state_t *state = hdr->b_l1hdr.b_state;

	ASSERT(HDR_HAS_L1HDR(hdr));
	ASSERT(state == arc_anon || MUTEX_HELD(hash_lock));
	ASSERT(!GHOST_STATE(state));

	/*
	 * arc_l2c_only counts as a ghost state so we don't need to explicitly
	 * check to prevent usage of the arc_l2c_only list.
	 */
	if (((cnt = refcount_remove(&hdr->b_l1hdr.b_refcnt, tag)) == 0) &&
	    (state != arc_anon)) {
		multilist_insert(state->arcs_list[arc_buf_type(hdr)], hdr);
		ASSERT3U(hdr->b_l1hdr.b_bufcnt, >, 0);
		arc_evictable_space_increment(hdr, state);
	}
	return (cnt);
}

/*
 * Move the supplied buffer to the indicated state. The hash lock
 * for the buffer must be held by the caller.
 */
static void
arc_change_state(arc_state_t *new_state, arc_buf_hdr_t *hdr,
    kmutex_t *hash_lock)
{
	arc_state_t *old_state;
	int64_t refcnt;
	uint32_t bufcnt;
	boolean_t update_old, update_new;
	arc_buf_contents_t buftype = arc_buf_type(hdr);

	/*
	 * We almost always have an L1 hdr here, since we call arc_hdr_realloc()
	 * in arc_read() when bringing a buffer out of the L2ARC.  However, the
	 * L1 hdr doesn't always exist when we change state to arc_anon before
	 * destroying a header, in which case reallocating to add the L1 hdr is
	 * pointless.
	 */
	if (HDR_HAS_L1HDR(hdr)) {
		old_state = hdr->b_l1hdr.b_state;
		refcnt = refcount_count(&hdr->b_l1hdr.b_refcnt);
		bufcnt = hdr->b_l1hdr.b_bufcnt;
		update_old = (bufcnt > 0 || hdr->b_l1hdr.b_pabd != NULL);
	} else {
		old_state = arc_l2c_only;
		refcnt = 0;
		bufcnt = 0;
		update_old = B_FALSE;
	}
	update_new = update_old;

	ASSERT(MUTEX_HELD(hash_lock));
	ASSERT3P(new_state, !=, old_state);
	ASSERT(!GHOST_STATE(new_state) || bufcnt == 0);
	ASSERT(old_state != arc_anon || bufcnt <= 1);

	/*
	 * If this buffer is evictable, transfer it from the
	 * old state list to the new state list.
	 */
	if (refcnt == 0) {
		if (old_state != arc_anon && old_state != arc_l2c_only) {
			ASSERT(HDR_HAS_L1HDR(hdr));
			multilist_remove(old_state->arcs_list[buftype], hdr);

			if (GHOST_STATE(old_state)) {
				ASSERT0(bufcnt);
				ASSERT3P(hdr->b_l1hdr.b_buf, ==, NULL);
				update_old = B_TRUE;
			}
			arc_evictable_space_decrement(hdr, old_state);
		}
		if (new_state != arc_anon && new_state != arc_l2c_only) {

			/*
			 * An L1 header always exists here, since if we're
			 * moving to some L1-cached state (i.e. not l2c_only or
			 * anonymous), we realloc the header to add an L1hdr
			 * beforehand.
			 */
			ASSERT(HDR_HAS_L1HDR(hdr));
			multilist_insert(new_state->arcs_list[buftype], hdr);

			if (GHOST_STATE(new_state)) {
				ASSERT0(bufcnt);
				ASSERT3P(hdr->b_l1hdr.b_buf, ==, NULL);
				update_new = B_TRUE;
			}
			arc_evictable_space_increment(hdr, new_state);
		}
	}

	ASSERT(!HDR_EMPTY(hdr));
	if (new_state == arc_anon && HDR_IN_HASH_TABLE(hdr)) {
		buf_hash_remove(hdr);
		arc_wait_for_short_holders(hdr);
	}

	/* adjust state sizes (ignore arc_l2c_only) */

	if (update_new && new_state != arc_l2c_only) {
		ASSERT(HDR_HAS_L1HDR(hdr));
		if (GHOST_STATE(new_state)) {
			ASSERT0(bufcnt);

			/*
			 * When moving a header to a ghost state, we first
			 * remove all arc buffers. Thus, we'll have a
			 * bufcnt of zero, and no arc buffer to use for
			 * the reference. As a result, we use the arc
			 * header pointer for the reference.
			 */
			(void) refcount_add_many(&new_state->arcs_size,
			    HDR_GET_LSIZE(hdr), hdr);
			ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);
		} else {
			uint32_t buffers = 0;

			/*
			 * Each individual buffer holds a unique reference,
			 * thus we must remove each of these references one
			 * at a time.
			 */
			for (arc_buf_t *buf = hdr->b_l1hdr.b_buf; buf != NULL;
			    buf = buf->b_next) {
				ASSERT3U(bufcnt, !=, 0);
				buffers++;

				/*
				 * When the arc_buf_t is sharing the data
				 * block with the hdr, the owner of the
				 * reference belongs to the hdr. Only
				 * add to the refcount if the arc_buf_t is
				 * not shared.
				 */
				if (arc_buf_is_shared(buf))
					continue;

				(void) refcount_add_many(&new_state->arcs_size,
				    arc_buf_size(buf), buf);
			}
			ASSERT3U(bufcnt, ==, buffers);

			if (hdr->b_l1hdr.b_pabd != NULL) {
				(void) refcount_add_many(&new_state->arcs_size,
				    arc_hdr_size(hdr), hdr);
			} else {
				ASSERT(GHOST_STATE(old_state));
			}
		}
	}

	if (update_old && old_state != arc_l2c_only) {
		ASSERT(HDR_HAS_L1HDR(hdr));
		if (GHOST_STATE(old_state)) {
			ASSERT0(bufcnt);
			ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);

			/*
			 * When moving a header off of a ghost state,
			 * the header will not contain any arc buffers.
			 * We use the arc header pointer for the reference
			 * which is exactly what we did when we put the
			 * header on the ghost state.
			 */

			(void) refcount_remove_many(&old_state->arcs_size,
			    HDR_GET_LSIZE(hdr), hdr);
		} else {
			uint32_t buffers = 0;

			/*
			 * Each individual buffer holds a unique reference,
			 * thus we must remove each of these references one
			 * at a time.
			 */
			for (arc_buf_t *buf = hdr->b_l1hdr.b_buf; buf != NULL;
			    buf = buf->b_next) {
				ASSERT3U(bufcnt, !=, 0);
				buffers++;

				/*
				 * When the arc_buf_t is sharing the data
				 * block with the hdr, the owner of the
				 * reference belongs to the hdr. Only
				 * add to the refcount if the arc_buf_t is
				 * not shared.
				 */
				if (arc_buf_is_shared(buf))
					continue;

				(void) refcount_remove_many(
				    &old_state->arcs_size, arc_buf_size(buf),
				    buf);
			}
			ASSERT3U(bufcnt, ==, buffers);
			ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);
			(void) refcount_remove_many(
			    &old_state->arcs_size, arc_hdr_size(hdr), hdr);
		}
	}

	if (HDR_HAS_L1HDR(hdr))
		hdr->b_l1hdr.b_state = new_state;

	/*
	 * L2 headers should never be on the L2 state list since they don't
	 * have L1 headers allocated.
	 */
	ASSERT(multilist_is_empty(arc_l2c_only->arcs_list[ARC_BUFC_DATA]));
	ASSERT(multilist_is_empty(arc_l2c_only->arcs_list[ARC_BUFC_METADATA]));
	ASSERT(multilist_is_empty(arc_l2c_only->arcs_list[ARC_BUFC_DDT]));
}

void
arc_space_consume(uint64_t space, arc_space_type_t type)
{
	ASSERT(type >= 0 && type < ARC_SPACE_NUMTYPES);

	switch (type) {
	case ARC_SPACE_DATA:
		aggsum_add(&astat_data_size, space);
		break;
	case ARC_SPACE_META:
		aggsum_add(&astat_metadata_size, space);
		break;
	case ARC_SPACE_DDT:
		aggsum_add(&astat_ddt_size, space);
		break;
	case ARC_SPACE_OTHER:
		aggsum_add(&astat_other_size, space);
		break;
	case ARC_SPACE_HDRS:
		aggsum_add(&astat_hdr_size, space);
		break;
	case ARC_SPACE_L2HDRS:
		aggsum_add(&astat_l2_hdr_size, space);
		break;
	}

	if (type != ARC_SPACE_DATA && type != ARC_SPACE_DDT)
		aggsum_add(&arc_meta_used, space);

	aggsum_add(&arc_size, space);
}

void
arc_space_return(uint64_t space, arc_space_type_t type)
{
	ASSERT(type >= 0 && type < ARC_SPACE_NUMTYPES);

	switch (type) {
	case ARC_SPACE_DATA:
		aggsum_add(&astat_data_size, -space);
		break;
	case ARC_SPACE_META:
		aggsum_add(&astat_metadata_size, -space);
		break;
	case ARC_SPACE_DDT:
		aggsum_add(&astat_ddt_size, -space);
		break;
	case ARC_SPACE_OTHER:
		aggsum_add(&astat_other_size, -space);
		break;
	case ARC_SPACE_HDRS:
		aggsum_add(&astat_hdr_size, -space);
		break;
	case ARC_SPACE_L2HDRS:
		aggsum_add(&astat_l2_hdr_size, -space);
		break;
	}

	if (type != ARC_SPACE_DATA && type != ARC_SPACE_DDT) {
		ASSERT(aggsum_compare(&arc_meta_used, space) >= 0);
		/*
		 * We use the upper bound here rather than the precise value
		 * because the arc_meta_max value doesn't need to be
		 * precise. It's only consumed by humans via arcstats.
		 */
		if (arc_meta_max < aggsum_upper_bound(&arc_meta_used))
			arc_meta_max = aggsum_upper_bound(&arc_meta_used);
		aggsum_add(&arc_meta_used, -space);
	}

	ASSERT(aggsum_compare(&arc_size, space) >= 0);
	aggsum_add(&arc_size, -space);
}

/*
 * Given a hdr and a buf, returns whether that buf can share its b_data buffer
 * with the hdr's b_pabd.
 */
static boolean_t
arc_can_share(arc_buf_hdr_t *hdr, arc_buf_t *buf)
{
	/*
	 * The criteria for sharing a hdr's data are:
	 * 1. the hdr's compression matches the buf's compression
	 * 2. the hdr doesn't need to be byteswapped
	 * 3. the hdr isn't already being shared
	 * 4. the buf is either compressed or it is the last buf in the hdr list
	 *
	 * Criterion #4 maintains the invariant that shared uncompressed
	 * bufs must be the final buf in the hdr's b_buf list. Reading this, you
	 * might ask, "if a compressed buf is allocated first, won't that be the
	 * last thing in the list?", but in that case it's impossible to create
	 * a shared uncompressed buf anyway (because the hdr must be compressed
	 * to have the compressed buf). You might also think that #3 is
	 * sufficient to make this guarantee, however it's possible
	 * (specifically in the rare L2ARC write race mentioned in
	 * arc_buf_alloc_impl()) there will be an existing uncompressed buf that
	 * is sharable, but wasn't at the time of its allocation. Rather than
	 * allow a new shared uncompressed buf to be created and then shuffle
	 * the list around to make it the last element, this simply disallows
	 * sharing if the new buf isn't the first to be added.
	 */
	ASSERT3P(buf->b_hdr, ==, hdr);
	boolean_t hdr_compressed = HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF;
	boolean_t buf_compressed = ARC_BUF_COMPRESSED(buf) != 0;
	return (buf_compressed == hdr_compressed &&
	    hdr->b_l1hdr.b_byteswap == DMU_BSWAP_NUMFUNCS &&
	    !HDR_SHARED_DATA(hdr) &&
	    (ARC_BUF_LAST(buf) || ARC_BUF_COMPRESSED(buf)));
}

/*
 * Allocate a buf for this hdr. If you care about the data that's in the hdr,
 * or if you want a compressed buffer, pass those flags in. Returns 0 if the
 * copy was made successfully, or an error code otherwise.
 */
static int
arc_buf_alloc_impl(arc_buf_hdr_t *hdr, void *tag, boolean_t compressed,
    boolean_t fill, arc_buf_t **ret)
{
	arc_buf_t *buf;

	ASSERT(HDR_HAS_L1HDR(hdr));
	ASSERT3U(HDR_GET_LSIZE(hdr), >, 0);
	VERIFY(hdr->b_type == ARC_BUFC_DATA ||
	    hdr->b_type == ARC_BUFC_METADATA ||
	    hdr->b_type == ARC_BUFC_DDT);
	ASSERT3P(ret, !=, NULL);
	ASSERT3P(*ret, ==, NULL);

	buf = *ret = kmem_cache_alloc(buf_cache, KM_PUSHPAGE);
	buf->b_hdr = hdr;
	buf->b_data = NULL;
	buf->b_next = hdr->b_l1hdr.b_buf;
	buf->b_flags = 0;

	add_reference(hdr, tag);

	/*
	 * We're about to change the hdr's b_flags. We must either
	 * hold the hash_lock or be undiscoverable.
	 */
	ASSERT(MUTEX_HELD(HDR_LOCK(hdr)) || HDR_EMPTY(hdr));

	/*
	 * Only honor requests for compressed bufs if the hdr is actually
	 * compressed.
	 */
	if (compressed && HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF)
		buf->b_flags |= ARC_BUF_FLAG_COMPRESSED;

	/*
	 * If the hdr's data can be shared then we share the data buffer and
	 * set the appropriate bit in the hdr's b_flags to indicate the hdr is
	 * sharing it's b_pabd with the arc_buf_t. Otherwise, we allocate a new
	 * buffer to store the buf's data.
	 *
	 * There are two additional restrictions here because we're sharing
	 * hdr -> buf instead of the usual buf -> hdr. First, the hdr can't be
	 * actively involved in an L2ARC write, because if this buf is used by
	 * an arc_write() then the hdr's data buffer will be released when the
	 * write completes, even though the L2ARC write might still be using it.
	 * Second, the hdr's ABD must be linear so that the buf's user doesn't
	 * need to be ABD-aware.
	 */
	boolean_t can_share = arc_can_share(hdr, buf) && !HDR_L2_WRITING(hdr) &&
	    abd_is_linear(hdr->b_l1hdr.b_pabd);

	/* Set up b_data and sharing */
	if (can_share) {
		buf->b_data = abd_to_buf(hdr->b_l1hdr.b_pabd);
		buf->b_flags |= ARC_BUF_FLAG_SHARED;
		arc_hdr_set_flags(hdr, ARC_FLAG_SHARED_DATA);
	} else {
		buf->b_data =
		    arc_get_data_buf(hdr, arc_buf_size(buf), buf);
		ARCSTAT_INCR(arcstat_overhead_size, arc_buf_size(buf));
	}
	VERIFY3P(buf->b_data, !=, NULL);

	hdr->b_l1hdr.b_buf = buf;
	hdr->b_l1hdr.b_bufcnt += 1;

	/*
	 * If the user wants the data from the hdr, we need to either copy or
	 * decompress the data.
	 */
	if (fill) {
		return (arc_buf_fill(buf, ARC_BUF_COMPRESSED(buf) != 0));
	}

	return (0);
}

static char *arc_onloan_tag = "onloan";

static inline void
arc_loaned_bytes_update(int64_t delta)
{
	atomic_add_64(&arc_loaned_bytes, delta);

	/* assert that it did not wrap around */
	ASSERT3S(atomic_add_64_nv(&arc_loaned_bytes, 0), >=, 0);
}

/*
 * Allocates an ARC buf header that's in an evicted & L2-cached state.
 * This is used during l2arc reconstruction to make empty ARC buffers
 * which circumvent the regular disk->arc->l2arc path and instead come
 * into being in the reverse order, i.e. l2arc->arc.
 */
static arc_buf_hdr_t *
arc_buf_alloc_l2only(uint64_t load_guid, arc_buf_contents_t type,
    l2arc_dev_t *dev, dva_t dva, uint64_t daddr, uint64_t lsize,
    uint64_t psize, uint64_t birth, zio_cksum_t cksum, int checksum_type,
    enum zio_compress compress, boolean_t arc_compress)
{
	arc_buf_hdr_t *hdr;

	if (type == ARC_BUFC_DDT && !zfs_arc_segregate_ddt)
		type = ARC_BUFC_METADATA;

	ASSERT(lsize != 0);
	hdr = kmem_cache_alloc(hdr_l2only_cache, KM_PUSHPAGE);
	ASSERT(HDR_EMPTY(hdr));
	ASSERT3P(hdr->b_freeze_cksum, ==, NULL);

	hdr->b_spa = load_guid;
	hdr->b_type = type;
	hdr->b_flags = 0;

	if (arc_compress)
		arc_hdr_set_flags(hdr, ARC_FLAG_COMPRESSED_ARC);
	else
		arc_hdr_clear_flags(hdr, ARC_FLAG_COMPRESSED_ARC);

	HDR_SET_COMPRESS(hdr, compress);

	arc_hdr_set_flags(hdr, arc_bufc_to_flags(type) | ARC_FLAG_HAS_L2HDR);
	hdr->b_dva = dva;
	hdr->b_birth = birth;
	if (checksum_type != ZIO_CHECKSUM_OFF) {
		hdr->b_freeze_cksum = kmem_alloc(sizeof (zio_cksum_t), KM_SLEEP);
		bcopy(&cksum, hdr->b_freeze_cksum, sizeof (cksum));
	}

	HDR_SET_PSIZE(hdr, psize);
	HDR_SET_LSIZE(hdr, lsize);

	hdr->b_l2hdr.b_dev = dev;
	hdr->b_l2hdr.b_daddr = daddr;

	return (hdr);
}

/*
 * Loan out an anonymous arc buffer. Loaned buffers are not counted as in
 * flight data by arc_tempreserve_space() until they are "returned". Loaned
 * buffers must be returned to the arc before they can be used by the DMU or
 * freed.
 */
arc_buf_t *
arc_loan_buf(spa_t *spa, boolean_t is_metadata, int size)
{
	arc_buf_t *buf = arc_alloc_buf(spa, arc_onloan_tag,
	    is_metadata ? ARC_BUFC_METADATA : ARC_BUFC_DATA, size);

	arc_loaned_bytes_update(size);

	return (buf);
}

arc_buf_t *
arc_loan_compressed_buf(spa_t *spa, uint64_t psize, uint64_t lsize,
    enum zio_compress compression_type)
{
	arc_buf_t *buf = arc_alloc_compressed_buf(spa, arc_onloan_tag,
	    psize, lsize, compression_type);

	arc_loaned_bytes_update(psize);

	return (buf);
}


/*
 * Return a loaned arc buffer to the arc.
 */
void
arc_return_buf(arc_buf_t *buf, void *tag)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;

	ASSERT3P(buf->b_data, !=, NULL);
	ASSERT(HDR_HAS_L1HDR(hdr));
	(void) refcount_add(&hdr->b_l1hdr.b_refcnt, tag);
	(void) refcount_remove(&hdr->b_l1hdr.b_refcnt, arc_onloan_tag);

	arc_loaned_bytes_update(-arc_buf_size(buf));
}

/* Detach an arc_buf from a dbuf (tag) */
void
arc_loan_inuse_buf(arc_buf_t *buf, void *tag)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;

	ASSERT3P(buf->b_data, !=, NULL);
	ASSERT(HDR_HAS_L1HDR(hdr));
	(void) refcount_add(&hdr->b_l1hdr.b_refcnt, arc_onloan_tag);
	(void) refcount_remove(&hdr->b_l1hdr.b_refcnt, tag);

	arc_loaned_bytes_update(arc_buf_size(buf));
}

static void
l2arc_free_abd_on_write(abd_t *abd, size_t size, arc_buf_contents_t type)
{
	l2arc_data_free_t *df = kmem_alloc(sizeof (*df), KM_SLEEP);

	df->l2df_abd = abd;
	df->l2df_size = size;
	df->l2df_type = type;
	mutex_enter(&l2arc_free_on_write_mtx);
	list_insert_head(l2arc_free_on_write, df);
	mutex_exit(&l2arc_free_on_write_mtx);
}

static void
arc_hdr_free_on_write(arc_buf_hdr_t *hdr)
{
	arc_state_t *state = hdr->b_l1hdr.b_state;
	arc_buf_contents_t type = arc_buf_type(hdr);
	uint64_t size = arc_hdr_size(hdr);

	/* protected by hash lock, if in the hash table */
	if (multilist_link_active(&hdr->b_l1hdr.b_arc_node)) {
		ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt));
		ASSERT(state != arc_anon && state != arc_l2c_only);

		(void) refcount_remove_many(&state->arcs_esize[type],
		    size, hdr);
	}
	(void) refcount_remove_many(&state->arcs_size, size, hdr);
	if (type == ARC_BUFC_DDT) {
		arc_space_return(size, ARC_SPACE_DDT);
	} else if (type == ARC_BUFC_METADATA) {
		arc_space_return(size, ARC_SPACE_META);
	} else {
		ASSERT(type == ARC_BUFC_DATA);
		arc_space_return(size, ARC_SPACE_DATA);
	}

	l2arc_free_abd_on_write(hdr->b_l1hdr.b_pabd, size, type);
}

/*
 * Share the arc_buf_t's data with the hdr. Whenever we are sharing the
 * data buffer, we transfer the refcount ownership to the hdr and update
 * the appropriate kstats.
 */
static void
arc_share_buf(arc_buf_hdr_t *hdr, arc_buf_t *buf)
{
	arc_state_t *state = hdr->b_l1hdr.b_state;

	ASSERT(arc_can_share(hdr, buf));
	ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);
	ASSERT(MUTEX_HELD(HDR_LOCK(hdr)) || HDR_EMPTY(hdr));

	/*
	 * Start sharing the data buffer. We transfer the
	 * refcount ownership to the hdr since it always owns
	 * the refcount whenever an arc_buf_t is shared.
	 */
	refcount_transfer_ownership(&state->arcs_size, buf, hdr);
	hdr->b_l1hdr.b_pabd = abd_get_from_buf(buf->b_data, arc_buf_size(buf));
	abd_take_ownership_of_buf(hdr->b_l1hdr.b_pabd,
	    !HDR_ISTYPE_DATA(hdr));
	arc_hdr_set_flags(hdr, ARC_FLAG_SHARED_DATA);
	buf->b_flags |= ARC_BUF_FLAG_SHARED;

	/*
	 * Since we've transferred ownership to the hdr we need
	 * to increment its compressed and uncompressed kstats and
	 * decrement the overhead size.
	 */
	ARCSTAT_INCR(arcstat_compressed_size, arc_hdr_size(hdr));
	ARCSTAT_INCR(arcstat_uncompressed_size, HDR_GET_LSIZE(hdr));
	ARCSTAT_INCR(arcstat_overhead_size, -arc_buf_size(buf));
}

static void
arc_unshare_buf(arc_buf_hdr_t *hdr, arc_buf_t *buf)
{
	arc_state_t *state = hdr->b_l1hdr.b_state;

	ASSERT(arc_buf_is_shared(buf));
	ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);
	ASSERT(MUTEX_HELD(HDR_LOCK(hdr)) || HDR_EMPTY(hdr));

	/*
	 * We are no longer sharing this buffer so we need
	 * to transfer its ownership to the rightful owner.
	 */
	refcount_transfer_ownership(&state->arcs_size, hdr, buf);
	arc_hdr_clear_flags(hdr, ARC_FLAG_SHARED_DATA);
	abd_release_ownership_of_buf(hdr->b_l1hdr.b_pabd);
	abd_put(hdr->b_l1hdr.b_pabd);
	hdr->b_l1hdr.b_pabd = NULL;
	buf->b_flags &= ~ARC_BUF_FLAG_SHARED;

	/*
	 * Since the buffer is no longer shared between
	 * the arc buf and the hdr, count it as overhead.
	 */
	ARCSTAT_INCR(arcstat_compressed_size, -arc_hdr_size(hdr));
	ARCSTAT_INCR(arcstat_uncompressed_size, -HDR_GET_LSIZE(hdr));
	ARCSTAT_INCR(arcstat_overhead_size, arc_buf_size(buf));
}

/*
 * Remove an arc_buf_t from the hdr's buf list and return the last
 * arc_buf_t on the list. If no buffers remain on the list then return
 * NULL.
 */
static arc_buf_t *
arc_buf_remove(arc_buf_hdr_t *hdr, arc_buf_t *buf)
{
	ASSERT(HDR_HAS_L1HDR(hdr));
	ASSERT(MUTEX_HELD(HDR_LOCK(hdr)) || HDR_EMPTY(hdr));

	arc_buf_t **bufp = &hdr->b_l1hdr.b_buf;
	arc_buf_t *lastbuf = NULL;

	/*
	 * Remove the buf from the hdr list and locate the last
	 * remaining buffer on the list.
	 */
	while (*bufp != NULL) {
		if (*bufp == buf)
			*bufp = buf->b_next;

		/*
		 * If we've removed a buffer in the middle of
		 * the list then update the lastbuf and update
		 * bufp.
		 */
		if (*bufp != NULL) {
			lastbuf = *bufp;
			bufp = &(*bufp)->b_next;
		}
	}
	buf->b_next = NULL;
	ASSERT3P(lastbuf, !=, buf);
	IMPLY(hdr->b_l1hdr.b_bufcnt > 0, lastbuf != NULL);
	IMPLY(hdr->b_l1hdr.b_bufcnt > 0, hdr->b_l1hdr.b_buf != NULL);
	IMPLY(lastbuf != NULL, ARC_BUF_LAST(lastbuf));

	return (lastbuf);
}

/*
 * Free up buf->b_data and pull the arc_buf_t off of the the arc_buf_hdr_t's
 * list and free it.
 */
static void
arc_buf_destroy_impl(arc_buf_t *buf)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;

	/*
	 * Free up the data associated with the buf but only if we're not
	 * sharing this with the hdr. If we are sharing it with the hdr, the
	 * hdr is responsible for doing the free.
	 */
	if (buf->b_data != NULL) {
		/*
		 * We're about to change the hdr's b_flags. We must either
		 * hold the hash_lock or be undiscoverable.
		 */
		ASSERT(MUTEX_HELD(HDR_LOCK(hdr)) || HDR_EMPTY(hdr));

		arc_cksum_verify(buf);
		arc_buf_unwatch(buf);

		if (arc_buf_is_shared(buf)) {
			arc_hdr_clear_flags(hdr, ARC_FLAG_SHARED_DATA);
		} else {
			uint64_t size = arc_buf_size(buf);
			arc_free_data_buf(hdr, buf->b_data, size, buf);
			ARCSTAT_INCR(arcstat_overhead_size, -size);
		}
		buf->b_data = NULL;

		ASSERT(hdr->b_l1hdr.b_bufcnt > 0);
		hdr->b_l1hdr.b_bufcnt -= 1;
	}

	arc_buf_t *lastbuf = arc_buf_remove(hdr, buf);

	if (ARC_BUF_SHARED(buf) && !ARC_BUF_COMPRESSED(buf)) {
		/*
		 * If the current arc_buf_t is sharing its data buffer with the
		 * hdr, then reassign the hdr's b_pabd to share it with the new
		 * buffer at the end of the list. The shared buffer is always
		 * the last one on the hdr's buffer list.
		 *
		 * There is an equivalent case for compressed bufs, but since
		 * they aren't guaranteed to be the last buf in the list and
		 * that is an exceedingly rare case, we just allow that space be
		 * wasted temporarily.
		 */
		if (lastbuf != NULL) {
			/* Only one buf can be shared at once */
			VERIFY(!arc_buf_is_shared(lastbuf));
			/* hdr is uncompressed so can't have compressed buf */
			VERIFY(!ARC_BUF_COMPRESSED(lastbuf));

			ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);
			arc_hdr_free_pabd(hdr);

			/*
			 * We must setup a new shared block between the
			 * last buffer and the hdr. The data would have
			 * been allocated by the arc buf so we need to transfer
			 * ownership to the hdr since it's now being shared.
			 */
			arc_share_buf(hdr, lastbuf);
		}
	} else if (HDR_SHARED_DATA(hdr)) {
		/*
		 * Uncompressed shared buffers are always at the end
		 * of the list. Compressed buffers don't have the
		 * same requirements. This makes it hard to
		 * simply assert that the lastbuf is shared so
		 * we rely on the hdr's compression flags to determine
		 * if we have a compressed, shared buffer.
		 */
		ASSERT3P(lastbuf, !=, NULL);
		ASSERT(arc_buf_is_shared(lastbuf) ||
		    HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF);
	}

	/*
	 * Free the checksum if we're removing the last uncompressed buf from
	 * this hdr.
	 */
	if (!arc_hdr_has_uncompressed_buf(hdr)) {
		arc_cksum_free(hdr);
	}

	/* clean up the buf */
	buf->b_hdr = NULL;
	kmem_cache_free(buf_cache, buf);
}

static void
arc_hdr_alloc_pabd(arc_buf_hdr_t *hdr)
{
	ASSERT3U(HDR_GET_LSIZE(hdr), >, 0);
	ASSERT(HDR_HAS_L1HDR(hdr));
	ASSERT(!HDR_SHARED_DATA(hdr));

	ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);
	hdr->b_l1hdr.b_pabd = arc_get_data_abd(hdr, arc_hdr_size(hdr), hdr);
	hdr->b_l1hdr.b_byteswap = DMU_BSWAP_NUMFUNCS;
	ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);

	ARCSTAT_INCR(arcstat_compressed_size, arc_hdr_size(hdr));
	ARCSTAT_INCR(arcstat_uncompressed_size, HDR_GET_LSIZE(hdr));
	arc_update_hit_stat(hdr, B_TRUE);
}

static void
arc_hdr_free_pabd(arc_buf_hdr_t *hdr)
{
	ASSERT(HDR_HAS_L1HDR(hdr));
	ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);

	/*
	 * If the hdr is currently being written to the l2arc then
	 * we defer freeing the data by adding it to the l2arc_free_on_write
	 * list. The l2arc will free the data once it's finished
	 * writing it to the l2arc device.
	 */
	if (HDR_L2_WRITING(hdr)) {
		arc_hdr_free_on_write(hdr);
		ARCSTAT_BUMP(arcstat_l2_free_on_write);
	} else {
		arc_free_data_abd(hdr, hdr->b_l1hdr.b_pabd,
		    arc_hdr_size(hdr), hdr);
	}
	hdr->b_l1hdr.b_pabd = NULL;
	hdr->b_l1hdr.b_byteswap = DMU_BSWAP_NUMFUNCS;

	ARCSTAT_INCR(arcstat_compressed_size, -arc_hdr_size(hdr));
	ARCSTAT_INCR(arcstat_uncompressed_size, -HDR_GET_LSIZE(hdr));
}

static arc_buf_hdr_t *
arc_hdr_alloc(uint64_t spa, int32_t psize, int32_t lsize,
    enum zio_compress compression_type, arc_buf_contents_t type)
{
	arc_buf_hdr_t *hdr;

	ASSERT3U(lsize, >, 0);

	if (type == ARC_BUFC_DDT && !zfs_arc_segregate_ddt)
		type = ARC_BUFC_METADATA;
	VERIFY(type == ARC_BUFC_DATA || type == ARC_BUFC_METADATA ||
	    type == ARC_BUFC_DDT);

	hdr = kmem_cache_alloc(hdr_full_cache, KM_PUSHPAGE);
	ASSERT(HDR_EMPTY(hdr));
	ASSERT3P(hdr->b_freeze_cksum, ==, NULL);
	ASSERT3P(hdr->b_l1hdr.b_thawed, ==, NULL);
	HDR_SET_PSIZE(hdr, psize);
	HDR_SET_LSIZE(hdr, lsize);
	hdr->b_spa = spa;
	hdr->b_type = type;
	hdr->b_flags = 0;
	arc_hdr_set_flags(hdr, arc_bufc_to_flags(type) | ARC_FLAG_HAS_L1HDR);
	arc_hdr_set_compress(hdr, compression_type);

	hdr->b_l1hdr.b_state = arc_anon;
	hdr->b_l1hdr.b_arc_access = 0;
	hdr->b_l1hdr.b_bufcnt = 0;
	hdr->b_l1hdr.b_buf = NULL;

	/*
	 * Allocate the hdr's buffer. This will contain either
	 * the compressed or uncompressed data depending on the block
	 * it references and compressed arc enablement.
	 */
	arc_hdr_alloc_pabd(hdr);
	ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt));

	return (hdr);
}

/*
 * Transition between the two allocation states for the arc_buf_hdr struct.
 * The arc_buf_hdr struct can be allocated with (hdr_full_cache) or without
 * (hdr_l2only_cache) the fields necessary for the L1 cache - the smaller
 * version is used when a cache buffer is only in the L2ARC in order to reduce
 * memory usage.
 */
static arc_buf_hdr_t *
arc_hdr_realloc(arc_buf_hdr_t *hdr, kmem_cache_t *old, kmem_cache_t *new)
{
	ASSERT(HDR_HAS_L2HDR(hdr));

	arc_buf_hdr_t *nhdr;
	l2arc_dev_t *dev = hdr->b_l2hdr.b_dev;

	ASSERT((old == hdr_full_cache && new == hdr_l2only_cache) ||
	    (old == hdr_l2only_cache && new == hdr_full_cache));

	nhdr = kmem_cache_alloc(new, KM_PUSHPAGE);

	ASSERT(MUTEX_HELD(HDR_LOCK(hdr)));
	buf_hash_remove(hdr);

	bcopy(hdr, nhdr, HDR_L2ONLY_SIZE);

	if (new == hdr_full_cache) {
		arc_hdr_set_flags(nhdr, ARC_FLAG_HAS_L1HDR);
		/*
		 * arc_access and arc_change_state need to be aware that a
		 * header has just come out of L2ARC, so we set its state to
		 * l2c_only even though it's about to change.
		 */
		nhdr->b_l1hdr.b_state = arc_l2c_only;

		/* Verify previous threads set to NULL before freeing */
		ASSERT3P(nhdr->b_l1hdr.b_pabd, ==, NULL);
	} else {
		ASSERT3P(hdr->b_l1hdr.b_buf, ==, NULL);
		ASSERT0(hdr->b_l1hdr.b_bufcnt);
		ASSERT3P(hdr->b_freeze_cksum, ==, NULL);

		/*
		 * If we've reached here, We must have been called from
		 * arc_evict_hdr(), as such we should have already been
		 * removed from any ghost list we were previously on
		 * (which protects us from racing with arc_evict_state),
		 * thus no locking is needed during this check.
		 */
		ASSERT(!multilist_link_active(&hdr->b_l1hdr.b_arc_node));

		/*
		 * A buffer must not be moved into the arc_l2c_only
		 * state if it's not finished being written out to the
		 * l2arc device. Otherwise, the b_l1hdr.b_pabd field
		 * might try to be accessed, even though it was removed.
		 */
		VERIFY(!HDR_L2_WRITING(hdr));
		VERIFY3P(hdr->b_l1hdr.b_pabd, ==, NULL);

#ifdef ZFS_DEBUG
		if (hdr->b_l1hdr.b_thawed != NULL) {
			kmem_free(hdr->b_l1hdr.b_thawed, 1);
			hdr->b_l1hdr.b_thawed = NULL;
		}
#endif

		arc_hdr_clear_flags(nhdr, ARC_FLAG_HAS_L1HDR);
	}
	/*
	 * The header has been reallocated so we need to re-insert it into any
	 * lists it was on.
	 */
	(void) buf_hash_insert(nhdr, NULL);

	ASSERT(list_link_active(&hdr->b_l2hdr.b_l2node));

	mutex_enter(&dev->l2ad_mtx);

	/*
	 * We must place the realloc'ed header back into the list at
	 * the same spot. Otherwise, if it's placed earlier in the list,
	 * l2arc_write_buffers() could find it during the function's
	 * write phase, and try to write it out to the l2arc.
	 */
	list_insert_after(&dev->l2ad_buflist, hdr, nhdr);
	list_remove(&dev->l2ad_buflist, hdr);

	mutex_exit(&dev->l2ad_mtx);

	/*
	 * Since we're using the pointer address as the tag when
	 * incrementing and decrementing the l2ad_alloc refcount, we
	 * must remove the old pointer (that we're about to destroy) and
	 * add the new pointer to the refcount. Otherwise we'd remove
	 * the wrong pointer address when calling arc_hdr_destroy() later.
	 */

	(void) refcount_remove_many(&dev->l2ad_alloc, arc_hdr_size(hdr), hdr);
	(void) refcount_add_many(&dev->l2ad_alloc, arc_hdr_size(nhdr), nhdr);

	buf_discard_identity(hdr);
	kmem_cache_free(old, hdr);

	return (nhdr);
}

/*
 * Allocate a new arc_buf_hdr_t and arc_buf_t and return the buf to the caller.
 * The buf is returned thawed since we expect the consumer to modify it.
 */
arc_buf_t *
arc_alloc_buf(spa_t *spa, void *tag, arc_buf_contents_t type, int32_t size)
{
	arc_buf_hdr_t *hdr = arc_hdr_alloc(spa_load_guid(spa), size, size,
	    ZIO_COMPRESS_OFF, type);
	ASSERT(!MUTEX_HELD(HDR_LOCK(hdr)));

	arc_buf_t *buf = NULL;
	VERIFY0(arc_buf_alloc_impl(hdr, tag, B_FALSE, B_FALSE, &buf));
	arc_buf_thaw(buf);

	return (buf);
}

/*
 * Allocate a compressed buf in the same manner as arc_alloc_buf. Don't use this
 * for bufs containing metadata.
 */
arc_buf_t *
arc_alloc_compressed_buf(spa_t *spa, void *tag, uint64_t psize, uint64_t lsize,
    enum zio_compress compression_type)
{
	ASSERT3U(lsize, >, 0);
	ASSERT3U(lsize, >=, psize);
	ASSERT(compression_type > ZIO_COMPRESS_OFF);
	ASSERT(compression_type < ZIO_COMPRESS_FUNCTIONS);

	arc_buf_hdr_t *hdr = arc_hdr_alloc(spa_load_guid(spa), psize, lsize,
	    compression_type, ARC_BUFC_DATA);
	ASSERT(!MUTEX_HELD(HDR_LOCK(hdr)));

	arc_buf_t *buf = NULL;
	VERIFY0(arc_buf_alloc_impl(hdr, tag, B_TRUE, B_FALSE, &buf));
	arc_buf_thaw(buf);
	ASSERT3P(hdr->b_freeze_cksum, ==, NULL);

	if (!arc_buf_is_shared(buf)) {
		/*
		 * To ensure that the hdr has the correct data in it if we call
		 * arc_decompress() on this buf before it's been written to
		 * disk, it's easiest if we just set up sharing between the
		 * buf and the hdr.
		 */
		ASSERT(!abd_is_linear(hdr->b_l1hdr.b_pabd));
		arc_hdr_free_pabd(hdr);
		arc_share_buf(hdr, buf);
	}

	return (buf);
}

static void
arc_hdr_l2hdr_destroy(arc_buf_hdr_t *hdr)
{
	l2arc_buf_hdr_t *l2hdr = &hdr->b_l2hdr;
	l2arc_dev_t *dev = l2hdr->b_dev;
	uint64_t psize = arc_hdr_size(hdr);

	ASSERT(MUTEX_HELD(&dev->l2ad_mtx));
	ASSERT(HDR_HAS_L2HDR(hdr));

	list_remove(&dev->l2ad_buflist, hdr);

	ARCSTAT_INCR(arcstat_l2_psize, -psize);
	ARCSTAT_INCR(arcstat_l2_lsize, -HDR_GET_LSIZE(hdr));

	/*
	 * l2ad_vdev can be NULL here if we async evicted it
	 */
	if (dev->l2ad_vdev != NULL)
		vdev_space_update(dev->l2ad_vdev, -psize, 0, 0);

	(void) refcount_remove_many(&dev->l2ad_alloc, psize, hdr);
	arc_hdr_clear_flags(hdr, ARC_FLAG_HAS_L2HDR);
}

static void
arc_hdr_destroy(arc_buf_hdr_t *hdr)
{
	if (HDR_HAS_L1HDR(hdr)) {
		ASSERT(hdr->b_l1hdr.b_buf == NULL ||
		    hdr->b_l1hdr.b_bufcnt > 0);
		ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt));
		ASSERT3P(hdr->b_l1hdr.b_state, ==, arc_anon);
	}
	ASSERT(!HDR_IO_IN_PROGRESS(hdr));
	ASSERT(!HDR_IN_HASH_TABLE(hdr));

	if (HDR_HAS_L2HDR(hdr)) {
		l2arc_dev_t *dev = hdr->b_l2hdr.b_dev;
		boolean_t buflist_held = MUTEX_HELD(&dev->l2ad_mtx);

		/* To avoid racing with L2ARC the header needs to be locked */
		ASSERT(MUTEX_HELD(HDR_LOCK(hdr)));

		if (!buflist_held)
			mutex_enter(&dev->l2ad_mtx);

		/*
		 * L2ARC buflist has been held, so we can safety discard
		 * identity, otherwise L2ARC can lock incorrect mutex
		 * for the hdr, that will cause a panic. That is possible,
		 * because a mutex is selected according to identity.
		 */
		if (!HDR_EMPTY(hdr))
			buf_discard_identity(hdr);

		/*
		 * Even though we checked this conditional above, we
		 * need to check this again now that we have the
		 * l2ad_mtx. This is because we could be racing with
		 * another thread calling l2arc_evict() which might have
		 * destroyed this header's L2 portion as we were waiting
		 * to acquire the l2ad_mtx. If that happens, we don't
		 * want to re-destroy the header's L2 portion.
		 */
		if (HDR_HAS_L2HDR(hdr))
			arc_hdr_l2hdr_destroy(hdr);

		if (!buflist_held)
			mutex_exit(&dev->l2ad_mtx);
	}

	if (!HDR_EMPTY(hdr))
		buf_discard_identity(hdr);

	if (HDR_HAS_L1HDR(hdr)) {
		arc_cksum_free(hdr);

		while (hdr->b_l1hdr.b_buf != NULL)
			arc_buf_destroy_impl(hdr->b_l1hdr.b_buf);

#ifdef ZFS_DEBUG
		if (hdr->b_l1hdr.b_thawed != NULL) {
			kmem_free(hdr->b_l1hdr.b_thawed, 1);
			hdr->b_l1hdr.b_thawed = NULL;
		}
#endif

		if (hdr->b_l1hdr.b_pabd != NULL) {
			arc_hdr_free_pabd(hdr);
		}
	}

	ASSERT3P(hdr->b_hash_next, ==, NULL);
	if (HDR_HAS_L1HDR(hdr)) {
		ASSERT(!multilist_link_active(&hdr->b_l1hdr.b_arc_node));
		ASSERT3P(hdr->b_l1hdr.b_acb, ==, NULL);
		kmem_cache_free(hdr_full_cache, hdr);
	} else {
		kmem_cache_free(hdr_l2only_cache, hdr);
	}
}

void
arc_buf_destroy(arc_buf_t *buf, void* tag)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	kmutex_t *hash_lock = HDR_LOCK(hdr);

	if (hdr->b_l1hdr.b_state == arc_anon) {
		ASSERT3U(hdr->b_l1hdr.b_bufcnt, ==, 1);
		ASSERT(!HDR_IO_IN_PROGRESS(hdr));
		VERIFY0(remove_reference(hdr, NULL, tag));
		arc_hdr_destroy(hdr);
		return;
	}

	mutex_enter(hash_lock);
	ASSERT3P(hdr, ==, buf->b_hdr);
	ASSERT(hdr->b_l1hdr.b_bufcnt > 0);
	ASSERT3P(hash_lock, ==, HDR_LOCK(hdr));
	ASSERT3P(hdr->b_l1hdr.b_state, !=, arc_anon);
	ASSERT3P(buf->b_data, !=, NULL);

	(void) remove_reference(hdr, hash_lock, tag);
	arc_buf_destroy_impl(buf);
	mutex_exit(hash_lock);
}

/*
 * Evict the arc_buf_hdr that is provided as a parameter. The resultant
 * state of the header is dependent on it's state prior to entering this
 * function. The following transitions are possible:
 *
 *    - arc_mru -> arc_mru_ghost
 *    - arc_mfu -> arc_mfu_ghost
 *    - arc_mru_ghost -> arc_l2c_only
 *    - arc_mru_ghost -> deleted
 *    - arc_mfu_ghost -> arc_l2c_only
 *    - arc_mfu_ghost -> deleted
 */
static int64_t
arc_evict_hdr(arc_buf_hdr_t *hdr, kmutex_t *hash_lock)
{
	arc_state_t *evicted_state, *state;
	int64_t bytes_evicted = 0;

	ASSERT(MUTEX_HELD(hash_lock));
	ASSERT(HDR_HAS_L1HDR(hdr));

	/* No reason to wait for holders */
	if (hdr->b_l1hdr.b_short_holders != 0)
		return (0);

	state = hdr->b_l1hdr.b_state;
	if (GHOST_STATE(state)) {
		ASSERT(!HDR_IO_IN_PROGRESS(hdr));
		ASSERT3P(hdr->b_l1hdr.b_buf, ==, NULL);

		/*
		 * l2arc_write_buffers() relies on a header's L1 portion
		 * (i.e. its b_pabd field) during it's write phase.
		 * Thus, we cannot push a header onto the arc_l2c_only
		 * state (removing it's L1 piece) until the header is
		 * done being written to the l2arc.
		 */
		if (HDR_HAS_L2HDR(hdr) && HDR_L2_WRITING(hdr)) {
			ARCSTAT_BUMP(arcstat_evict_l2_skip);
			return (bytes_evicted);
		}

		ARCSTAT_BUMP(arcstat_deleted);
		bytes_evicted += HDR_GET_LSIZE(hdr);

		DTRACE_PROBE1(arc__delete, arc_buf_hdr_t *, hdr);

		ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);
		if (HDR_HAS_L2HDR(hdr)) {
			/*
			 * This buffer is cached on the 2nd Level ARC;
			 * don't destroy the header.
			 */
			arc_change_state(arc_l2c_only, hdr, hash_lock);
			/*
			 * dropping from L1+L2 cached to L2-only,
			 * realloc to remove the L1 header.
			 */
			hdr = arc_hdr_realloc(hdr, hdr_full_cache,
			    hdr_l2only_cache);
		} else {
			arc_change_state(arc_anon, hdr, hash_lock);
			arc_hdr_destroy(hdr);
		}
		return (bytes_evicted);
	}

	ASSERT(state == arc_mru || state == arc_mfu);
	evicted_state = (state == arc_mru) ? arc_mru_ghost : arc_mfu_ghost;

	/* prefetch buffers have a minimum lifespan */
	if (HDR_IO_IN_PROGRESS(hdr) ||
	    ((hdr->b_flags & (ARC_FLAG_PREFETCH | ARC_FLAG_INDIRECT)) &&
	    ddi_get_lbolt() - hdr->b_l1hdr.b_arc_access <
	    arc_min_prefetch_lifespan)) {
		ARCSTAT_BUMP(arcstat_evict_skip);
		return (bytes_evicted);
	}

	ASSERT0(refcount_count(&hdr->b_l1hdr.b_refcnt));
	while (hdr->b_l1hdr.b_buf) {
		arc_buf_t *buf = hdr->b_l1hdr.b_buf;
		if (!mutex_tryenter(&buf->b_evict_lock)) {
			ARCSTAT_BUMP(arcstat_mutex_miss);
			break;
		}
		if (buf->b_data != NULL)
			bytes_evicted += HDR_GET_LSIZE(hdr);
		mutex_exit(&buf->b_evict_lock);
		arc_buf_destroy_impl(buf);
	}

	if (HDR_HAS_L2HDR(hdr)) {
		ARCSTAT_INCR(arcstat_evict_l2_cached, HDR_GET_LSIZE(hdr));
	} else {
		if (l2arc_write_eligible(hdr->b_spa, hdr)) {
			ARCSTAT_INCR(arcstat_evict_l2_eligible,
			    HDR_GET_LSIZE(hdr));
		} else {
			ARCSTAT_INCR(arcstat_evict_l2_ineligible,
			    HDR_GET_LSIZE(hdr));
		}
	}

	if (hdr->b_l1hdr.b_bufcnt == 0) {
		arc_cksum_free(hdr);

		bytes_evicted += arc_hdr_size(hdr);

		/*
		 * If this hdr is being evicted and has a compressed
		 * buffer then we discard it here before we change states.
		 * This ensures that the accounting is updated correctly
		 * in arc_free_data_impl().
		 */
		arc_hdr_free_pabd(hdr);

		arc_change_state(evicted_state, hdr, hash_lock);
		ASSERT(HDR_IN_HASH_TABLE(hdr));
		arc_hdr_set_flags(hdr, ARC_FLAG_IN_HASH_TABLE);
		DTRACE_PROBE1(arc__evict, arc_buf_hdr_t *, hdr);
	}

	return (bytes_evicted);
}

static uint64_t
arc_evict_state_impl(multilist_t *ml, int idx, arc_buf_hdr_t *marker,
    uint64_t spa, int64_t bytes)
{
	multilist_sublist_t *mls;
	uint64_t bytes_evicted = 0;
	arc_buf_hdr_t *hdr;
	kmutex_t *hash_lock;
	int evict_count = 0;

	ASSERT3P(marker, !=, NULL);
	IMPLY(bytes < 0, bytes == ARC_EVICT_ALL);

	mls = multilist_sublist_lock(ml, idx);

	for (hdr = multilist_sublist_prev(mls, marker); hdr != NULL;
	    hdr = multilist_sublist_prev(mls, marker)) {
		if ((bytes != ARC_EVICT_ALL && bytes_evicted >= bytes) ||
		    (evict_count >= zfs_arc_evict_batch_limit))
			break;

		/*
		 * To keep our iteration location, move the marker
		 * forward. Since we're not holding hdr's hash lock, we
		 * must be very careful and not remove 'hdr' from the
		 * sublist. Otherwise, other consumers might mistake the
		 * 'hdr' as not being on a sublist when they call the
		 * multilist_link_active() function (they all rely on
		 * the hash lock protecting concurrent insertions and
		 * removals). multilist_sublist_move_forward() was
		 * specifically implemented to ensure this is the case
		 * (only 'marker' will be removed and re-inserted).
		 */
		multilist_sublist_move_forward(mls, marker);

		/*
		 * The only case where the b_spa field should ever be
		 * zero, is the marker headers inserted by
		 * arc_evict_state(). It's possible for multiple threads
		 * to be calling arc_evict_state() concurrently (e.g.
		 * dsl_pool_close() and zio_inject_fault()), so we must
		 * skip any markers we see from these other threads.
		 */
		if (hdr->b_spa == 0)
			continue;

		/* we're only interested in evicting buffers of a certain spa */
		if (spa != 0 && hdr->b_spa != spa) {
			ARCSTAT_BUMP(arcstat_evict_skip);
			continue;
		}

		hash_lock = HDR_LOCK(hdr);

		/*
		 * We aren't calling this function from any code path
		 * that would already be holding a hash lock, so we're
		 * asserting on this assumption to be defensive in case
		 * this ever changes. Without this check, it would be
		 * possible to incorrectly increment arcstat_mutex_miss
		 * below (e.g. if the code changed such that we called
		 * this function with a hash lock held).
		 */
		ASSERT(!MUTEX_HELD(hash_lock));

		if (mutex_tryenter(hash_lock)) {
			uint64_t evicted = arc_evict_hdr(hdr, hash_lock);
			mutex_exit(hash_lock);

			bytes_evicted += evicted;

			/*
			 * If evicted is zero, arc_evict_hdr() must have
			 * decided to skip this header, don't increment
			 * evict_count in this case.
			 */
			if (evicted != 0)
				evict_count++;

			/*
			 * If arc_size isn't overflowing, signal any
			 * threads that might happen to be waiting.
			 *
			 * For each header evicted, we wake up a single
			 * thread. If we used cv_broadcast, we could
			 * wake up "too many" threads causing arc_size
			 * to significantly overflow arc_c; since
			 * arc_get_data_impl() doesn't check for overflow
			 * when it's woken up (it doesn't because it's
			 * possible for the ARC to be overflowing while
			 * full of un-evictable buffers, and the
			 * function should proceed in this case).
			 *
			 * If threads are left sleeping, due to not
			 * using cv_broadcast, they will be woken up
			 * just before arc_reclaim_thread() sleeps.
			 */
			mutex_enter(&arc_reclaim_lock);
			if (!arc_is_overflowing())
				cv_signal(&arc_reclaim_waiters_cv);
			mutex_exit(&arc_reclaim_lock);
		} else {
			ARCSTAT_BUMP(arcstat_mutex_miss);
		}
	}

	multilist_sublist_unlock(mls);

	return (bytes_evicted);
}

/*
 * Evict buffers from the given arc state, until we've removed the
 * specified number of bytes. Move the removed buffers to the
 * appropriate evict state.
 *
 * This function makes a "best effort". It skips over any buffers
 * it can't get a hash_lock on, and so, may not catch all candidates.
 * It may also return without evicting as much space as requested.
 *
 * If bytes is specified using the special value ARC_EVICT_ALL, this
 * will evict all available (i.e. unlocked and evictable) buffers from
 * the given arc state; which is used by arc_flush().
 */
static uint64_t
arc_evict_state(arc_state_t *state, uint64_t spa, int64_t bytes,
    arc_buf_contents_t type)
{
	uint64_t total_evicted = 0;
	multilist_t *ml = state->arcs_list[type];
	int num_sublists;
	arc_buf_hdr_t **markers;

	IMPLY(bytes < 0, bytes == ARC_EVICT_ALL);

	num_sublists = multilist_get_num_sublists(ml);

	/*
	 * If we've tried to evict from each sublist, made some
	 * progress, but still have not hit the target number of bytes
	 * to evict, we want to keep trying. The markers allow us to
	 * pick up where we left off for each individual sublist, rather
	 * than starting from the tail each time.
	 */
	markers = kmem_zalloc(sizeof (*markers) * num_sublists, KM_SLEEP);
	for (int i = 0; i < num_sublists; i++) {
		markers[i] = kmem_cache_alloc(hdr_full_cache, KM_SLEEP);

		/*
		 * A b_spa of 0 is used to indicate that this header is
		 * a marker. This fact is used in arc_adjust_type() and
		 * arc_evict_state_impl().
		 */
		markers[i]->b_spa = 0;

		multilist_sublist_t *mls = multilist_sublist_lock(ml, i);
		multilist_sublist_insert_tail(mls, markers[i]);
		multilist_sublist_unlock(mls);
	}

	/*
	 * While we haven't hit our target number of bytes to evict, or
	 * we're evicting all available buffers.
	 */
	while (total_evicted < bytes || bytes == ARC_EVICT_ALL) {
		/*
		 * Start eviction using a randomly selected sublist,
		 * this is to try and evenly balance eviction across all
		 * sublists. Always starting at the same sublist
		 * (e.g. index 0) would cause evictions to favor certain
		 * sublists over others.
		 */
		int sublist_idx = multilist_get_random_index(ml);
		uint64_t scan_evicted = 0;

		for (int i = 0; i < num_sublists; i++) {
			uint64_t bytes_remaining;
			uint64_t bytes_evicted;

			if (bytes == ARC_EVICT_ALL)
				bytes_remaining = ARC_EVICT_ALL;
			else if (total_evicted < bytes)
				bytes_remaining = bytes - total_evicted;
			else
				break;

			bytes_evicted = arc_evict_state_impl(ml, sublist_idx,
			    markers[sublist_idx], spa, bytes_remaining);

			scan_evicted += bytes_evicted;
			total_evicted += bytes_evicted;

			/* we've reached the end, wrap to the beginning */
			if (++sublist_idx >= num_sublists)
				sublist_idx = 0;
		}

		/*
		 * If we didn't evict anything during this scan, we have
		 * no reason to believe we'll evict more during another
		 * scan, so break the loop.
		 */
		if (scan_evicted == 0) {
			/* This isn't possible, let's make that obvious */
			ASSERT3S(bytes, !=, 0);

			/*
			 * When bytes is ARC_EVICT_ALL, the only way to
			 * break the loop is when scan_evicted is zero.
			 * In that case, we actually have evicted enough,
			 * so we don't want to increment the kstat.
			 */
			if (bytes != ARC_EVICT_ALL) {
				ASSERT3S(total_evicted, <, bytes);
				ARCSTAT_BUMP(arcstat_evict_not_enough);
			}

			break;
		}
	}

	for (int i = 0; i < num_sublists; i++) {
		multilist_sublist_t *mls = multilist_sublist_lock(ml, i);
		multilist_sublist_remove(mls, markers[i]);
		multilist_sublist_unlock(mls);

		kmem_cache_free(hdr_full_cache, markers[i]);
	}
	kmem_free(markers, sizeof (*markers) * num_sublists);

	return (total_evicted);
}

/*
 * Flush all "evictable" data of the given type from the arc state
 * specified. This will not evict any "active" buffers (i.e. referenced).
 *
 * When 'retry' is set to B_FALSE, the function will make a single pass
 * over the state and evict any buffers that it can. Since it doesn't
 * continually retry the eviction, it might end up leaving some buffers
 * in the ARC due to lock misses.
 *
 * When 'retry' is set to B_TRUE, the function will continually retry the
 * eviction until *all* evictable buffers have been removed from the
 * state. As a result, if concurrent insertions into the state are
 * allowed (e.g. if the ARC isn't shutting down), this function might
 * wind up in an infinite loop, continually trying to evict buffers.
 */
static uint64_t
arc_flush_state(arc_state_t *state, uint64_t spa, arc_buf_contents_t type,
    boolean_t retry)
{
	uint64_t evicted = 0;

	while (refcount_count(&state->arcs_esize[type]) != 0) {
		evicted += arc_evict_state(state, spa, ARC_EVICT_ALL, type);

		if (!retry)
			break;
	}

	return (evicted);
}

/*
 * Evict the specified number of bytes from the state specified,
 * restricting eviction to the spa and type given. This function
 * prevents us from trying to evict more from a state's list than
 * is "evictable", and to skip evicting altogether when passed a
 * negative value for "bytes". In contrast, arc_evict_state() will
 * evict everything it can, when passed a negative value for "bytes".
 */
static uint64_t
arc_adjust_impl(arc_state_t *state, uint64_t spa, int64_t bytes,
    arc_buf_contents_t type)
{
	int64_t delta;

	if (bytes > 0 && refcount_count(&state->arcs_esize[type]) > 0) {
		delta = MIN(refcount_count(&state->arcs_esize[type]), bytes);
		return (arc_evict_state(state, spa, delta, type));
	}

	return (0);
}

/*
 * Depending on the value of adjust_ddt arg evict either DDT (B_TRUE)
 * or metadata (B_TRUE) buffers.
 * Evict metadata or DDT buffers from the cache, such that arc_meta_used or
 * astat_ddt_size is capped by the arc_meta_limit or arc_ddt_limit tunable.
 */
static uint64_t
arc_adjust_meta_or_ddt(uint64_t used, boolean_t adjust_ddt)
{
	uint64_t total_evicted = 0;
	int64_t target, over_limit;
	arc_buf_contents_t type;

	if (adjust_ddt) {
		over_limit = used - arc_ddt_limit;
		type = ARC_BUFC_DDT;
	} else {
		over_limit = used - arc_meta_limit;
		type = ARC_BUFC_METADATA;
	}

	/*
	 * If we're over the limit, we want to evict enough
	 * to get back under the limit. We don't want to
	 * evict so much that we drop the MRU below arc_p, though. If
	 * we're over the meta limit more than we're over arc_p, we
	 * evict some from the MRU here, and some from the MFU below.
	 */
	target = MIN(over_limit,
	    (int64_t)(refcount_count(&arc_anon->arcs_size) +
	    refcount_count(&arc_mru->arcs_size) - arc_p));

	total_evicted += arc_adjust_impl(arc_mru, 0, target, type);

#if 0
	// FIXME: upstream doesn't have such code, why ???
	over_limit = adjust_ddt ? arc_ddt_size - arc_ddt_limit :
	    arc_meta_used - arc_meta_limit;
#endif

	/*
	 * Similar to the above, we want to evict enough bytes to get us
	 * below the meta limit, but not so much as to drop us below the
	 * space allotted to the MFU (which is defined as arc_c - arc_p).
	 */
	target = MIN(over_limit,
	    (int64_t)(refcount_count(&arc_mfu->arcs_size) - (arc_c - arc_p)));

	total_evicted += arc_adjust_impl(arc_mfu, 0, target, type);

	return (total_evicted);
}

/*
 * Return the type of the oldest buffer in the given arc state
 *
 * This function will select a random sublists of type ARC_BUFC_DATA,
 * ARC_BUFC_METADATA, and ARC_BUFC_DDT. The tail of each sublist
 * is compared, and the type which contains the "older" buffer will be
 * returned.
 */
static arc_buf_contents_t
arc_adjust_type(arc_state_t *state)
{
	multilist_t *data_ml = state->arcs_list[ARC_BUFC_DATA];
	multilist_t *meta_ml = state->arcs_list[ARC_BUFC_METADATA];
	multilist_t *ddt_ml = state->arcs_list[ARC_BUFC_DDT];
	int data_idx = multilist_get_random_index(data_ml);
	int meta_idx = multilist_get_random_index(meta_ml);
	int ddt_idx = multilist_get_random_index(ddt_ml);
	multilist_sublist_t *data_mls;
	multilist_sublist_t *meta_mls;
	multilist_sublist_t *ddt_mls;
	arc_buf_contents_t type = ARC_BUFC_DATA; /* silence compiler warning */
	arc_buf_hdr_t *data_hdr;
	arc_buf_hdr_t *meta_hdr;
	arc_buf_hdr_t *ddt_hdr;
	clock_t	oldest;

	/*
	 * We keep the sublist lock until we're finished, to prevent
	 * the headers from being destroyed via arc_evict_state().
	 */
	data_mls = multilist_sublist_lock(data_ml, data_idx);
	meta_mls = multilist_sublist_lock(meta_ml, meta_idx);
	ddt_mls = multilist_sublist_lock(ddt_ml, ddt_idx);

	/*
	 * These two loops are to ensure we skip any markers that
	 * might be at the tail of the lists due to arc_evict_state().
	 */

	for (data_hdr = multilist_sublist_tail(data_mls); data_hdr != NULL;
	    data_hdr = multilist_sublist_prev(data_mls, data_hdr)) {
		if (data_hdr->b_spa != 0)
			break;
	}

	for (meta_hdr = multilist_sublist_tail(meta_mls); meta_hdr != NULL;
	    meta_hdr = multilist_sublist_prev(meta_mls, meta_hdr)) {
		if (meta_hdr->b_spa != 0)
			break;
	}

	for (ddt_hdr = multilist_sublist_tail(ddt_mls); ddt_hdr != NULL;
	    ddt_hdr = multilist_sublist_prev(ddt_mls, ddt_hdr)) {
		if (ddt_hdr->b_spa != 0)
			break;
	}

	if (data_hdr == NULL && meta_hdr == NULL && ddt_hdr == NULL) {
		type = ARC_BUFC_DATA;
	} else if (data_hdr != NULL && meta_hdr != NULL && ddt_hdr != NULL) {
		/* The headers can't be on the sublist without an L1 header */
		ASSERT(HDR_HAS_L1HDR(data_hdr));
		ASSERT(HDR_HAS_L1HDR(meta_hdr));
		ASSERT(HDR_HAS_L1HDR(ddt_hdr));

		oldest = data_hdr->b_l1hdr.b_arc_access;
		type = ARC_BUFC_DATA;
		if (oldest > meta_hdr->b_l1hdr.b_arc_access) {
			oldest = meta_hdr->b_l1hdr.b_arc_access;
			type = ARC_BUFC_METADATA;
		}
		if (oldest > ddt_hdr->b_l1hdr.b_arc_access) {
			type = ARC_BUFC_DDT;
		}
	} else if (data_hdr == NULL && ddt_hdr == NULL) {
		ASSERT3P(meta_hdr, !=, NULL);
		type = ARC_BUFC_METADATA;
	} else if (meta_hdr == NULL && ddt_hdr == NULL) {
		ASSERT3P(data_hdr, !=, NULL);
		type = ARC_BUFC_DATA;
	} else if (meta_hdr == NULL && data_hdr == NULL) {
		ASSERT3P(ddt_hdr, !=, NULL);
		type = ARC_BUFC_DDT;
	} else if (data_hdr != NULL && ddt_hdr != NULL) {
		ASSERT3P(meta_hdr, ==, NULL);

		/* The headers can't be on the sublist without an L1 header */
		ASSERT(HDR_HAS_L1HDR(data_hdr));
		ASSERT(HDR_HAS_L1HDR(ddt_hdr));

		if (data_hdr->b_l1hdr.b_arc_access <
		    ddt_hdr->b_l1hdr.b_arc_access) {
			type = ARC_BUFC_DATA;
		} else {
			type = ARC_BUFC_DDT;
		}
	} else if (meta_hdr != NULL && ddt_hdr != NULL) {
		ASSERT3P(data_hdr, ==, NULL);

		/* The headers can't be on the sublist without an L1 header */
		ASSERT(HDR_HAS_L1HDR(meta_hdr));
		ASSERT(HDR_HAS_L1HDR(ddt_hdr));

		if (meta_hdr->b_l1hdr.b_arc_access <
		    ddt_hdr->b_l1hdr.b_arc_access) {
			type = ARC_BUFC_METADATA;
		} else {
			type = ARC_BUFC_DDT;
		}
	} else if (meta_hdr != NULL && data_hdr != NULL) {
		ASSERT3P(ddt_hdr, ==, NULL);

		/* The headers can't be on the sublist without an L1 header */
		ASSERT(HDR_HAS_L1HDR(data_hdr));
		ASSERT(HDR_HAS_L1HDR(meta_hdr));

		if (data_hdr->b_l1hdr.b_arc_access <
		    meta_hdr->b_l1hdr.b_arc_access) {
			type = ARC_BUFC_DATA;
		} else {
			type = ARC_BUFC_METADATA;
		}
	} else {
		/* should never get here */
		ASSERT(0);
	}

	multilist_sublist_unlock(ddt_mls);
	multilist_sublist_unlock(meta_mls);
	multilist_sublist_unlock(data_mls);

	return (type);
}

/*
 * Evict buffers from the cache, such that arc_size is capped by arc_c.
 */
static uint64_t
arc_adjust(void)
{
	uint64_t total_evicted = 0;
	uint64_t bytes;
	int64_t target;
	uint64_t asize = aggsum_value(&arc_size);
	uint64_t ameta = aggsum_value(&arc_meta_used);
	uint64_t addt = aggsum_value(&astat_ddt_size);

	/*
	 * If we're over arc_meta_limit, we want to correct that before
	 * potentially evicting data buffers below.
	 */
	total_evicted += arc_adjust_meta_or_ddt(ameta, B_FALSE);

	/*
	 * If we're over arc_ddt_limit, we want to correct that before
	 * potentially evicting data buffers below.
	 */
	total_evicted += arc_adjust_meta_or_ddt(addt, B_TRUE);

	/*
	 * Adjust MRU size
	 *
	 * If we're over the target cache size, we want to evict enough
	 * from the list to get back to our target size. We don't want
	 * to evict too much from the MRU, such that it drops below
	 * arc_p. So, if we're over our target cache size more than
	 * the MRU is over arc_p, we'll evict enough to get back to
	 * arc_p here, and then evict more from the MFU below.
	 */
	target = MIN((int64_t)(asize - arc_c),
	    (int64_t)(refcount_count(&arc_anon->arcs_size) +
	    refcount_count(&arc_mru->arcs_size) + ameta - arc_p));

	/*
	 * If we're below arc_meta_min, always prefer to evict data.
	 * Otherwise, try to satisfy the requested number of bytes to
	 * evict from the type which contains older buffers; in an
	 * effort to keep newer buffers in the cache regardless of their
	 * type. If we cannot satisfy the number of bytes from this
	 * type, spill over into the next type.
	 */
	if (arc_adjust_type(arc_mru) == ARC_BUFC_METADATA &&
	    ameta > arc_meta_min) {
		bytes = arc_adjust_impl(arc_mru, 0, target, ARC_BUFC_METADATA);
		total_evicted += bytes;

		/*
		 * If we couldn't evict our target number of bytes from
		 * metadata, we try to get the rest from data.
		 */
		target -= bytes;

		bytes += arc_adjust_impl(arc_mru, 0, target, ARC_BUFC_DATA);
		total_evicted += bytes;
	} else {
		bytes = arc_adjust_impl(arc_mru, 0, target, ARC_BUFC_DATA);
		total_evicted += bytes;

		/*
		 * If we couldn't evict our target number of bytes from
		 * data, we try to get the rest from metadata.
		 */
		target -= bytes;

		bytes += arc_adjust_impl(arc_mru, 0, target, ARC_BUFC_METADATA);
		total_evicted += bytes;
	}

	/*
	 * If we couldn't evict our target number of bytes from
	 * data and metadata, we try to get the rest from ddt.
	 */
	target -= bytes;
	total_evicted +=
	    arc_adjust_impl(arc_mru, 0, target, ARC_BUFC_DDT);

	/*
	 * Adjust MFU size
	 *
	 * Now that we've tried to evict enough from the MRU to get its
	 * size back to arc_p, if we're still above the target cache
	 * size, we evict the rest from the MFU.
	 */
	target = asize - arc_c;

	if (arc_adjust_type(arc_mfu) == ARC_BUFC_METADATA &&
	    ameta > arc_meta_min) {
		bytes = arc_adjust_impl(arc_mfu, 0, target, ARC_BUFC_METADATA);
		total_evicted += bytes;

		/*
		 * If we couldn't evict our target number of bytes from
		 * metadata, we try to get the rest from data.
		 */
		target -= bytes;

		bytes += arc_adjust_impl(arc_mfu, 0, target, ARC_BUFC_DATA);
		total_evicted += bytes;
	} else {
		bytes = arc_adjust_impl(arc_mfu, 0, target, ARC_BUFC_DATA);
		total_evicted += bytes;

		/*
		 * If we couldn't evict our target number of bytes from
		 * data, we try to get the rest from data.
		 */
		target -= bytes;

		bytes += arc_adjust_impl(arc_mfu, 0, target, ARC_BUFC_METADATA);
		total_evicted += bytes;
	}

	/*
	 * If we couldn't evict our target number of bytes from
	 * data and metadata, we try to get the rest from ddt.
	 */
	target -= bytes;
	total_evicted +=
	    arc_adjust_impl(arc_mfu, 0, target, ARC_BUFC_DDT);

	/*
	 * Adjust ghost lists
	 *
	 * In addition to the above, the ARC also defines target values
	 * for the ghost lists. The sum of the mru list and mru ghost
	 * list should never exceed the target size of the cache, and
	 * the sum of the mru list, mfu list, mru ghost list, and mfu
	 * ghost list should never exceed twice the target size of the
	 * cache. The following logic enforces these limits on the ghost
	 * caches, and evicts from them as needed.
	 */
	target = refcount_count(&arc_mru->arcs_size) +
	    refcount_count(&arc_mru_ghost->arcs_size) - arc_c;

	bytes = arc_adjust_impl(arc_mru_ghost, 0, target, ARC_BUFC_DATA);
	total_evicted += bytes;

	target -= bytes;

	bytes += arc_adjust_impl(arc_mru_ghost, 0, target, ARC_BUFC_METADATA);
	total_evicted += bytes;

	target -= bytes;

	total_evicted +=
	    arc_adjust_impl(arc_mru_ghost, 0, target, ARC_BUFC_DDT);

	/*
	 * We assume the sum of the mru list and mfu list is less than
	 * or equal to arc_c (we enforced this above), which means we
	 * can use the simpler of the two equations below:
	 *
	 *	mru + mfu + mru ghost + mfu ghost <= 2 * arc_c
	 *		    mru ghost + mfu ghost <= arc_c
	 */
	target = refcount_count(&arc_mru_ghost->arcs_size) +
	    refcount_count(&arc_mfu_ghost->arcs_size) - arc_c;

	bytes = arc_adjust_impl(arc_mfu_ghost, 0, target, ARC_BUFC_DATA);
	total_evicted += bytes;

	target -= bytes;

	bytes += arc_adjust_impl(arc_mfu_ghost, 0, target, ARC_BUFC_METADATA);
	total_evicted += bytes;

	target -= bytes;

	total_evicted +=
	    arc_adjust_impl(arc_mfu_ghost, 0, target, ARC_BUFC_DDT);

	return (total_evicted);
}

typedef struct arc_async_flush_data {
	uint64_t	aaf_guid;
	boolean_t	aaf_retry;
} arc_async_flush_data_t;

static taskq_t *arc_flush_taskq;

static void
arc_flush_impl(uint64_t guid, boolean_t retry)
{
	arc_buf_contents_t arcs;

	for (arcs = ARC_BUFC_DATA; arcs < ARC_BUFC_NUMTYPES; ++arcs) {
		(void) arc_flush_state(arc_mru, guid, arcs, retry);
		(void) arc_flush_state(arc_mfu, guid, arcs, retry);
		(void) arc_flush_state(arc_mru_ghost, guid, arcs, retry);
		(void) arc_flush_state(arc_mfu_ghost, guid, arcs, retry);
	}
}

static void
arc_flush_task(void *arg)
{
	arc_async_flush_data_t *aaf = (arc_async_flush_data_t *)arg;
	arc_flush_impl(aaf->aaf_guid, aaf->aaf_retry);
	kmem_free(aaf, sizeof (arc_async_flush_data_t));
}

boolean_t zfs_fastflush = B_TRUE;

void
arc_flush(spa_t *spa, boolean_t retry)
{
	uint64_t guid = 0;
	boolean_t async_flush = (spa != NULL ? zfs_fastflush : FALSE);
	arc_async_flush_data_t *aaf = NULL;

	/*
	 * If retry is B_TRUE, a spa must not be specified since we have
	 * no good way to determine if all of a spa's buffers have been
	 * evicted from an arc state.
	 */
	ASSERT(!retry || spa == NULL);

	if (spa != NULL) {
		guid = spa_load_guid(spa);
		if (async_flush) {
			aaf = kmem_alloc(sizeof (arc_async_flush_data_t),
			    KM_SLEEP);
			aaf->aaf_guid = guid;
			aaf->aaf_retry = retry;
		}
	}

	/*
	 * Try to flush per-spa remaining ARC ghost buffers asynchronously
	 * while a pool is being closed.
	 * An ARC buffer is bound to spa only by guid, so buffer can
	 * exist even when pool has already gone. If asynchronous flushing
	 * fails we fall back to regular (synchronous) one.
	 * NOTE: If asynchronous flushing had not yet finished when the pool
	 * was imported again it wouldn't be a problem, even when guids before
	 * and after export/import are the same. We can evict only unreferenced
	 * buffers, other are skipped.
	 */
	if (!async_flush || (taskq_dispatch(arc_flush_taskq, arc_flush_task,
	    aaf, TQ_NOSLEEP) == NULL)) {
		arc_flush_impl(guid, retry);
		if (async_flush)
			kmem_free(aaf, sizeof (arc_async_flush_data_t));
	}
}

void
arc_shrink(int64_t to_free)
{
	uint64_t asize = aggsum_value(&arc_size);
	if (arc_c > arc_c_min) {

		if (arc_c > arc_c_min + to_free)
			atomic_add_64(&arc_c, -to_free);
		else
			arc_c = arc_c_min;

		atomic_add_64(&arc_p, -(arc_p >> arc_shrink_shift));
		if (asize < arc_c)
			arc_c = MAX(asize, arc_c_min);
		if (arc_p > arc_c)
			arc_p = (arc_c >> 1);
		ASSERT(arc_c >= arc_c_min);
		ASSERT((int64_t)arc_p >= 0);
	}

	if (asize > arc_c)
		(void) arc_adjust();
}

typedef enum free_memory_reason_t {
	FMR_UNKNOWN,
	FMR_NEEDFREE,
	FMR_LOTSFREE,
	FMR_SWAPFS_MINFREE,
	FMR_PAGES_PP_MAXIMUM,
	FMR_HEAP_ARENA,
	FMR_ZIO_ARENA,
} free_memory_reason_t;

int64_t last_free_memory;
free_memory_reason_t last_free_reason;

/*
 * Additional reserve of pages for pp_reserve.
 */
int64_t arc_pages_pp_reserve = 64;

/*
 * Additional reserve of pages for swapfs.
 */
int64_t arc_swapfs_reserve = 64;

/*
 * Return the amount of memory that can be consumed before reclaim will be
 * needed.  Positive if there is sufficient free memory, negative indicates
 * the amount of memory that needs to be freed up.
 */
static int64_t
arc_available_memory(void)
{
	int64_t lowest = INT64_MAX;
	int64_t n;
	free_memory_reason_t r = FMR_UNKNOWN;

#ifdef _KERNEL
	if (needfree > 0) {
		n = PAGESIZE * (-needfree);
		if (n < lowest) {
			lowest = n;
			r = FMR_NEEDFREE;
		}
	}

	/*
	 * check that we're out of range of the pageout scanner.  It starts to
	 * schedule paging if freemem is less than lotsfree and needfree.
	 * lotsfree is the high-water mark for pageout, and needfree is the
	 * number of needed free pages.  We add extra pages here to make sure
	 * the scanner doesn't start up while we're freeing memory.
	 */
	n = PAGESIZE * (freemem - lotsfree - needfree - desfree);
	if (n < lowest) {
		lowest = n;
		r = FMR_LOTSFREE;
	}

	/*
	 * check to make sure that swapfs has enough space so that anon
	 * reservations can still succeed. anon_resvmem() checks that the
	 * availrmem is greater than swapfs_minfree, and the number of reserved
	 * swap pages.  We also add a bit of extra here just to prevent
	 * circumstances from getting really dire.
	 */
	n = PAGESIZE * (availrmem - swapfs_minfree - swapfs_reserve -
	    desfree - arc_swapfs_reserve);
	if (n < lowest) {
		lowest = n;
		r = FMR_SWAPFS_MINFREE;
	}


	/*
	 * Check that we have enough availrmem that memory locking (e.g., via
	 * mlock(3C) or memcntl(2)) can still succeed.  (pages_pp_maximum
	 * stores the number of pages that cannot be locked; when availrmem
	 * drops below pages_pp_maximum, page locking mechanisms such as
	 * page_pp_lock() will fail.)
	 */
	n = PAGESIZE * (availrmem - pages_pp_maximum -
	    arc_pages_pp_reserve);
	if (n < lowest) {
		lowest = n;
		r = FMR_PAGES_PP_MAXIMUM;
	}

#if defined(__i386)
	/*
	 * If we're on an i386 platform, it's possible that we'll exhaust the
	 * kernel heap space before we ever run out of available physical
	 * memory.  Most checks of the size of the heap_area compare against
	 * tune.t_minarmem, which is the minimum available real memory that we
	 * can have in the system.  However, this is generally fixed at 25 pages
	 * which is so low that it's useless.  In this comparison, we seek to
	 * calculate the total heap-size, and reclaim if more than 3/4ths of the
	 * heap is allocated.  (Or, in the calculation, if less than 1/4th is
	 * free)
	 */
	n = (int64_t)vmem_size(heap_arena, VMEM_FREE) -
	    (vmem_size(heap_arena, VMEM_FREE | VMEM_ALLOC) >> 2);
	if (n < lowest) {
		lowest = n;
		r = FMR_HEAP_ARENA;
	}
#endif

	/*
	 * If zio data pages are being allocated out of a separate heap segment,
	 * then enforce that the size of available vmem for this arena remains
	 * above about 1/4th (1/(2^arc_zio_arena_free_shift)) free.
	 *
	 * Note that reducing the arc_zio_arena_free_shift keeps more virtual
	 * memory (in the zio_arena) free, which can avoid memory
	 * fragmentation issues.
	 */
	if (zio_arena != NULL) {
		n = (int64_t)vmem_size(zio_arena, VMEM_FREE) -
		    (vmem_size(zio_arena, VMEM_ALLOC) >>
		    arc_zio_arena_free_shift);
		if (n < lowest) {
			lowest = n;
			r = FMR_ZIO_ARENA;
		}
	}
#else
	/* Every 100 calls, free a small amount */
	if (spa_get_random(100) == 0)
		lowest = -1024;
#endif

	last_free_memory = lowest;
	last_free_reason = r;

	return (lowest);
}


/*
 * Determine if the system is under memory pressure and is asking
 * to reclaim memory. A return value of B_TRUE indicates that the system
 * is under memory pressure and that the arc should adjust accordingly.
 */
static boolean_t
arc_reclaim_needed(void)
{
	return (arc_available_memory() < 0);
}

static void
arc_kmem_reap_now(void)
{
	size_t			i;
	kmem_cache_t		*prev_cache = NULL;
	kmem_cache_t		*prev_data_cache = NULL;
	extern kmem_cache_t	*zio_buf_cache[];
	extern kmem_cache_t	*zio_data_buf_cache[];
	extern kmem_cache_t	*range_seg_cache;
	extern kmem_cache_t	*abd_chunk_cache;

#ifdef _KERNEL
	if (aggsum_compare(&arc_meta_used, arc_meta_limit) >= 0 ||
	    aggsum_compare(&astat_ddt_size, arc_ddt_limit) >= 0) {
		/*
		 * We are exceeding our meta-data or DDT cache limit.
		 * Purge some DNLC entries to release holds on meta-data/DDT.
		 */
		dnlc_reduce_cache((void *)(uintptr_t)arc_reduce_dnlc_percent);
	}
#if defined(__i386)
	/*
	 * Reclaim unused memory from all kmem caches.
	 */
	kmem_reap();
#endif
#endif

	/*
	 * If a kmem reap is already active, don't schedule more.  We must
	 * check for this because kmem_cache_reap_soon() won't actually
	 * block on the cache being reaped (this is to prevent callers from
	 * becoming implicitly blocked by a system-wide kmem reap -- which,
	 * on a system with many, many full magazines, can take minutes).
	 */
	if (kmem_cache_reap_active())
		return;

	for (i = 0; i < SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT; i++) {
		if (zio_buf_cache[i] != prev_cache) {
			prev_cache = zio_buf_cache[i];
			kmem_cache_reap_soon(zio_buf_cache[i]);
		}
		if (zio_data_buf_cache[i] != prev_data_cache) {
			prev_data_cache = zio_data_buf_cache[i];
			kmem_cache_reap_soon(zio_data_buf_cache[i]);
		}
	}
	kmem_cache_reap_soon(abd_chunk_cache);
	kmem_cache_reap_soon(buf_cache);
	kmem_cache_reap_soon(hdr_full_cache);
	kmem_cache_reap_soon(hdr_l2only_cache);
	kmem_cache_reap_soon(range_seg_cache);

	if (zio_arena != NULL) {
		/*
		 * Ask the vmem arena to reclaim unused memory from its
		 * quantum caches.
		 */
		vmem_qcache_reap(zio_arena);
	}
}

/*
 * Threads can block in arc_get_data_impl() waiting for this thread to evict
 * enough data and signal them to proceed. When this happens, the threads in
 * arc_get_data_impl() are sleeping while holding the hash lock for their
 * particular arc header. Thus, we must be careful to never sleep on a
 * hash lock in this thread. This is to prevent the following deadlock:
 *
 *  - Thread A sleeps on CV in arc_get_data_impl() holding hash lock "L",
 *    waiting for the reclaim thread to signal it.
 *
 *  - arc_reclaim_thread() tries to acquire hash lock "L" using mutex_enter,
 *    fails, and goes to sleep forever.
 *
 * This possible deadlock is avoided by always acquiring a hash lock
 * using mutex_tryenter() from arc_reclaim_thread().
 */
/* ARGSUSED */
static void
arc_reclaim_thread(void *unused)
{
	hrtime_t		growtime = 0;
	hrtime_t		kmem_reap_time = 0;
	callb_cpr_t		cpr;

	CALLB_CPR_INIT(&cpr, &arc_reclaim_lock, callb_generic_cpr, FTAG);

	mutex_enter(&arc_reclaim_lock);
	while (!arc_reclaim_thread_exit) {
		uint64_t evicted = 0;

		/*
		 * This is necessary in order for the mdb ::arc dcmd to
		 * show up to date information. Since the ::arc command
		 * does not call the kstat's update function, without
		 * this call, the command may show stale stats for the
		 * anon, mru, mru_ghost, mfu, and mfu_ghost lists. Even
		 * with this change, the data might be up to 1 second
		 * out of date; but that should suffice. The arc_state_t
		 * structures can be queried directly if more accurate
		 * information is needed.
		 */
		if (arc_ksp != NULL)
			arc_ksp->ks_update(arc_ksp, KSTAT_READ);

		mutex_exit(&arc_reclaim_lock);

		/*
		 * We call arc_adjust() before (possibly) calling
		 * arc_kmem_reap_now(), so that we can wake up
		 * arc_get_data_impl() sooner.
		 */
		evicted = arc_adjust();

		int64_t free_memory = arc_available_memory();
		if (free_memory < 0) {
			hrtime_t curtime = gethrtime();
			arc_no_grow = B_TRUE;
			arc_warm = B_TRUE;

			/*
			 * Wait at least zfs_grow_retry (default 60) seconds
			 * before considering growing.
			 */
			growtime = curtime + SEC2NSEC(arc_grow_retry);

			/*
			 * Wait at least arc_kmem_cache_reap_retry_ms
			 * between arc_kmem_reap_now() calls. Without
			 * this check it is possible to end up in a
			 * situation where we spend lots of time
			 * reaping caches, while we're near arc_c_min.
			 */
			if (curtime >= kmem_reap_time) {
				arc_kmem_reap_now();
				kmem_reap_time = gethrtime() +
				    MSEC2NSEC(arc_kmem_cache_reap_retry_ms);
			}

			/*
			 * If we are still low on memory, shrink the ARC
			 * so that we have arc_shrink_min free space.
			 */
			free_memory = arc_available_memory();

			int64_t to_free =
			    (arc_c >> arc_shrink_shift) - free_memory;
			if (to_free > 0) {
#ifdef _KERNEL
				to_free = MAX(to_free, ptob(needfree));
#endif
				arc_shrink(to_free);
			}
		} else if (free_memory < arc_c >> arc_no_grow_shift) {
			arc_no_grow = B_TRUE;
		} else if (gethrtime() >= growtime) {
			arc_no_grow = B_FALSE;
		}

		mutex_enter(&arc_reclaim_lock);

		/*
		 * If evicted is zero, we couldn't evict anything via
		 * arc_adjust(). This could be due to hash lock
		 * collisions, but more likely due to the majority of
		 * arc buffers being unevictable. Therefore, even if
		 * arc_size is above arc_c, another pass is unlikely to
		 * be helpful and could potentially cause us to enter an
		 * infinite loop.
		 */
		if (aggsum_compare(&arc_size, arc_c) <= 0|| evicted == 0) {
			/*
			 * We're either no longer overflowing, or we
			 * can't evict anything more, so we should wake
			 * up any threads before we go to sleep.
			 */
			cv_broadcast(&arc_reclaim_waiters_cv);

			/*
			 * Block until signaled, or after one second (we
			 * might need to perform arc_kmem_reap_now()
			 * even if we aren't being signalled)
			 */
			CALLB_CPR_SAFE_BEGIN(&cpr);
			(void) cv_timedwait_hires(&arc_reclaim_thread_cv,
			    &arc_reclaim_lock, SEC2NSEC(1), MSEC2NSEC(1), 0);
			CALLB_CPR_SAFE_END(&cpr, &arc_reclaim_lock);
		}
	}

	arc_reclaim_thread_exit = B_FALSE;
	cv_broadcast(&arc_reclaim_thread_cv);
	CALLB_CPR_EXIT(&cpr);		/* drops arc_reclaim_lock */
	thread_exit();
}

/*
 * Adapt arc info given the number of bytes we are trying to add and
 * the state that we are comming from.  This function is only called
 * when we are adding new content to the cache.
 */
static void
arc_adapt(int bytes, arc_state_t *state)
{
	int mult;
	uint64_t arc_p_min = (arc_c >> arc_p_min_shift);
	int64_t mrug_size = refcount_count(&arc_mru_ghost->arcs_size);
	int64_t mfug_size = refcount_count(&arc_mfu_ghost->arcs_size);

	if (state == arc_l2c_only)
		return;

	ASSERT(bytes > 0);
	/*
	 * Adapt the target size of the MRU list:
	 *	- if we just hit in the MRU ghost list, then increase
	 *	  the target size of the MRU list.
	 *	- if we just hit in the MFU ghost list, then increase
	 *	  the target size of the MFU list by decreasing the
	 *	  target size of the MRU list.
	 */
	if (state == arc_mru_ghost) {
		mult = (mrug_size >= mfug_size) ? 1 : (mfug_size / mrug_size);
		mult = MIN(mult, 10); /* avoid wild arc_p adjustment */

		arc_p = MIN(arc_c - arc_p_min, arc_p + bytes * mult);
	} else if (state == arc_mfu_ghost) {
		uint64_t delta;

		mult = (mfug_size >= mrug_size) ? 1 : (mrug_size / mfug_size);
		mult = MIN(mult, 10);

		delta = MIN(bytes * mult, arc_p);
		arc_p = MAX(arc_p_min, arc_p - delta);
	}
	ASSERT((int64_t)arc_p >= 0);

	if (arc_reclaim_needed()) {
		cv_signal(&arc_reclaim_thread_cv);
		return;
	}

	if (arc_no_grow)
		return;

	if (arc_c >= arc_c_max)
		return;

	/*
	 * If we're within (2 * maxblocksize) bytes of the target
	 * cache size, increment the target cache size
	 */
	if (aggsum_compare(&arc_size, arc_c - (2ULL << SPA_MAXBLOCKSHIFT)) >
	    0) {
		atomic_add_64(&arc_c, (int64_t)bytes);
		if (arc_c > arc_c_max)
			arc_c = arc_c_max;
		else if (state == arc_anon)
			atomic_add_64(&arc_p, (int64_t)bytes);
		if (arc_p > arc_c)
			arc_p = arc_c;
	}
	ASSERT((int64_t)arc_p >= 0);
}

/*
 * Check if arc_size has grown past our upper threshold, determined by
 * zfs_arc_overflow_shift.
 */
static boolean_t
arc_is_overflowing(void)
{
	/* Always allow at least one block of overflow */
	uint64_t overflow = MAX(SPA_MAXBLOCKSIZE,
	    arc_c >> zfs_arc_overflow_shift);

	/*
	 * We just compare the lower bound here for performance reasons. Our
	 * primary goals are to make sure that the arc never grows without
	 * bound, and that it can reach its maximum size. This check
	 * accomplishes both goals. The maximum amount we could run over by is
	 * 2 * aggsum_borrow_multiplier * NUM_CPUS * the average size of a block
	 * in the ARC. In practice, that's in the tens of MB, which is low
	 * enough to be safe.
	 */
	return (aggsum_lower_bound(&arc_size) >= arc_c + overflow);
}

static abd_t *
arc_get_data_abd(arc_buf_hdr_t *hdr, uint64_t size, void *tag)
{
	arc_buf_contents_t type = arc_buf_type(hdr);

	arc_get_data_impl(hdr, size, tag);
	if (type == ARC_BUFC_METADATA || type == ARC_BUFC_DDT) {
		return (abd_alloc(size, B_TRUE));
	} else {
		ASSERT(type == ARC_BUFC_DATA);
		return (abd_alloc(size, B_FALSE));
	}
}

static void *
arc_get_data_buf(arc_buf_hdr_t *hdr, uint64_t size, void *tag)
{
	arc_buf_contents_t type = arc_buf_type(hdr);

	arc_get_data_impl(hdr, size, tag);
	if (type == ARC_BUFC_METADATA || type == ARC_BUFC_DDT) {
		return (zio_buf_alloc(size));
	} else {
		ASSERT(type == ARC_BUFC_DATA);
		return (zio_data_buf_alloc(size));
	}
}

/*
 * Allocate a block and return it to the caller. If we are hitting the
 * hard limit for the cache size, we must sleep, waiting for the eviction
 * thread to catch up. If we're past the target size but below the hard
 * limit, we'll only signal the reclaim thread and continue on.
 */
static void
arc_get_data_impl(arc_buf_hdr_t *hdr, uint64_t size, void *tag)
{
	arc_state_t *state = hdr->b_l1hdr.b_state;
	arc_buf_contents_t type = arc_buf_type(hdr);

	arc_adapt(size, state);

	/*
	 * If arc_size is currently overflowing, and has grown past our
	 * upper limit, we must be adding data faster than the evict
	 * thread can evict. Thus, to ensure we don't compound the
	 * problem by adding more data and forcing arc_size to grow even
	 * further past it's target size, we halt and wait for the
	 * eviction thread to catch up.
	 *
	 * It's also possible that the reclaim thread is unable to evict
	 * enough buffers to get arc_size below the overflow limit (e.g.
	 * due to buffers being un-evictable, or hash lock collisions).
	 * In this case, we want to proceed regardless if we're
	 * overflowing; thus we don't use a while loop here.
	 */
	if (arc_is_overflowing()) {
		mutex_enter(&arc_reclaim_lock);

		/*
		 * Now that we've acquired the lock, we may no longer be
		 * over the overflow limit, lets check.
		 *
		 * We're ignoring the case of spurious wake ups. If that
		 * were to happen, it'd let this thread consume an ARC
		 * buffer before it should have (i.e. before we're under
		 * the overflow limit and were signalled by the reclaim
		 * thread). As long as that is a rare occurrence, it
		 * shouldn't cause any harm.
		 */
		if (arc_is_overflowing()) {
			cv_signal(&arc_reclaim_thread_cv);
			cv_wait(&arc_reclaim_waiters_cv, &arc_reclaim_lock);
		}

		mutex_exit(&arc_reclaim_lock);
	}

	VERIFY3U(hdr->b_type, ==, type);
	if (type == ARC_BUFC_DDT) {
		arc_space_consume(size, ARC_SPACE_DDT);
	} else if (type == ARC_BUFC_METADATA) {
		arc_space_consume(size, ARC_SPACE_META);
	} else {
		arc_space_consume(size, ARC_SPACE_DATA);
	}

	/*
	 * Update the state size.  Note that ghost states have a
	 * "ghost size" and so don't need to be updated.
	 */
	if (!GHOST_STATE(state)) {

		(void) refcount_add_many(&state->arcs_size, size, tag);

		/*
		 * If this is reached via arc_read, the link is
		 * protected by the hash lock. If reached via
		 * arc_buf_alloc, the header should not be accessed by
		 * any other thread. And, if reached via arc_read_done,
		 * the hash lock will protect it if it's found in the
		 * hash table; otherwise no other thread should be
		 * trying to [add|remove]_reference it.
		 */
		if (multilist_link_active(&hdr->b_l1hdr.b_arc_node)) {
			ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt));
			(void) refcount_add_many(&state->arcs_esize[type],
			    size, tag);
		}

		/*
		 * If we are growing the cache, and we are adding anonymous
		 * data, and we have outgrown arc_p, update arc_p
		 */
		if (aggsum_compare(&arc_size, arc_c) < 0 &&
		    hdr->b_l1hdr.b_state == arc_anon &&
		    (refcount_count(&arc_anon->arcs_size) +
		    refcount_count(&arc_mru->arcs_size) > arc_p))
			arc_p = MIN(arc_c, arc_p + size);
	}
}

static void
arc_free_data_abd(arc_buf_hdr_t *hdr, abd_t *abd, uint64_t size, void *tag)
{
	arc_free_data_impl(hdr, size, tag);
	abd_free(abd);
}

static void
arc_free_data_buf(arc_buf_hdr_t *hdr, void *buf, uint64_t size, void *tag)
{
	arc_buf_contents_t type = arc_buf_type(hdr);

	arc_free_data_impl(hdr, size, tag);
	if (type == ARC_BUFC_METADATA || type == ARC_BUFC_DDT) {
		zio_buf_free(buf, size);
	} else {
		ASSERT(type == ARC_BUFC_DATA);
		zio_data_buf_free(buf, size);
	}
}

/*
 * Free the arc data buffer.
 */
static void
arc_free_data_impl(arc_buf_hdr_t *hdr, uint64_t size, void *tag)
{
	arc_state_t *state = hdr->b_l1hdr.b_state;
	arc_buf_contents_t type = arc_buf_type(hdr);

	/* protected by hash lock, if in the hash table */
	if (multilist_link_active(&hdr->b_l1hdr.b_arc_node)) {
		ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt));
		ASSERT(state != arc_anon && state != arc_l2c_only);

		(void) refcount_remove_many(&state->arcs_esize[type],
		    size, tag);
	}
	(void) refcount_remove_many(&state->arcs_size, size, tag);

	VERIFY3U(hdr->b_type, ==, type);
	if (type == ARC_BUFC_DDT) {
		arc_space_return(size, ARC_SPACE_DDT);
	} else if (type == ARC_BUFC_METADATA) {
		arc_space_return(size, ARC_SPACE_META);
	} else {
		ASSERT(type == ARC_BUFC_DATA);
		arc_space_return(size, ARC_SPACE_DATA);
	}
}

/*
 * This routine is called whenever a buffer is accessed.
 * NOTE: the hash lock is dropped in this function.
 */
static void
arc_access(arc_buf_hdr_t *hdr, kmutex_t *hash_lock)
{
	clock_t now;

	ASSERT(MUTEX_HELD(hash_lock));
	ASSERT(HDR_HAS_L1HDR(hdr));

	if (hdr->b_l1hdr.b_state == arc_anon) {
		/*
		 * This buffer is not in the cache, and does not
		 * appear in our "ghost" list.  Add the new buffer
		 * to the MRU state.
		 */

		ASSERT0(hdr->b_l1hdr.b_arc_access);
		hdr->b_l1hdr.b_arc_access = ddi_get_lbolt();
		DTRACE_PROBE1(new_state__mru, arc_buf_hdr_t *, hdr);
		arc_change_state(arc_mru, hdr, hash_lock);

	} else if (hdr->b_l1hdr.b_state == arc_mru) {
		now = ddi_get_lbolt();

		/*
		 * If this buffer is here because of a prefetch, then either:
		 * - clear the flag if this is a "referencing" read
		 *   (any subsequent access will bump this into the MFU state).
		 * or
		 * - move the buffer to the head of the list if this is
		 *   another prefetch (to make it less likely to be evicted).
		 */
		if (HDR_PREFETCH(hdr)) {
			if (refcount_count(&hdr->b_l1hdr.b_refcnt) == 0) {
				/* link protected by hash lock */
				ASSERT(multilist_link_active(
				    &hdr->b_l1hdr.b_arc_node));
			} else {
				arc_hdr_clear_flags(hdr, ARC_FLAG_PREFETCH);
				ARCSTAT_BUMP(arcstat_mru_hits);
			}
			hdr->b_l1hdr.b_arc_access = now;
			return;
		}

		/*
		 * This buffer has been "accessed" only once so far,
		 * but it is still in the cache. Move it to the MFU
		 * state.
		 */
		if (now > hdr->b_l1hdr.b_arc_access + ARC_MINTIME) {
			/*
			 * More than 125ms have passed since we
			 * instantiated this buffer.  Move it to the
			 * most frequently used state.
			 */
			hdr->b_l1hdr.b_arc_access = now;
			DTRACE_PROBE1(new_state__mfu, arc_buf_hdr_t *, hdr);
			arc_change_state(arc_mfu, hdr, hash_lock);
		}
		ARCSTAT_BUMP(arcstat_mru_hits);
	} else if (hdr->b_l1hdr.b_state == arc_mru_ghost) {
		arc_state_t	*new_state;
		/*
		 * This buffer has been "accessed" recently, but
		 * was evicted from the cache.  Move it to the
		 * MFU state.
		 */

		if (HDR_PREFETCH(hdr)) {
			new_state = arc_mru;
			if (refcount_count(&hdr->b_l1hdr.b_refcnt) > 0)
				arc_hdr_clear_flags(hdr, ARC_FLAG_PREFETCH);
			DTRACE_PROBE1(new_state__mru, arc_buf_hdr_t *, hdr);
		} else {
			new_state = arc_mfu;
			DTRACE_PROBE1(new_state__mfu, arc_buf_hdr_t *, hdr);
		}

		hdr->b_l1hdr.b_arc_access = ddi_get_lbolt();
		arc_change_state(new_state, hdr, hash_lock);

		ARCSTAT_BUMP(arcstat_mru_ghost_hits);
	} else if (hdr->b_l1hdr.b_state == arc_mfu) {
		/*
		 * This buffer has been accessed more than once and is
		 * still in the cache.  Keep it in the MFU state.
		 *
		 * NOTE: an add_reference() that occurred when we did
		 * the arc_read() will have kicked this off the list.
		 * If it was a prefetch, we will explicitly move it to
		 * the head of the list now.
		 */
		if ((HDR_PREFETCH(hdr)) != 0) {
			ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt));
			/* link protected by hash_lock */
			ASSERT(multilist_link_active(&hdr->b_l1hdr.b_arc_node));
		}
		ARCSTAT_BUMP(arcstat_mfu_hits);
		hdr->b_l1hdr.b_arc_access = ddi_get_lbolt();
	} else if (hdr->b_l1hdr.b_state == arc_mfu_ghost) {
		arc_state_t	*new_state = arc_mfu;
		/*
		 * This buffer has been accessed more than once but has
		 * been evicted from the cache.  Move it back to the
		 * MFU state.
		 */

		if (HDR_PREFETCH(hdr)) {
			/*
			 * This is a prefetch access...
			 * move this block back to the MRU state.
			 */
			ASSERT0(refcount_count(&hdr->b_l1hdr.b_refcnt));
			new_state = arc_mru;
		}

		hdr->b_l1hdr.b_arc_access = ddi_get_lbolt();
		DTRACE_PROBE1(new_state__mfu, arc_buf_hdr_t *, hdr);
		arc_change_state(new_state, hdr, hash_lock);

		ARCSTAT_BUMP(arcstat_mfu_ghost_hits);
	} else if (hdr->b_l1hdr.b_state == arc_l2c_only) {
		/*
		 * This buffer is on the 2nd Level ARC.
		 */

		hdr->b_l1hdr.b_arc_access = ddi_get_lbolt();
		DTRACE_PROBE1(new_state__mfu, arc_buf_hdr_t *, hdr);
		arc_change_state(arc_mfu, hdr, hash_lock);
	} else {
		ASSERT(!"invalid arc state");
	}
}

/*
 * This routine is called by dbuf_hold() to update the arc_access() state
 * which otherwise would be skipped for entries in the dbuf cache.
 */
void
arc_buf_access(arc_buf_t *buf)
{
	mutex_enter(&buf->b_evict_lock);
	arc_buf_hdr_t *hdr = buf->b_hdr;

	/*
	 * Avoid taking the hash_lock when possible as an optimization.
	 * The header must be checked again under the hash_lock in order
	 * to handle the case where it is concurrently being released.
	 */
	if (hdr->b_l1hdr.b_state == arc_anon || HDR_EMPTY(hdr)) {
		mutex_exit(&buf->b_evict_lock);
		return;
	}

	kmutex_t *hash_lock = HDR_LOCK(hdr);
	mutex_enter(hash_lock);

	if (hdr->b_l1hdr.b_state == arc_anon || HDR_EMPTY(hdr)) {
		mutex_exit(hash_lock);
		mutex_exit(&buf->b_evict_lock);
		ARCSTAT_BUMP(arcstat_access_skip);
		return;
	}

	mutex_exit(&buf->b_evict_lock);

	ASSERT(hdr->b_l1hdr.b_state == arc_mru ||
	    hdr->b_l1hdr.b_state == arc_mfu);

	DTRACE_PROBE1(arc__hit, arc_buf_hdr_t *, hdr);
	arc_access(hdr, hash_lock);
	mutex_exit(hash_lock);

	ARCSTAT_BUMP(arcstat_hits);
	/*
	 * Upstream used the ARCSTAT_CONDSTAT macro here, but they changed
	 * the argument format for that macro, which would requie that we
	 * go and modify all other uses of it. So it's easier to just expand
	 * this one invocation of the macro to do the right thing.
	 */
	if (!HDR_PREFETCH(hdr)) {
		if (!HDR_ISTYPE_METADATA(hdr))
			ARCSTAT_BUMP(arcstat_demand_data_hits);
		else
			ARCSTAT_BUMP(arcstat_demand_metadata_hits);
	} else {
		if (!HDR_ISTYPE_METADATA(hdr))
			ARCSTAT_BUMP(arcstat_prefetch_data_hits);
		else
			ARCSTAT_BUMP(arcstat_prefetch_metadata_hits);
	}
}

/* a generic arc_done_func_t which you can use */
/* ARGSUSED */
void
arc_bcopy_func(zio_t *zio, arc_buf_t *buf, void *arg)
{
	if (zio == NULL || zio->io_error == 0)
		bcopy(buf->b_data, arg, arc_buf_size(buf));
	arc_buf_destroy(buf, arg);
}

/* a generic arc_done_func_t */
void
arc_getbuf_func(zio_t *zio, arc_buf_t *buf, void *arg)
{
	arc_buf_t **bufp = arg;
	if (buf == NULL) {
		ASSERT(zio == NULL || zio->io_error != 0);
		*bufp = NULL;
	} else {
		ASSERT(zio == NULL || zio->io_error == 0);
		*bufp = buf;
		ASSERT(buf->b_data != NULL);
	}
}

static void
arc_hdr_verify(arc_buf_hdr_t *hdr, blkptr_t *bp)
{
	if (BP_IS_HOLE(bp) || BP_IS_EMBEDDED(bp)) {
		ASSERT3U(HDR_GET_PSIZE(hdr), ==, 0);
		ASSERT3U(HDR_GET_COMPRESS(hdr), ==, ZIO_COMPRESS_OFF);
	} else {
		if (HDR_COMPRESSION_ENABLED(hdr)) {
			ASSERT3U(HDR_GET_COMPRESS(hdr), ==,
			    BP_GET_COMPRESS(bp));
		}
		ASSERT3U(HDR_GET_LSIZE(hdr), ==, BP_GET_LSIZE(bp));
		ASSERT3U(HDR_GET_PSIZE(hdr), ==, BP_GET_PSIZE(bp));
	}
}

static void
arc_read_done(zio_t *zio)
{
	arc_buf_hdr_t	*hdr = zio->io_private;
	kmutex_t	*hash_lock = NULL;
	arc_callback_t	*callback_list;
	arc_callback_t	*acb;
	boolean_t	freeable = B_FALSE;
	boolean_t	no_zio_error = (zio->io_error == 0);

	/*
	 * The hdr was inserted into hash-table and removed from lists
	 * prior to starting I/O.  We should find this header, since
	 * it's in the hash table, and it should be legit since it's
	 * not possible to evict it during the I/O.  The only possible
	 * reason for it not to be found is if we were freed during the
	 * read.
	 */
	if (HDR_IN_HASH_TABLE(hdr)) {
		ASSERT3U(hdr->b_birth, ==, BP_PHYSICAL_BIRTH(zio->io_bp));
		ASSERT3U(hdr->b_dva.dva_word[0], ==,
		    BP_IDENTITY(zio->io_bp)->dva_word[0]);
		ASSERT3U(hdr->b_dva.dva_word[1], ==,
		    BP_IDENTITY(zio->io_bp)->dva_word[1]);

		arc_buf_hdr_t *found = buf_hash_find(hdr->b_spa, zio->io_bp,
		    &hash_lock);

		ASSERT((found == hdr &&
		    DVA_EQUAL(&hdr->b_dva, BP_IDENTITY(zio->io_bp))) ||
		    (found == hdr && HDR_L2_READING(hdr)));
		ASSERT3P(hash_lock, !=, NULL);
	}

	if (no_zio_error) {
		/* byteswap if necessary */
		if (BP_SHOULD_BYTESWAP(zio->io_bp)) {
			if (BP_GET_LEVEL(zio->io_bp) > 0) {
				hdr->b_l1hdr.b_byteswap = DMU_BSWAP_UINT64;
			} else {
				hdr->b_l1hdr.b_byteswap =
				    DMU_OT_BYTESWAP(BP_GET_TYPE(zio->io_bp));
			}
		} else {
			hdr->b_l1hdr.b_byteswap = DMU_BSWAP_NUMFUNCS;
		}
	}

	arc_hdr_clear_flags(hdr, ARC_FLAG_L2_EVICTED);
	if (l2arc_noprefetch && HDR_PREFETCH(hdr))
		arc_hdr_clear_flags(hdr, ARC_FLAG_L2CACHE);

	callback_list = hdr->b_l1hdr.b_acb;
	ASSERT3P(callback_list, !=, NULL);

	if (hash_lock && no_zio_error && hdr->b_l1hdr.b_state == arc_anon) {
		/*
		 * Only call arc_access on anonymous buffers.  This is because
		 * if we've issued an I/O for an evicted buffer, we've already
		 * called arc_access (to prevent any simultaneous readers from
		 * getting confused).
		 */
		arc_access(hdr, hash_lock);
	}

	/*
	 * If a read request has a callback (i.e. acb_done is not NULL), then we
	 * make a buf containing the data according to the parameters which were
	 * passed in. The implementation of arc_buf_alloc_impl() ensures that we
	 * aren't needlessly decompressing the data multiple times.
	 */
	int callback_cnt = 0;
	for (acb = callback_list; acb != NULL; acb = acb->acb_next) {
		if (!acb->acb_done)
			continue;

		/* This is a demand read since prefetches don't use callbacks */
		callback_cnt++;

		if (no_zio_error) {
			int error = arc_buf_alloc_impl(hdr, acb->acb_private,
			    acb->acb_compressed, zio->io_error == 0,
			    &acb->acb_buf);
			if (error != 0) {
				/*
				 * Decompression failed.  Set io_error
				 * so that when we call acb_done (below),
				 * we will indicate that the read failed.
				 * Note that in the unusual case where one
				 * callback is compressed and another
				 * uncompressed, we will mark all of them
				 * as failed, even though the uncompressed
				 * one can't actually fail.  In this case,
				 * the hdr will not be anonymous, because
				 * if there are multiple callbacks, it's
				 * because multiple threads found the same
				 * arc buf in the hash table.
				 */
				zio->io_error = error;
			}
		}
	}
	/*
	 * If there are multiple callbacks, we must have the hash lock,
	 * because the only way for multiple threads to find this hdr is
	 * in the hash table.  This ensures that if there are multiple
	 * callbacks, the hdr is not anonymous.  If it were anonymous,
	 * we couldn't use arc_buf_destroy() in the error case below.
	 */
	ASSERT(callback_cnt < 2 || hash_lock != NULL);

	hdr->b_l1hdr.b_acb = NULL;
	arc_hdr_clear_flags(hdr, ARC_FLAG_IO_IN_PROGRESS);
	if (callback_cnt == 0) {
		ASSERT(HDR_PREFETCH(hdr));
		ASSERT0(hdr->b_l1hdr.b_bufcnt);
		ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);
	}

	ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt) ||
	    callback_list != NULL);

	if (no_zio_error) {
		arc_hdr_verify(hdr, zio->io_bp);
	} else {
		arc_hdr_set_flags(hdr, ARC_FLAG_IO_ERROR);
		if (hdr->b_l1hdr.b_state != arc_anon)
			arc_change_state(arc_anon, hdr, hash_lock);
		if (HDR_IN_HASH_TABLE(hdr)) {
			buf_hash_remove(hdr);
			if (hash_lock)
				arc_wait_for_short_holders(hdr);
		}
		freeable = refcount_is_zero(&hdr->b_l1hdr.b_refcnt);
	}

	/*
	 * Broadcast before we drop the hash_lock to avoid the possibility
	 * that the hdr (and hence the cv) might be freed before we get to
	 * the cv_broadcast().
	 */
	cv_broadcast(&hdr->b_l1hdr.b_cv);

	if (hash_lock != NULL) {
		mutex_exit(hash_lock);
	} else {
		/*
		 * This block was freed while we waited for the read to
		 * complete.  It has been removed from the hash table and
		 * moved to the anonymous state (so that it won't show up
		 * in the cache).
		 */
		ASSERT3P(hdr->b_l1hdr.b_state, ==, arc_anon);
		freeable = refcount_is_zero(&hdr->b_l1hdr.b_refcnt);
	}

	/* execute each callback and free its structure */
	while ((acb = callback_list) != NULL) {
		if (acb->acb_done != NULL) {
			if (zio->io_error != 0 && acb->acb_buf != NULL) {
				/*
				 * If arc_buf_alloc_impl() fails during
				 * decompression, the buf will still be
				 * allocated, and needs to be freed here.
				 */
				arc_buf_destroy(acb->acb_buf, acb->acb_private);
				acb->acb_buf = NULL;
			}
			acb->acb_done(zio, acb->acb_buf, acb->acb_private);
		}

		if (acb->acb_zio_dummy != NULL) {
			acb->acb_zio_dummy->io_error = zio->io_error;
			zio_nowait(acb->acb_zio_dummy);
		}

		callback_list = acb->acb_next;
		kmem_free(acb, sizeof (arc_callback_t));
	}

	if (freeable)
		arc_hdr_destroy(hdr);
}

/*
 * The function to process data from arc by a callback
 * The main purpose is to directly copy data from arc to a target buffer
 */
int
arc_io_bypass(spa_t *spa, const blkptr_t *bp,
    arc_bypass_io_func func, void *arg)
{
	arc_buf_hdr_t *hdr;
	kmutex_t *hash_lock = NULL;
	int error = 0;
	uint64_t guid = spa_load_guid(spa);

top:
	hdr = buf_hash_find(guid, bp, &hash_lock);
	if (hdr != NULL && HDR_HAS_L1HDR(hdr) && hdr->b_l1hdr.b_pabd != NULL) {
		if (HDR_IO_IN_PROGRESS(hdr)) {
			cv_wait(&hdr->b_l1hdr.b_cv, hash_lock);
			mutex_exit(hash_lock);
			DTRACE_PROBE(arc_bypass_wait);
			goto top;
		}

		/*
		 * As the func is an arbitrary callback, which can block, lock
		 * should be released not to block other threads from
		 * performing. A counter is used to hold a reference to block
		 * which are held by caller.
		 */

		hdr->b_l1hdr.b_short_holders++;
		mutex_exit(hash_lock);

		error = func(hdr->b_l1hdr.b_pabd,
		    HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF, arg);

		mutex_enter(hash_lock);
		hdr->b_l1hdr.b_short_holders--;
		cv_broadcast(&hdr->b_l1hdr.b_cv);
		mutex_exit(hash_lock);

		return (error);
	} else {
		if (hash_lock)
			mutex_exit(hash_lock);

		return (ENODATA);
	}
}

/*
 * "Read" the block at the specified DVA (in bp) via the
 * cache.  If the block is found in the cache, invoke the provided
 * callback immediately and return.  Note that the `zio' parameter
 * in the callback will be NULL in this case, since no IO was
 * required.  If the block is not in the cache pass the read request
 * on to the spa with a substitute callback function, so that the
 * requested block will be added to the cache.
 *
 * If a read request arrives for a block that has a read in-progress,
 * either wait for the in-progress read to complete (and return the
 * results); or, if this is a read with a "done" func, add a record
 * to the read to invoke the "done" func when the read completes,
 * and return; or just return.
 *
 * arc_read_done() will invoke all the requested "done" functions
 * for readers of this block.
 */
int
arc_read(zio_t *pio, spa_t *spa, const blkptr_t *bp, arc_done_func_t *done,
    void *private, zio_priority_t priority, int zio_flags,
    arc_flags_t *arc_flags, const zbookmark_phys_t *zb)
{
	arc_buf_hdr_t *hdr = NULL;
	kmutex_t *hash_lock = NULL;
	zio_t *rzio;
	uint64_t guid = spa_load_guid(spa);
	boolean_t compressed_read = (zio_flags & ZIO_FLAG_RAW) != 0;

	ASSERT(!BP_IS_EMBEDDED(bp) ||
	    BPE_GET_ETYPE(bp) == BP_EMBEDDED_TYPE_DATA);

top:
	if (!BP_IS_EMBEDDED(bp)) {
		/*
		 * Embedded BP's have no DVA and require no I/O to "read".
		 * Create an anonymous arc buf to back it.
		 */
		hdr = buf_hash_find(guid, bp, &hash_lock);
	}

	if (hdr != NULL && HDR_HAS_L1HDR(hdr) && hdr->b_l1hdr.b_pabd != NULL) {
		arc_buf_t *buf = NULL;
		*arc_flags |= ARC_FLAG_CACHED;

		if (HDR_IO_IN_PROGRESS(hdr)) {

			if ((hdr->b_flags & ARC_FLAG_PRIO_ASYNC_READ) &&
			    priority == ZIO_PRIORITY_SYNC_READ) {
				/*
				 * This sync read must wait for an
				 * in-progress async read (e.g. a predictive
				 * prefetch).  Async reads are queued
				 * separately at the vdev_queue layer, so
				 * this is a form of priority inversion.
				 * Ideally, we would "inherit" the demand
				 * i/o's priority by moving the i/o from
				 * the async queue to the synchronous queue,
				 * but there is currently no mechanism to do
				 * so.  Track this so that we can evaluate
				 * the magnitude of this potential performance
				 * problem.
				 *
				 * Note that if the prefetch i/o is already
				 * active (has been issued to the device),
				 * the prefetch improved performance, because
				 * we issued it sooner than we would have
				 * without the prefetch.
				 */
				DTRACE_PROBE1(arc__sync__wait__for__async,
				    arc_buf_hdr_t *, hdr);
				ARCSTAT_BUMP(arcstat_sync_wait_for_async);
			}
			if (hdr->b_flags & ARC_FLAG_PREDICTIVE_PREFETCH) {
				arc_hdr_clear_flags(hdr,
				    ARC_FLAG_PREDICTIVE_PREFETCH);
			}

			if (*arc_flags & ARC_FLAG_WAIT) {
				cv_wait(&hdr->b_l1hdr.b_cv, hash_lock);
				mutex_exit(hash_lock);
				goto top;
			}
			ASSERT(*arc_flags & ARC_FLAG_NOWAIT);

			if (done) {
				arc_callback_t *acb = NULL;

				acb = kmem_zalloc(sizeof (arc_callback_t),
				    KM_SLEEP);
				acb->acb_done = done;
				acb->acb_private = private;
				acb->acb_compressed = compressed_read;
				if (pio != NULL)
					acb->acb_zio_dummy = zio_null(pio,
					    spa, NULL, NULL, NULL, zio_flags);

				ASSERT3P(acb->acb_done, !=, NULL);
				acb->acb_next = hdr->b_l1hdr.b_acb;
				hdr->b_l1hdr.b_acb = acb;
				mutex_exit(hash_lock);
				return (0);
			}
			mutex_exit(hash_lock);
			return (0);
		}

		ASSERT(hdr->b_l1hdr.b_state == arc_mru ||
		    hdr->b_l1hdr.b_state == arc_mfu);

		if (done) {
			if (hdr->b_flags & ARC_FLAG_PREDICTIVE_PREFETCH) {
				/*
				 * This is a demand read which does not have to
				 * wait for i/o because we did a predictive
				 * prefetch i/o for it, which has completed.
				 */
				DTRACE_PROBE1(
				    arc__demand__hit__predictive__prefetch,
				    arc_buf_hdr_t *, hdr);
				ARCSTAT_BUMP(
				    arcstat_demand_hit_predictive_prefetch);
				arc_hdr_clear_flags(hdr,
				    ARC_FLAG_PREDICTIVE_PREFETCH);
			}
			ASSERT(!BP_IS_EMBEDDED(bp) || !BP_IS_HOLE(bp));

			/* Get a buf with the desired data in it. */
			VERIFY0(arc_buf_alloc_impl(hdr, private,
			    compressed_read, B_TRUE, &buf));
		} else if (*arc_flags & ARC_FLAG_PREFETCH &&
		    refcount_count(&hdr->b_l1hdr.b_refcnt) == 0) {
			arc_hdr_set_flags(hdr, ARC_FLAG_PREFETCH);
		}
		DTRACE_PROBE1(arc__hit, arc_buf_hdr_t *, hdr);
		arc_access(hdr, hash_lock);
		if (*arc_flags & ARC_FLAG_L2CACHE)
			arc_hdr_set_flags(hdr, ARC_FLAG_L2CACHE);
		mutex_exit(hash_lock);
		ARCSTAT_BUMP(arcstat_hits);
		if (HDR_ISTYPE_DDT(hdr))
			ARCSTAT_BUMP(arcstat_ddt_hits);
		arc_update_hit_stat(hdr, B_TRUE);

		if (done)
			done(NULL, buf, private);
	} else {
		uint64_t lsize = BP_GET_LSIZE(bp);
		uint64_t psize = BP_GET_PSIZE(bp);
		arc_callback_t *acb;
		vdev_t *vd = NULL;
		uint64_t addr = 0;
		boolean_t devw = B_FALSE;
		uint64_t size;

		if (hdr == NULL) {
			/* this block is not in the cache */
			arc_buf_hdr_t *exists = NULL;
			arc_buf_contents_t type = BP_GET_BUFC_TYPE(bp);
			hdr = arc_hdr_alloc(spa_load_guid(spa), psize, lsize,
			    BP_GET_COMPRESS(bp), type);

			if (!BP_IS_EMBEDDED(bp)) {
				hdr->b_dva = *BP_IDENTITY(bp);
				hdr->b_birth = BP_PHYSICAL_BIRTH(bp);
				exists = buf_hash_insert(hdr, &hash_lock);
			}
			if (exists != NULL) {
				/* somebody beat us to the hash insert */
				arc_hdr_destroy(hdr);
				mutex_exit(hash_lock);
				goto top; /* restart the IO request */
			}
		} else {
			/*
			 * This block is in the ghost cache. If it was L2-only
			 * (and thus didn't have an L1 hdr), we realloc the
			 * header to add an L1 hdr.
			 */
			if (!HDR_HAS_L1HDR(hdr)) {
				hdr = arc_hdr_realloc(hdr, hdr_l2only_cache,
				    hdr_full_cache);
			}
			ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);
			ASSERT(GHOST_STATE(hdr->b_l1hdr.b_state));
			ASSERT(!HDR_IO_IN_PROGRESS(hdr));
			ASSERT(refcount_is_zero(&hdr->b_l1hdr.b_refcnt));
			ASSERT3P(hdr->b_l1hdr.b_buf, ==, NULL);
			ASSERT3P(hdr->b_freeze_cksum, ==, NULL);

			/*
			 * This is a delicate dance that we play here.
			 * This hdr is in the ghost list so we access it
			 * to move it out of the ghost list before we
			 * initiate the read. If it's a prefetch then
			 * it won't have a callback so we'll remove the
			 * reference that arc_buf_alloc_impl() created. We
			 * do this after we've called arc_access() to
			 * avoid hitting an assert in remove_reference().
			 */
			arc_access(hdr, hash_lock);
			arc_hdr_alloc_pabd(hdr);
		}
		ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);
		size = arc_hdr_size(hdr);

		/*
		 * If compression is enabled on the hdr, then will do
		 * RAW I/O and will store the compressed data in the hdr's
		 * data block. Otherwise, the hdr's data block will contain
		 * the uncompressed data.
		 */
		if (HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF) {
			zio_flags |= ZIO_FLAG_RAW;
		}

		if (*arc_flags & ARC_FLAG_PREFETCH)
			arc_hdr_set_flags(hdr, ARC_FLAG_PREFETCH);
		if (*arc_flags & ARC_FLAG_L2CACHE)
			arc_hdr_set_flags(hdr, ARC_FLAG_L2CACHE);
		if (BP_GET_LEVEL(bp) > 0)
			arc_hdr_set_flags(hdr, ARC_FLAG_INDIRECT);
		if (*arc_flags & ARC_FLAG_PREDICTIVE_PREFETCH)
			arc_hdr_set_flags(hdr, ARC_FLAG_PREDICTIVE_PREFETCH);
		ASSERT(!GHOST_STATE(hdr->b_l1hdr.b_state));

		acb = kmem_zalloc(sizeof (arc_callback_t), KM_SLEEP);
		acb->acb_done = done;
		acb->acb_private = private;
		acb->acb_compressed = compressed_read;

		ASSERT3P(hdr->b_l1hdr.b_acb, ==, NULL);
		hdr->b_l1hdr.b_acb = acb;
		arc_hdr_set_flags(hdr, ARC_FLAG_IO_IN_PROGRESS);

		if (HDR_HAS_L2HDR(hdr) &&
		    (vd = hdr->b_l2hdr.b_dev->l2ad_vdev) != NULL) {
			devw = hdr->b_l2hdr.b_dev->l2ad_writing;
			addr = hdr->b_l2hdr.b_daddr;
			/*
			 * Lock out device removal.
			 */
			if (vdev_is_dead(vd) ||
			    !spa_config_tryenter(spa, SCL_L2ARC, vd, RW_READER))
				vd = NULL;
		}

		if (priority == ZIO_PRIORITY_ASYNC_READ)
			arc_hdr_set_flags(hdr, ARC_FLAG_PRIO_ASYNC_READ);
		else
			arc_hdr_clear_flags(hdr, ARC_FLAG_PRIO_ASYNC_READ);

		if (hash_lock != NULL)
			mutex_exit(hash_lock);

		/*
		 * At this point, we have a level 1 cache miss.  Try again in
		 * L2ARC if possible.
		 */
		ASSERT3U(HDR_GET_LSIZE(hdr), ==, lsize);

		DTRACE_PROBE4(arc__miss, arc_buf_hdr_t *, hdr, blkptr_t *, bp,
		    uint64_t, lsize, zbookmark_phys_t *, zb);
		ARCSTAT_BUMP(arcstat_misses);
		arc_update_hit_stat(hdr, B_FALSE);

		if (vd != NULL && l2arc_ndev != 0 && !(l2arc_norw && devw)) {
			/*
			 * Read from the L2ARC if the following are true:
			 * 1. The L2ARC vdev was previously cached.
			 * 2. This buffer still has L2ARC metadata.
			 * 3. This buffer isn't currently writing to the L2ARC.
			 * 4. The L2ARC entry wasn't evicted, which may
			 *    also have invalidated the vdev.
			 * 5. This isn't prefetch and l2arc_noprefetch is set.
			 */
			if (HDR_HAS_L2HDR(hdr) &&
			    !HDR_L2_WRITING(hdr) && !HDR_L2_EVICTED(hdr) &&
			    !(l2arc_noprefetch && HDR_PREFETCH(hdr))) {
				l2arc_read_callback_t *cb;
				abd_t *abd;
				uint64_t asize;

				DTRACE_PROBE1(l2arc__hit, arc_buf_hdr_t *, hdr);
				ARCSTAT_BUMP(arcstat_l2_hits);
				if (vdev_type_is_ddt(vd))
					ARCSTAT_BUMP(arcstat_l2_ddt_hits);

				cb = kmem_zalloc(sizeof (l2arc_read_callback_t),
				    KM_SLEEP);
				cb->l2rcb_hdr = hdr;
				cb->l2rcb_bp = *bp;
				cb->l2rcb_zb = *zb;
				cb->l2rcb_flags = zio_flags;

				asize = vdev_psize_to_asize(vd, size);
				if (asize != size) {
					abd = abd_alloc_for_io(asize,
					    !HDR_ISTYPE_DATA(hdr));
					cb->l2rcb_abd = abd;
				} else {
					abd = hdr->b_l1hdr.b_pabd;
				}

				ASSERT(addr >= VDEV_LABEL_START_SIZE &&
				    addr + asize <= vd->vdev_psize -
				    VDEV_LABEL_END_SIZE);

				/*
				 * l2arc read.  The SCL_L2ARC lock will be
				 * released by l2arc_read_done().
				 * Issue a null zio if the underlying buffer
				 * was squashed to zero size by compression.
				 */
				ASSERT3U(HDR_GET_COMPRESS(hdr), !=,
				    ZIO_COMPRESS_EMPTY);
				rzio = zio_read_phys(pio, vd, addr,
				    asize, abd,
				    ZIO_CHECKSUM_OFF,
				    l2arc_read_done, cb, priority,
				    zio_flags | ZIO_FLAG_DONT_CACHE |
				    ZIO_FLAG_CANFAIL |
				    ZIO_FLAG_DONT_PROPAGATE |
				    ZIO_FLAG_DONT_RETRY, B_FALSE);
				DTRACE_PROBE2(l2arc__read, vdev_t *, vd,
				    zio_t *, rzio);

				ARCSTAT_INCR(arcstat_l2_read_bytes, size);
				if (vdev_type_is_ddt(vd))
					ARCSTAT_INCR(arcstat_l2_ddt_read_bytes,
					    size);

				if (*arc_flags & ARC_FLAG_NOWAIT) {
					zio_nowait(rzio);
					return (0);
				}

				ASSERT(*arc_flags & ARC_FLAG_WAIT);
				if (zio_wait(rzio) == 0)
					return (0);

				/* l2arc read error; goto zio_read() */
			} else {
				DTRACE_PROBE1(l2arc__miss,
				    arc_buf_hdr_t *, hdr);
				ARCSTAT_BUMP(arcstat_l2_misses);
				if (HDR_L2_WRITING(hdr))
					ARCSTAT_BUMP(arcstat_l2_rw_clash);
				spa_config_exit(spa, SCL_L2ARC, vd);
			}
		} else {
			if (vd != NULL)
				spa_config_exit(spa, SCL_L2ARC, vd);
			if (l2arc_ndev != 0) {
				DTRACE_PROBE1(l2arc__miss,
				    arc_buf_hdr_t *, hdr);
				ARCSTAT_BUMP(arcstat_l2_misses);
			}
		}

		rzio = zio_read(pio, spa, bp, hdr->b_l1hdr.b_pabd, size,
		    arc_read_done, hdr, priority, zio_flags, zb);

		if (*arc_flags & ARC_FLAG_WAIT)
			return (zio_wait(rzio));

		ASSERT(*arc_flags & ARC_FLAG_NOWAIT);
		zio_nowait(rzio);
	}
	return (0);
}

/*
 * Notify the arc that a block was freed, and thus will never be used again.
 */
void
arc_freed(spa_t *spa, const blkptr_t *bp)
{
	arc_buf_hdr_t *hdr;
	kmutex_t *hash_lock;
	uint64_t guid = spa_load_guid(spa);

	ASSERT(!BP_IS_EMBEDDED(bp));

	hdr = buf_hash_find(guid, bp, &hash_lock);
	if (hdr == NULL)
		return;

	/*
	 * We might be trying to free a block that is still doing I/O
	 * (i.e. prefetch) or has a reference (i.e. a dedup-ed,
	 * dmu_sync-ed block). If this block is being prefetched, then it
	 * would still have the ARC_FLAG_IO_IN_PROGRESS flag set on the hdr
	 * until the I/O completes. A block may also have a reference if it is
	 * part of a dedup-ed, dmu_synced write. The dmu_sync() function would
	 * have written the new block to its final resting place on disk but
	 * without the dedup flag set. This would have left the hdr in the MRU
	 * state and discoverable. When the txg finally syncs it detects that
	 * the block was overridden in open context and issues an override I/O.
	 * Since this is a dedup block, the override I/O will determine if the
	 * block is already in the DDT. If so, then it will replace the io_bp
	 * with the bp from the DDT and allow the I/O to finish. When the I/O
	 * reaches the done callback, dbuf_write_override_done, it will
	 * check to see if the io_bp and io_bp_override are identical.
	 * If they are not, then it indicates that the bp was replaced with
	 * the bp in the DDT and the override bp is freed. This allows
	 * us to arrive here with a reference on a block that is being
	 * freed. So if we have an I/O in progress, or a reference to
	 * this hdr, then we don't destroy the hdr.
	 */
	if (!HDR_HAS_L1HDR(hdr) || (!HDR_IO_IN_PROGRESS(hdr) &&
	    refcount_is_zero(&hdr->b_l1hdr.b_refcnt))) {
		arc_change_state(arc_anon, hdr, hash_lock);
		arc_hdr_destroy(hdr);
		mutex_exit(hash_lock);
	} else {
		mutex_exit(hash_lock);
	}

}

/*
 * Release this buffer from the cache, making it an anonymous buffer.  This
 * must be done after a read and prior to modifying the buffer contents.
 * If the buffer has more than one reference, we must make
 * a new hdr for the buffer.
 */
void
arc_release(arc_buf_t *buf, void *tag)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;

	/*
	 * It would be nice to assert that if it's DMU metadata (level >
	 * 0 || it's the dnode file), then it must be syncing context.
	 * But we don't know that information at this level.
	 */

	mutex_enter(&buf->b_evict_lock);

	ASSERT(HDR_HAS_L1HDR(hdr));

	/*
	 * We don't grab the hash lock prior to this check, because if
	 * the buffer's header is in the arc_anon state, it won't be
	 * linked into the hash table.
	 */
	if (hdr->b_l1hdr.b_state == arc_anon) {
		mutex_exit(&buf->b_evict_lock);
		ASSERT(!HDR_IO_IN_PROGRESS(hdr));
		ASSERT(!HDR_IN_HASH_TABLE(hdr));
		ASSERT(!HDR_HAS_L2HDR(hdr));
		ASSERT(HDR_EMPTY(hdr));

		ASSERT3U(hdr->b_l1hdr.b_bufcnt, ==, 1);
		ASSERT3S(refcount_count(&hdr->b_l1hdr.b_refcnt), ==, 1);
		ASSERT(!list_link_active(&hdr->b_l1hdr.b_arc_node));

		hdr->b_l1hdr.b_arc_access = 0;

		/*
		 * If the buf is being overridden then it may already
		 * have a hdr that is not empty.
		 */
		buf_discard_identity(hdr);
		arc_buf_thaw(buf);

		return;
	}

	kmutex_t *hash_lock = HDR_LOCK(hdr);
	mutex_enter(hash_lock);

	/*
	 * This assignment is only valid as long as the hash_lock is
	 * held, we must be careful not to reference state or the
	 * b_state field after dropping the lock.
	 */
	arc_state_t *state = hdr->b_l1hdr.b_state;
	ASSERT3P(hash_lock, ==, HDR_LOCK(hdr));
	ASSERT3P(state, !=, arc_anon);

	/* this buffer is not on any list */
	ASSERT3S(refcount_count(&hdr->b_l1hdr.b_refcnt), >, 0);

	if (HDR_HAS_L2HDR(hdr)) {
		mutex_enter(&hdr->b_l2hdr.b_dev->l2ad_mtx);

		/*
		 * We have to recheck this conditional again now that
		 * we're holding the l2ad_mtx to prevent a race with
		 * another thread which might be concurrently calling
		 * l2arc_evict(). In that case, l2arc_evict() might have
		 * destroyed the header's L2 portion as we were waiting
		 * to acquire the l2ad_mtx.
		 */
		if (HDR_HAS_L2HDR(hdr))
			arc_hdr_l2hdr_destroy(hdr);

		mutex_exit(&hdr->b_l2hdr.b_dev->l2ad_mtx);
	}

	/*
	 * Do we have more than one buf?
	 */
	if (hdr->b_l1hdr.b_bufcnt > 1) {
		arc_buf_hdr_t *nhdr;
		uint64_t spa = hdr->b_spa;
		uint64_t psize = HDR_GET_PSIZE(hdr);
		uint64_t lsize = HDR_GET_LSIZE(hdr);
		enum zio_compress compress = HDR_GET_COMPRESS(hdr);
		arc_buf_contents_t type = arc_buf_type(hdr);
		VERIFY3U(hdr->b_type, ==, type);

		ASSERT(hdr->b_l1hdr.b_buf != buf || buf->b_next != NULL);
		(void) remove_reference(hdr, hash_lock, tag);

		if (arc_buf_is_shared(buf) && !ARC_BUF_COMPRESSED(buf)) {
			ASSERT3P(hdr->b_l1hdr.b_buf, !=, buf);
			ASSERT(ARC_BUF_LAST(buf));
		}

		/*
		 * Pull the data off of this hdr and attach it to
		 * a new anonymous hdr. Also find the last buffer
		 * in the hdr's buffer list.
		 */
		arc_buf_t *lastbuf = arc_buf_remove(hdr, buf);
		ASSERT3P(lastbuf, !=, NULL);

		/*
		 * If the current arc_buf_t and the hdr are sharing their data
		 * buffer, then we must stop sharing that block.
		 */
		if (arc_buf_is_shared(buf)) {
			VERIFY(!arc_buf_is_shared(lastbuf));

			/*
			 * First, sever the block sharing relationship between
			 * buf and the arc_buf_hdr_t.
			 */
			arc_unshare_buf(hdr, buf);

			/*
			 * Now we need to recreate the hdr's b_pabd. Since we
			 * have lastbuf handy, we try to share with it, but if
			 * we can't then we allocate a new b_pabd and copy the
			 * data from buf into it.
			 */
			if (arc_can_share(hdr, lastbuf)) {
				arc_share_buf(hdr, lastbuf);
			} else {
				arc_hdr_alloc_pabd(hdr);
				abd_copy_from_buf(hdr->b_l1hdr.b_pabd,
				    buf->b_data, psize);
			}
			VERIFY3P(lastbuf->b_data, !=, NULL);
		} else if (HDR_SHARED_DATA(hdr)) {
			/*
			 * Uncompressed shared buffers are always at the end
			 * of the list. Compressed buffers don't have the
			 * same requirements. This makes it hard to
			 * simply assert that the lastbuf is shared so
			 * we rely on the hdr's compression flags to determine
			 * if we have a compressed, shared buffer.
			 */
			ASSERT(arc_buf_is_shared(lastbuf) ||
			    HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF);
			ASSERT(!ARC_BUF_SHARED(buf));
		}
		ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);
		ASSERT3P(state, !=, arc_l2c_only);

		(void) refcount_remove_many(&state->arcs_size,
		    arc_buf_size(buf), buf);

		if (refcount_is_zero(&hdr->b_l1hdr.b_refcnt)) {
			ASSERT3P(state, !=, arc_l2c_only);
			(void) refcount_remove_many(&state->arcs_esize[type],
			    arc_buf_size(buf), buf);
		}

		hdr->b_l1hdr.b_bufcnt -= 1;
		arc_cksum_verify(buf);
		arc_buf_unwatch(buf);

		mutex_exit(hash_lock);

		/*
		 * Allocate a new hdr. The new hdr will contain a b_pabd
		 * buffer which will be freed in arc_write().
		 */
		nhdr = arc_hdr_alloc(spa, psize, lsize, compress, type);
		ASSERT3P(nhdr->b_l1hdr.b_buf, ==, NULL);
		ASSERT0(nhdr->b_l1hdr.b_bufcnt);
		ASSERT0(refcount_count(&nhdr->b_l1hdr.b_refcnt));
		VERIFY3U(nhdr->b_type, ==, type);
		ASSERT(!HDR_SHARED_DATA(nhdr));

		nhdr->b_l1hdr.b_buf = buf;
		nhdr->b_l1hdr.b_bufcnt = 1;
		(void) refcount_add(&nhdr->b_l1hdr.b_refcnt, tag);
		nhdr->b_l1hdr.b_short_holders = 0;

		buf->b_hdr = nhdr;

		mutex_exit(&buf->b_evict_lock);
		(void) refcount_add_many(&arc_anon->arcs_size,
		    arc_buf_size(buf), buf);
	} else {
		mutex_exit(&buf->b_evict_lock);
		ASSERT(refcount_count(&hdr->b_l1hdr.b_refcnt) == 1);
		/* protected by hash lock, or hdr is on arc_anon */
		ASSERT(!multilist_link_active(&hdr->b_l1hdr.b_arc_node));
		ASSERT(!HDR_IO_IN_PROGRESS(hdr));
		arc_change_state(arc_anon, hdr, hash_lock);
		hdr->b_l1hdr.b_arc_access = 0;
		mutex_exit(hash_lock);

		buf_discard_identity(hdr);
		arc_buf_thaw(buf);
	}
}

int
arc_released(arc_buf_t *buf)
{
	int released;

	mutex_enter(&buf->b_evict_lock);
	released = (buf->b_data != NULL &&
	    buf->b_hdr->b_l1hdr.b_state == arc_anon);
	mutex_exit(&buf->b_evict_lock);
	return (released);
}

#ifdef ZFS_DEBUG
int
arc_referenced(arc_buf_t *buf)
{
	int referenced;

	mutex_enter(&buf->b_evict_lock);
	referenced = (refcount_count(&buf->b_hdr->b_l1hdr.b_refcnt));
	mutex_exit(&buf->b_evict_lock);
	return (referenced);
}
#endif

static void
arc_write_ready(zio_t *zio)
{
	arc_write_callback_t *callback = zio->io_private;
	arc_buf_t *buf = callback->awcb_buf;
	arc_buf_hdr_t *hdr = buf->b_hdr;
	uint64_t psize = BP_IS_HOLE(zio->io_bp) ? 0 : BP_GET_PSIZE(zio->io_bp);

	ASSERT(HDR_HAS_L1HDR(hdr));
	ASSERT(!refcount_is_zero(&buf->b_hdr->b_l1hdr.b_refcnt));
	ASSERT(hdr->b_l1hdr.b_bufcnt > 0);

	/*
	 * If we're reexecuting this zio because the pool suspended, then
	 * cleanup any state that was previously set the first time the
	 * callback was invoked.
	 */
	if (zio->io_flags & ZIO_FLAG_REEXECUTED) {
		arc_cksum_free(hdr);
		arc_buf_unwatch(buf);
		if (hdr->b_l1hdr.b_pabd != NULL) {
			if (arc_buf_is_shared(buf)) {
				arc_unshare_buf(hdr, buf);
			} else {
				arc_hdr_free_pabd(hdr);
			}
		}
	}
	ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);
	ASSERT(!HDR_SHARED_DATA(hdr));
	ASSERT(!arc_buf_is_shared(buf));

	callback->awcb_ready(zio, buf, callback->awcb_private);

	if (HDR_IO_IN_PROGRESS(hdr))
		ASSERT(zio->io_flags & ZIO_FLAG_REEXECUTED);

	arc_cksum_compute(buf);
	arc_hdr_set_flags(hdr, ARC_FLAG_IO_IN_PROGRESS);

	enum zio_compress compress;
	if (BP_IS_HOLE(zio->io_bp) || BP_IS_EMBEDDED(zio->io_bp)) {
		compress = ZIO_COMPRESS_OFF;
	} else {
		ASSERT3U(HDR_GET_LSIZE(hdr), ==, BP_GET_LSIZE(zio->io_bp));
		compress = BP_GET_COMPRESS(zio->io_bp);
	}
	HDR_SET_PSIZE(hdr, psize);
	arc_hdr_set_compress(hdr, compress);


	/*
	 * Fill the hdr with data. If the hdr is compressed, the data we want
	 * is available from the zio, otherwise we can take it from the buf.
	 *
	 * We might be able to share the buf's data with the hdr here. However,
	 * doing so would cause the ARC to be full of linear ABDs if we write a
	 * lot of shareable data. As a compromise, we check whether scattered
	 * ABDs are allowed, and assume that if they are then the user wants
	 * the ARC to be primarily filled with them regardless of the data being
	 * written. Therefore, if they're allowed then we allocate one and copy
	 * the data into it; otherwise, we share the data directly if we can.
	 */
	if (zfs_abd_scatter_enabled || !arc_can_share(hdr, buf)) {
		arc_hdr_alloc_pabd(hdr);

		/*
		 * Ideally, we would always copy the io_abd into b_pabd, but the
		 * user may have disabled compressed ARC, thus we must check the
		 * hdr's compression setting rather than the io_bp's.
		 */
		if (HDR_GET_COMPRESS(hdr) != ZIO_COMPRESS_OFF) {
			ASSERT3U(BP_GET_COMPRESS(zio->io_bp), !=,
			    ZIO_COMPRESS_OFF);
			ASSERT3U(psize, >, 0);

			abd_copy(hdr->b_l1hdr.b_pabd, zio->io_abd, psize);
		} else {
			ASSERT3U(zio->io_orig_size, ==, arc_hdr_size(hdr));

			abd_copy_from_buf(hdr->b_l1hdr.b_pabd, buf->b_data,
			    arc_buf_size(buf));
		}
	} else {
		ASSERT3P(buf->b_data, ==, abd_to_buf(zio->io_orig_abd));
		ASSERT3U(zio->io_orig_size, ==, arc_buf_size(buf));
		ASSERT3U(hdr->b_l1hdr.b_bufcnt, ==, 1);

		arc_share_buf(hdr, buf);
	}

	arc_hdr_verify(hdr, zio->io_bp);
}

static void
arc_write_children_ready(zio_t *zio)
{
	arc_write_callback_t *callback = zio->io_private;
	arc_buf_t *buf = callback->awcb_buf;

	callback->awcb_children_ready(zio, buf, callback->awcb_private);
}

/*
 * The SPA calls this callback for each physical write that happens on behalf
 * of a logical write.  See the comment in dbuf_write_physdone() for details.
 */
static void
arc_write_physdone(zio_t *zio)
{
	arc_write_callback_t *cb = zio->io_private;
	if (cb->awcb_physdone != NULL)
		cb->awcb_physdone(zio, cb->awcb_buf, cb->awcb_private);
}

static void
arc_write_done(zio_t *zio)
{
	arc_write_callback_t *callback = zio->io_private;
	arc_buf_t *buf = callback->awcb_buf;
	arc_buf_hdr_t *hdr = buf->b_hdr;

	ASSERT3P(hdr->b_l1hdr.b_acb, ==, NULL);

	if (zio->io_error == 0) {
		arc_hdr_verify(hdr, zio->io_bp);

		if (BP_IS_HOLE(zio->io_bp) || BP_IS_EMBEDDED(zio->io_bp)) {
			buf_discard_identity(hdr);
		} else {
			hdr->b_dva = *BP_IDENTITY(zio->io_bp);
			hdr->b_birth = BP_PHYSICAL_BIRTH(zio->io_bp);
		}
	} else {
		ASSERT(HDR_EMPTY(hdr));
	}

	/*
	 * If the block to be written was all-zero or compressed enough to be
	 * embedded in the BP, no write was performed so there will be no
	 * dva/birth/checksum.  The buffer must therefore remain anonymous
	 * (and uncached).
	 */
	if (!HDR_EMPTY(hdr)) {
		arc_buf_hdr_t *exists;
		kmutex_t *hash_lock;

		ASSERT3U(zio->io_error, ==, 0);

		arc_cksum_verify(buf);

		exists = buf_hash_insert(hdr, &hash_lock);
		if (exists != NULL) {
			/*
			 * This can only happen if we overwrite for
			 * sync-to-convergence, because we remove
			 * buffers from the hash table when we arc_free().
			 */
			if (zio->io_flags & ZIO_FLAG_IO_REWRITE) {
				if (!BP_EQUAL(&zio->io_bp_orig, zio->io_bp))
					panic("bad overwrite, hdr=%p exists=%p",
					    (void *)hdr, (void *)exists);
				ASSERT(refcount_is_zero(
				    &exists->b_l1hdr.b_refcnt));
				arc_change_state(arc_anon, exists, hash_lock);
				arc_wait_for_short_holders(exists);
				arc_hdr_destroy(exists);
				mutex_exit(hash_lock);
				exists = buf_hash_insert(hdr, &hash_lock);
				ASSERT3P(exists, ==, NULL);
			} else if (zio->io_flags & ZIO_FLAG_NOPWRITE) {
				/* nopwrite */
				ASSERT(zio->io_prop.zp_nopwrite);
				if (!BP_EQUAL(&zio->io_bp_orig, zio->io_bp))
					panic("bad nopwrite, hdr=%p exists=%p",
					    (void *)hdr, (void *)exists);
			} else {
				/* Dedup */
				ASSERT(hdr->b_l1hdr.b_bufcnt == 1);
				ASSERT(hdr->b_l1hdr.b_state == arc_anon);
				ASSERT(BP_GET_DEDUP(zio->io_bp));
				ASSERT(BP_GET_LEVEL(zio->io_bp) == 0);
			}
		}
		arc_hdr_clear_flags(hdr, ARC_FLAG_IO_IN_PROGRESS);
		/* if it's not anon, we are doing a scrub */
		if (exists == NULL && hdr->b_l1hdr.b_state == arc_anon)
			arc_access(hdr, hash_lock);
		mutex_exit(hash_lock);
	} else {
		arc_hdr_clear_flags(hdr, ARC_FLAG_IO_IN_PROGRESS);
	}

	ASSERT(!refcount_is_zero(&hdr->b_l1hdr.b_refcnt));
	callback->awcb_done(zio, buf, callback->awcb_private);

	abd_put(zio->io_abd);
	kmem_free(callback, sizeof (arc_write_callback_t));
}

zio_t *
arc_write(zio_t *pio, spa_t *spa, uint64_t txg, blkptr_t *bp, arc_buf_t *buf,
    boolean_t l2arc, const zio_prop_t *zp, arc_done_func_t *ready,
    arc_done_func_t *children_ready, arc_done_func_t *physdone,
    arc_done_func_t *done, void *private, zio_priority_t priority,
    int zio_flags, const zbookmark_phys_t *zb,
    const zio_smartcomp_info_t *smartcomp)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	arc_write_callback_t *callback;
	zio_t *zio;
	zio_prop_t localprop = *zp;

	ASSERT3P(ready, !=, NULL);
	ASSERT3P(done, !=, NULL);
	ASSERT(!HDR_IO_ERROR(hdr));
	ASSERT(!HDR_IO_IN_PROGRESS(hdr));
	ASSERT3P(hdr->b_l1hdr.b_acb, ==, NULL);
	ASSERT3U(hdr->b_l1hdr.b_bufcnt, >, 0);
	if (l2arc)
		arc_hdr_set_flags(hdr, ARC_FLAG_L2CACHE);
	if (ARC_BUF_COMPRESSED(buf)) {
		/*
		 * We're writing a pre-compressed buffer.  Make the
		 * compression algorithm requested by the zio_prop_t match
		 * the pre-compressed buffer's compression algorithm.
		 */
		localprop.zp_compress = HDR_GET_COMPRESS(hdr);

		ASSERT3U(HDR_GET_LSIZE(hdr), !=, arc_buf_size(buf));
		zio_flags |= ZIO_FLAG_RAW;
	}
	callback = kmem_zalloc(sizeof (arc_write_callback_t), KM_SLEEP);
	callback->awcb_ready = ready;
	callback->awcb_children_ready = children_ready;
	callback->awcb_physdone = physdone;
	callback->awcb_done = done;
	callback->awcb_private = private;
	callback->awcb_buf = buf;

	/*
	 * The hdr's b_pabd is now stale, free it now. A new data block
	 * will be allocated when the zio pipeline calls arc_write_ready().
	 */
	if (hdr->b_l1hdr.b_pabd != NULL) {
		/*
		 * If the buf is currently sharing the data block with
		 * the hdr then we need to break that relationship here.
		 * The hdr will remain with a NULL data pointer and the
		 * buf will take sole ownership of the block.
		 */
		if (arc_buf_is_shared(buf)) {
			arc_unshare_buf(hdr, buf);
		} else {
			arc_hdr_free_pabd(hdr);
		}
		VERIFY3P(buf->b_data, !=, NULL);
		arc_hdr_set_compress(hdr, ZIO_COMPRESS_OFF);
	}
	ASSERT(!arc_buf_is_shared(buf));
	ASSERT3P(hdr->b_l1hdr.b_pabd, ==, NULL);

	zio = zio_write(pio, spa, txg, bp,
	    abd_get_from_buf(buf->b_data, HDR_GET_LSIZE(hdr)),
	    HDR_GET_LSIZE(hdr), arc_buf_size(buf), &localprop, arc_write_ready,
	    (children_ready != NULL) ? arc_write_children_ready : NULL,
	    arc_write_physdone, arc_write_done, callback,
	    priority, zio_flags, zb, smartcomp);

	return (zio);
}

static int
arc_memory_throttle(uint64_t reserve, uint64_t txg)
{
#ifdef _KERNEL
	uint64_t available_memory = ptob(freemem);
	static uint64_t page_load = 0;
	static uint64_t last_txg = 0;

#if defined(__i386)
	available_memory =
	    MIN(available_memory, vmem_size(heap_arena, VMEM_FREE));
#endif

	if (freemem > physmem * arc_lotsfree_percent / 100)
		return (0);

	if (txg > last_txg) {
		last_txg = txg;
		page_load = 0;
	}
	/*
	 * If we are in pageout, we know that memory is already tight,
	 * the arc is already going to be evicting, so we just want to
	 * continue to let page writes occur as quickly as possible.
	 */
	if (curproc == proc_pageout) {
		if (page_load > MAX(ptob(minfree), available_memory) / 4)
			return (SET_ERROR(ERESTART));
		/* Note: reserve is inflated, so we deflate */
		page_load += reserve / 8;
		return (0);
	} else if (page_load > 0 && arc_reclaim_needed()) {
		/* memory is low, delay before restarting */
		ARCSTAT_INCR(arcstat_memory_throttle_count, 1);
		return (SET_ERROR(EAGAIN));
	}
	page_load = 0;
#endif
	return (0);
}

void
arc_tempreserve_clear(uint64_t reserve)
{
	atomic_add_64(&arc_tempreserve, -reserve);
	ASSERT((int64_t)arc_tempreserve >= 0);
}

int
arc_tempreserve_space(uint64_t reserve, uint64_t txg)
{
	int error;
	uint64_t anon_size;

	if (reserve > arc_c/4 && !arc_no_grow)
		arc_c = MIN(arc_c_max, reserve * 4);
	if (reserve > arc_c)
		return (SET_ERROR(ENOMEM));

	/*
	 * Don't count loaned bufs as in flight dirty data to prevent long
	 * network delays from blocking transactions that are ready to be
	 * assigned to a txg.
	 */

	/* assert that it has not wrapped around */
	ASSERT3S(atomic_add_64_nv(&arc_loaned_bytes, 0), >=, 0);

	anon_size = MAX((int64_t)(refcount_count(&arc_anon->arcs_size) -
	    arc_loaned_bytes), 0);

	/*
	 * Writes will, almost always, require additional memory allocations
	 * in order to compress/encrypt/etc the data.  We therefore need to
	 * make sure that there is sufficient available memory for this.
	 */
	error = arc_memory_throttle(reserve, txg);
	if (error != 0)
		return (error);

	/*
	 * Throttle writes when the amount of dirty data in the cache
	 * gets too large.  We try to keep the cache less than half full
	 * of dirty blocks so that our sync times don't grow too large.
	 * Note: if two requests come in concurrently, we might let them
	 * both succeed, when one of them should fail.  Not a huge deal.
	 */
	if (reserve + arc_tempreserve + anon_size > arc_c / 2 &&
	    anon_size > arc_c / 4) {
		DTRACE_PROBE4(arc__tempreserve__space__throttle, uint64_t,
		    arc_tempreserve, arc_state_t *, arc_anon, uint64_t,
		    reserve, uint64_t, arc_c);

		uint64_t meta_esize =
		    refcount_count(&arc_anon->arcs_esize[ARC_BUFC_METADATA]);
		uint64_t data_esize =
		    refcount_count(&arc_anon->arcs_esize[ARC_BUFC_DATA]);
		dprintf("failing, arc_tempreserve=%lluK anon_meta=%lluK "
		    "anon_data=%lluK tempreserve=%lluK arc_c=%lluK\n",
		    arc_tempreserve >> 10, meta_esize >> 10,
		    data_esize >> 10, reserve >> 10, arc_c >> 10);
		return (SET_ERROR(ERESTART));
	}
	atomic_add_64(&arc_tempreserve, reserve);
	return (0);
}

static void
arc_kstat_update_state(arc_state_t *state, kstat_named_t *size,
    kstat_named_t *evict_data, kstat_named_t *evict_metadata,
    kstat_named_t *evict_ddt)
{
	size->value.ui64 = refcount_count(&state->arcs_size);
	evict_data->value.ui64 =
	    refcount_count(&state->arcs_esize[ARC_BUFC_DATA]);
	evict_metadata->value.ui64 =
	    refcount_count(&state->arcs_esize[ARC_BUFC_METADATA]);
	evict_ddt->value.ui64 =
	    refcount_count(&state->arcs_esize[ARC_BUFC_DDT]);
}

static int
arc_kstat_update(kstat_t *ksp, int rw)
{
	arc_stats_t *as = ksp->ks_data;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		arc_kstat_update_state(arc_anon,
		    &as->arcstat_anon_size,
		    &as->arcstat_anon_evictable_data,
		    &as->arcstat_anon_evictable_metadata,
		    &as->arcstat_anon_evictable_ddt);
		arc_kstat_update_state(arc_mru,
		    &as->arcstat_mru_size,
		    &as->arcstat_mru_evictable_data,
		    &as->arcstat_mru_evictable_metadata,
		    &as->arcstat_mru_evictable_ddt);
		arc_kstat_update_state(arc_mru_ghost,
		    &as->arcstat_mru_ghost_size,
		    &as->arcstat_mru_ghost_evictable_data,
		    &as->arcstat_mru_ghost_evictable_metadata,
		    &as->arcstat_mru_ghost_evictable_ddt);
		arc_kstat_update_state(arc_mfu,
		    &as->arcstat_mfu_size,
		    &as->arcstat_mfu_evictable_data,
		    &as->arcstat_mfu_evictable_metadata,
		    &as->arcstat_mfu_evictable_ddt);
		arc_kstat_update_state(arc_mfu_ghost,
		    &as->arcstat_mfu_ghost_size,
		    &as->arcstat_mfu_ghost_evictable_data,
		    &as->arcstat_mfu_ghost_evictable_metadata,
		    &as->arcstat_mfu_ghost_evictable_ddt);

		ARCSTAT(arcstat_size) = aggsum_value(&arc_size);
		ARCSTAT(arcstat_meta_used) = aggsum_value(&arc_meta_used);
		ARCSTAT(arcstat_data_size) = aggsum_value(&astat_data_size);
		ARCSTAT(arcstat_ddt_size) = aggsum_value(&astat_ddt_size);
		ARCSTAT(arcstat_metadata_size) =
		    aggsum_value(&astat_metadata_size);
		ARCSTAT(arcstat_hdr_size) = aggsum_value(&astat_hdr_size);
		ARCSTAT(arcstat_other_size) = aggsum_value(&astat_other_size);
		ARCSTAT(arcstat_l2_hdr_size) = aggsum_value(&astat_l2_hdr_size);
	}

	return (0);
}

/*
 * This function *must* return indices evenly distributed between all
 * sublists of the multilist. This is needed due to how the ARC eviction
 * code is laid out; arc_evict_state() assumes ARC buffers are evenly
 * distributed between all sublists and uses this assumption when
 * deciding which sublist to evict from and how much to evict from it.
 */
unsigned int
arc_state_multilist_index_func(multilist_t *ml, void *obj)
{
	arc_buf_hdr_t *hdr = obj;

	/*
	 * We rely on b_dva to generate evenly distributed index
	 * numbers using buf_hash below. So, as an added precaution,
	 * let's make sure we never add empty buffers to the arc lists.
	 */
	ASSERT(!HDR_EMPTY(hdr));

	/*
	 * The assumption here, is the hash value for a given
	 * arc_buf_hdr_t will remain constant throughout it's lifetime
	 * (i.e. it's b_spa, b_dva, and b_birth fields don't change).
	 * Thus, we don't need to store the header's sublist index
	 * on insertion, as this index can be recalculated on removal.
	 *
	 * Also, the low order bits of the hash value are thought to be
	 * distributed evenly. Otherwise, in the case that the multilist
	 * has a power of two number of sublists, each sublists' usage
	 * would not be evenly distributed.
	 */
	return (buf_hash(hdr->b_spa, &hdr->b_dva, hdr->b_birth) %
	    multilist_get_num_sublists(ml));
}

static void
arc_state_init(void)
{
	arc_anon = &ARC_anon;
	arc_mru = &ARC_mru;
	arc_mru_ghost = &ARC_mru_ghost;
	arc_mfu = &ARC_mfu;
	arc_mfu_ghost = &ARC_mfu_ghost;
	arc_l2c_only = &ARC_l2c_only;
	arc_buf_contents_t arcs;

	for (arcs = ARC_BUFC_DATA; arcs < ARC_BUFC_NUMTYPES; ++arcs) {
		arc_mru->arcs_list[arcs] =
		    multilist_create(sizeof (arc_buf_hdr_t),
		    offsetof(arc_buf_hdr_t, b_l1hdr.b_arc_node),
		    arc_state_multilist_index_func);
		arc_mru_ghost->arcs_list[arcs] =
		    multilist_create(sizeof (arc_buf_hdr_t),
		    offsetof(arc_buf_hdr_t, b_l1hdr.b_arc_node),
			arc_state_multilist_index_func);
		arc_mfu->arcs_list[arcs] =
		    multilist_create(sizeof (arc_buf_hdr_t),
		    offsetof(arc_buf_hdr_t, b_l1hdr.b_arc_node),
		    arc_state_multilist_index_func);
		arc_mfu_ghost->arcs_list[arcs] =
		    multilist_create(sizeof (arc_buf_hdr_t),
		    offsetof(arc_buf_hdr_t, b_l1hdr.b_arc_node),
		    arc_state_multilist_index_func);
		arc_l2c_only->arcs_list[arcs] =
		    multilist_create(sizeof (arc_buf_hdr_t),
		    offsetof(arc_buf_hdr_t, b_l1hdr.b_arc_node),
		    arc_state_multilist_index_func);

		refcount_create(&arc_anon->arcs_esize[arcs]);
		refcount_create(&arc_mru->arcs_esize[arcs]);
		refcount_create(&arc_mru_ghost->arcs_esize[arcs]);
		refcount_create(&arc_mfu->arcs_esize[arcs]);
		refcount_create(&arc_mfu_ghost->arcs_esize[arcs]);
		refcount_create(&arc_l2c_only->arcs_esize[arcs]);
	}

	arc_flush_taskq = taskq_create("arc_flush_tq",
	    max_ncpus, minclsyspri, 1, zfs_flush_ntasks, TASKQ_DYNAMIC);

	refcount_create(&arc_anon->arcs_size);
	refcount_create(&arc_mru->arcs_size);
	refcount_create(&arc_mru_ghost->arcs_size);
	refcount_create(&arc_mfu->arcs_size);
	refcount_create(&arc_mfu_ghost->arcs_size);
	refcount_create(&arc_l2c_only->arcs_size);

	aggsum_init(&arc_meta_used, 0);
	aggsum_init(&arc_size, 0);
	aggsum_init(&astat_data_size, 0);
	aggsum_init(&astat_ddt_size, 0);
	aggsum_init(&astat_metadata_size, 0);
	aggsum_init(&astat_hdr_size, 0);
	aggsum_init(&astat_other_size, 0);
	aggsum_init(&astat_l2_hdr_size, 0);
}

static void
arc_state_fini(void)
{
	arc_buf_contents_t arcs;

	refcount_destroy(&arc_anon->arcs_size);
	refcount_destroy(&arc_mru->arcs_size);
	refcount_destroy(&arc_mru_ghost->arcs_size);
	refcount_destroy(&arc_mfu->arcs_size);
	refcount_destroy(&arc_mfu_ghost->arcs_size);
	refcount_destroy(&arc_l2c_only->arcs_size);

	for (arcs = ARC_BUFC_DATA; arcs < ARC_BUFC_NUMTYPES; ++arcs) {
		multilist_destroy(arc_mru->arcs_list[arcs]);
		multilist_destroy(arc_mru_ghost->arcs_list[arcs]);
		multilist_destroy(arc_mfu->arcs_list[arcs]);
		multilist_destroy(arc_mfu_ghost->arcs_list[arcs]);
		multilist_destroy(arc_l2c_only->arcs_list[arcs]);

		refcount_destroy(&arc_anon->arcs_esize[arcs]);
		refcount_destroy(&arc_mru->arcs_esize[arcs]);
		refcount_destroy(&arc_mru_ghost->arcs_esize[arcs]);
		refcount_destroy(&arc_mfu->arcs_esize[arcs]);
		refcount_destroy(&arc_mfu_ghost->arcs_esize[arcs]);
		refcount_destroy(&arc_l2c_only->arcs_esize[arcs]);
	}
}

uint64_t
arc_max_bytes(void)
{
	return (arc_c_max);
}

void
arc_init(void)
{
	/*
	 * allmem is "all memory that we could possibly use".
	 */
#ifdef _KERNEL
	uint64_t allmem = ptob(physmem - swapfs_minfree);
#else
	uint64_t allmem = (physmem * PAGESIZE) / 2;
#endif

	mutex_init(&arc_reclaim_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&arc_reclaim_thread_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&arc_reclaim_waiters_cv, NULL, CV_DEFAULT, NULL);

	/* Convert seconds to clock ticks */
	arc_min_prefetch_lifespan = 1 * hz;

	/* set min cache to 1/32 of all memory, or 64MB, whichever is more */
	arc_c_min = MAX(allmem / 32, 64 << 20);
	/* set max to 3/4 of all memory, or all but 1GB, whichever is more */
	if (allmem >= 1 << 30)
		arc_c_max = allmem - (1 << 30);
	else
		arc_c_max = arc_c_min;
	arc_c_max = MAX(allmem * 3 / 4, arc_c_max);

	/*
	 * In userland, there's only the memory pressure that we artificially
	 * create (see arc_available_memory()).  Don't let arc_c get too
	 * small, because it can cause transactions to be larger than
	 * arc_c, causing arc_tempreserve_space() to fail.
	 */
#ifndef _KERNEL
	arc_c_min = arc_c_max / 2;
#endif

	/*
	 * Allow the tunables to override our calculations if they are
	 * reasonable (ie. over 64MB)
	 */
	if (zfs_arc_max > 64 << 20 && zfs_arc_max < allmem) {
		arc_c_max = zfs_arc_max;
		arc_c_min = MIN(arc_c_min, arc_c_max);
	}
	if (zfs_arc_min > 64 << 20 && zfs_arc_min <= arc_c_max)
		arc_c_min = zfs_arc_min;

	arc_c = arc_c_max;
	arc_p = (arc_c >> 1);

	/* limit ddt meta-data to 1/4 of the arc capacity */
	arc_ddt_limit = arc_c_max / 4;
	/* limit meta-data to 1/4 of the arc capacity */
	arc_meta_limit = arc_c_max / 4;

#ifdef _KERNEL
	/*
	 * Metadata is stored in the kernel's heap.  Don't let us
	 * use more than half the heap for the ARC.
	 */
	arc_meta_limit = MIN(arc_meta_limit,
	    vmem_size(heap_arena, VMEM_ALLOC | VMEM_FREE) / 2);
#endif

	/* Allow the tunable to override if it is reasonable */
	if (zfs_arc_ddt_limit > 0 && zfs_arc_ddt_limit <= arc_c_max)
		arc_ddt_limit = zfs_arc_ddt_limit;
	arc_ddt_evict_threshold =
	    zfs_arc_segregate_ddt ? &arc_ddt_limit : &arc_meta_limit;

	/* Allow the tunable to override if it is reasonable */
	if (zfs_arc_meta_limit > 0 && zfs_arc_meta_limit <= arc_c_max)
		arc_meta_limit = zfs_arc_meta_limit;

	if (arc_c_min < arc_meta_limit / 2 && zfs_arc_min == 0)
		arc_c_min = arc_meta_limit / 2;

	if (zfs_arc_meta_min > 0) {
		arc_meta_min = zfs_arc_meta_min;
	} else {
		arc_meta_min = arc_c_min / 2;
	}

	if (zfs_arc_grow_retry > 0)
		arc_grow_retry = zfs_arc_grow_retry;

	if (zfs_arc_shrink_shift > 0)
		arc_shrink_shift = zfs_arc_shrink_shift;

	/*
	 * Ensure that arc_no_grow_shift is less than arc_shrink_shift.
	 */
	if (arc_no_grow_shift >= arc_shrink_shift)
		arc_no_grow_shift = arc_shrink_shift - 1;

	if (zfs_arc_p_min_shift > 0)
		arc_p_min_shift = zfs_arc_p_min_shift;

	/* if kmem_flags are set, lets try to use less memory */
	if (kmem_debugging())
		arc_c = arc_c / 2;
	if (arc_c < arc_c_min)
		arc_c = arc_c_min;

	arc_state_init();
	buf_init();

	arc_reclaim_thread_exit = B_FALSE;

	arc_ksp = kstat_create("zfs", 0, "arcstats", "misc", KSTAT_TYPE_NAMED,
	    sizeof (arc_stats) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);

	if (arc_ksp != NULL) {
		arc_ksp->ks_data = &arc_stats;
		arc_ksp->ks_update = arc_kstat_update;
		kstat_install(arc_ksp);
	}

	(void) thread_create(NULL, 0, arc_reclaim_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);

	arc_dead = B_FALSE;
	arc_warm = B_FALSE;

	/*
	 * Calculate maximum amount of dirty data per pool.
	 *
	 * If it has been set by /etc/system, take that.
	 * Otherwise, use a percentage of physical memory defined by
	 * zfs_dirty_data_max_percent (default 10%) with a cap at
	 * zfs_dirty_data_max_max (default 4GB).
	 */
	if (zfs_dirty_data_max == 0) {
		zfs_dirty_data_max = physmem * PAGESIZE *
		    zfs_dirty_data_max_percent / 100;
		zfs_dirty_data_max = MIN(zfs_dirty_data_max,
		    zfs_dirty_data_max_max);
	}
}

void
arc_fini(void)
{
	mutex_enter(&arc_reclaim_lock);
	arc_reclaim_thread_exit = B_TRUE;
	/*
	 * The reclaim thread will set arc_reclaim_thread_exit back to
	 * B_FALSE when it is finished exiting; we're waiting for that.
	 */
	while (arc_reclaim_thread_exit) {
		cv_signal(&arc_reclaim_thread_cv);
		cv_wait(&arc_reclaim_thread_cv, &arc_reclaim_lock);
	}
	mutex_exit(&arc_reclaim_lock);

	/* Use B_TRUE to ensure *all* buffers are evicted */
	arc_flush(NULL, B_TRUE);

	arc_dead = B_TRUE;

	if (arc_ksp != NULL) {
		kstat_delete(arc_ksp);
		arc_ksp = NULL;
	}

	taskq_destroy(arc_flush_taskq);

	mutex_destroy(&arc_reclaim_lock);
	cv_destroy(&arc_reclaim_thread_cv);
	cv_destroy(&arc_reclaim_waiters_cv);

	arc_state_fini();
	buf_fini();

	ASSERT0(arc_loaned_bytes);
}

/*
 * Level 2 ARC
 *
 * The level 2 ARC (L2ARC) is a cache layer in-between main memory and disk.
 * It uses dedicated storage devices to hold cached data, which are populated
 * using large infrequent writes.  The main role of this cache is to boost
 * the performance of random read workloads.  The intended L2ARC devices
 * include short-stroked disks, solid state disks, and other media with
 * substantially faster read latency than disk.
 *
 *                 +-----------------------+
 *                 |         ARC           |
 *                 +-----------------------+
 *                    |         ^     ^
 *                    |         |     |
 *      l2arc_feed_thread()    arc_read()
 *                    |         |     |
 *                    |  l2arc read   |
 *                    V         |     |
 *               +---------------+    |
 *               |     L2ARC     |    |
 *               +---------------+    |
 *                   |    ^           |
 *          l2arc_write() |           |
 *                   |    |           |
 *                   V    |           |
 *                 +-------+      +-------+
 *                 | vdev  |      | vdev  |
 *                 | cache |      | cache |
 *                 +-------+      +-------+
 *                 +=========+     .-----.
 *                 :  L2ARC  :    |-_____-|
 *                 : devices :    | Disks |
 *                 +=========+    `-_____-'
 *
 * Read requests are satisfied from the following sources, in order:
 *
 *	1) ARC
 *	2) vdev cache of L2ARC devices
 *	3) L2ARC devices
 *	4) vdev cache of disks
 *	5) disks
 *
 * Some L2ARC device types exhibit extremely slow write performance.
 * To accommodate for this there are some significant differences between
 * the L2ARC and traditional cache design:
 *
 * 1. There is no eviction path from the ARC to the L2ARC.  Evictions from
 * the ARC behave as usual, freeing buffers and placing headers on ghost
 * lists.  The ARC does not send buffers to the L2ARC during eviction as
 * this would add inflated write latencies for all ARC memory pressure.
 *
 * 2. The L2ARC attempts to cache data from the ARC before it is evicted.
 * It does this by periodically scanning buffers from the eviction-end of
 * the MFU and MRU ARC lists, copying them to the L2ARC devices if they are
 * not already there. It scans until a headroom of buffers is satisfied,
 * which itself is a buffer for ARC eviction. If a compressible buffer is
 * found during scanning and selected for writing to an L2ARC device, we
 * temporarily boost scanning headroom during the next scan cycle to make
 * sure we adapt to compression effects (which might significantly reduce
 * the data volume we write to L2ARC). The thread that does this is
 * l2arc_feed_thread(), illustrated below; example sizes are included to
 * provide a better sense of ratio than this diagram:
 *
 *	       head -->                        tail
 *	        +---------------------+----------+
 *	ARC_mfu |:::::#:::::::::::::::|o#o###o###|-->.   # already on L2ARC
 *	        +---------------------+----------+   |   o L2ARC eligible
 *	ARC_mru |:#:::::::::::::::::::|#o#ooo####|-->|   : ARC buffer
 *	        +---------------------+----------+   |
 *	             15.9 Gbytes      ^ 32 Mbytes    |
 *	                           headroom          |
 *	                                      l2arc_feed_thread()
 *	                                             |
 *	                 l2arc write hand <--[oooo]--'
 *	                         |           8 Mbyte
 *	                         |          write max
 *	                         V
 *		  +==============================+
 *	L2ARC dev |####|#|###|###|    |####| ... |
 *	          +==============================+
 *	                     32 Gbytes
 *
 * 3. If an ARC buffer is copied to the L2ARC but then hit instead of
 * evicted, then the L2ARC has cached a buffer much sooner than it probably
 * needed to, potentially wasting L2ARC device bandwidth and storage.  It is
 * safe to say that this is an uncommon case, since buffers at the end of
 * the ARC lists have moved there due to inactivity.
 *
 * 4. If the ARC evicts faster than the L2ARC can maintain a headroom,
 * then the L2ARC simply misses copying some buffers.  This serves as a
 * pressure valve to prevent heavy read workloads from both stalling the ARC
 * with waits and clogging the L2ARC with writes.  This also helps prevent
 * the potential for the L2ARC to churn if it attempts to cache content too
 * quickly, such as during backups of the entire pool.
 *
 * 5. After system boot and before the ARC has filled main memory, there are
 * no evictions from the ARC and so the tails of the ARC_mfu and ARC_mru
 * lists can remain mostly static.  Instead of searching from tail of these
 * lists as pictured, the l2arc_feed_thread() will search from the list heads
 * for eligible buffers, greatly increasing its chance of finding them.
 *
 * The L2ARC device write speed is also boosted during this time so that
 * the L2ARC warms up faster.  Since there have been no ARC evictions yet,
 * there are no L2ARC reads, and no fear of degrading read performance
 * through increased writes.
 *
 * 6. Writes to the L2ARC devices are grouped and sent in-sequence, so that
 * the vdev queue can aggregate them into larger and fewer writes.  Each
 * device is written to in a rotor fashion, sweeping writes through
 * available space then repeating.
 *
 * 7. The L2ARC does not store dirty content.  It never needs to flush
 * write buffers back to disk based storage.
 *
 * 8. If an ARC buffer is written (and dirtied) which also exists in the
 * L2ARC, the now stale L2ARC buffer is immediately dropped.
 *
 * The performance of the L2ARC can be tweaked by a number of tunables, which
 * may be necessary for different workloads:
 *
 *	l2arc_write_max		max write bytes per interval
 *	l2arc_write_boost	extra write bytes during device warmup
 *	l2arc_noprefetch	skip caching prefetched buffers
 *	l2arc_headroom		number of max device writes to precache
 *	l2arc_headroom_boost	when we find compressed buffers during ARC
 *				scanning, we multiply headroom by this
 *				percentage factor for the next scan cycle,
 *				since more compressed buffers are likely to
 *				be present
 *	l2arc_feed_secs		seconds between L2ARC writing
 *
 * Tunables may be removed or added as future performance improvements are
 * integrated, and also may become zpool properties.
 *
 * There are three key functions that control how the L2ARC warms up:
 *
 *	l2arc_write_eligible()	check if a buffer is eligible to cache
 *	l2arc_write_size()	calculate how much to write
 *	l2arc_write_interval()	calculate sleep delay between writes
 *
 * These three functions determine what to write, how much, and how quickly
 * to send writes.
 *
 * L2ARC persistency:
 *
 * When writing buffers to L2ARC, we periodically add some metadata to
 * make sure we can pick them up after reboot, thus dramatically reducing
 * the impact that any downtime has on the performance of storage systems
 * with large caches.
 *
 * The implementation works fairly simply by integrating the following two
 * modifications:
 *
 * *) Every now and then we mix in a piece of metadata (called a log block)
 *    into the L2ARC write. This allows us to understand what's been written,
 *    so that we can rebuild the arc_buf_hdr_t structures of the main ARC
 *    buffers. The log block also includes a "2-back-reference" pointer to
 *    he second-to-previous block, forming a back-linked list of blocks on
 *    the L2ARC device.
 *
 * *) We reserve SPA_MINBLOCKSIZE of space at the start of each L2ARC device
 *    for our header bookkeeping purposes. This contains a device header,
 *    which contains our top-level reference structures. We update it each
 *    time we write a new log block, so that we're able to locate it in the
 *    L2ARC device. If this write results in an inconsistent device header
 *    (e.g. due to power failure), we detect this by verifying the header's
 *    checksum and simply drop the entries from L2ARC.
 *
 * Implementation diagram:
 *
 * +=== L2ARC device (not to scale) ======================================+
 * |       ___two newest log block pointers__.__________                  |
 * |      /                                   \1 back   \latest           |
 * |.____/_.                                   V         V                |
 * ||L2 dev|....|lb |bufs |lb |bufs |lb |bufs |lb |bufs |lb |---(empty)---|
 * ||   hdr|      ^         /^       /^        /         /                |
 * |+------+  ...--\-------/  \-----/--\------/         /                 |
 * |                \--------------/    \--------------/                  |
 * +======================================================================+
 *
 * As can be seen on the diagram, rather than using a simple linked list,
 * we use a pair of linked lists with alternating elements. This is a
 * performance enhancement due to the fact that we only find out of the
 * address of the next log block access once the current block has been
 * completely read in. Obviously, this hurts performance, because we'd be
 * keeping the device's I/O queue at only a 1 operation deep, thus
 * incurring a large amount of I/O round-trip latency. Having two lists
 * allows us to "prefetch" two log blocks ahead of where we are currently
 * rebuilding L2ARC buffers.
 *
 * On-device data structures:
 *
 * L2ARC device header:	l2arc_dev_hdr_phys_t
 * L2ARC log block:	l2arc_log_blk_phys_t
 *
 * L2ARC reconstruction:
 *
 * When writing data, we simply write in the standard rotary fashion,
 * evicting buffers as we go and simply writing new data over them (writing
 * a new log block every now and then). This obviously means that once we
 * loop around the end of the device, we will start cutting into an already
 * committed log block (and its referenced data buffers), like so:
 *
 *    current write head__       __old tail
 *                        \     /
 *                        V    V
 * <--|bufs |lb |bufs |lb |    |bufs |lb |bufs |lb |-->
 *                         ^    ^^^^^^^^^___________________________________
 *                         |                                                \
 *                   <<nextwrite>> may overwrite this blk and/or its bufs --'
 *
 * When importing the pool, we detect this situation and use it to stop
 * our scanning process (see l2arc_rebuild).
 *
 * There is one significant caveat to consider when rebuilding ARC contents
 * from an L2ARC device: what about invalidated buffers? Given the above
 * construction, we cannot update blocks which we've already written to amend
 * them to remove buffers which were invalidated. Thus, during reconstruction,
 * we might be populating the cache with buffers for data that's not on the
 * main pool anymore, or may have been overwritten!
 *
 * As it turns out, this isn't a problem. Every arc_read request includes
 * both the DVA and, crucially, the birth TXG of the BP the caller is
 * looking for. So even if the cache were populated by completely rotten
 * blocks for data that had been long deleted and/or overwritten, we'll
 * never actually return bad data from the cache, since the DVA with the
 * birth TXG uniquely identify a block in space and time - once created,
 * a block is immutable on disk. The worst thing we have done is wasted
 * some time and memory at l2arc rebuild to reconstruct outdated ARC
 * entries that will get dropped from the l2arc as it is being updated
 * with new blocks.
 */

static boolean_t
l2arc_write_eligible(uint64_t spa_guid, arc_buf_hdr_t *hdr)
{
	/*
	 * A buffer is *not* eligible for the L2ARC if it:
	 * 1. belongs to a different spa.
	 * 2. is already cached on the L2ARC.
	 * 3. has an I/O in progress (it may be an incomplete read).
	 * 4. is flagged not eligible (zfs property).
	 */
	if (hdr->b_spa != spa_guid || HDR_HAS_L2HDR(hdr) ||
	    HDR_IO_IN_PROGRESS(hdr) || !HDR_L2CACHE(hdr))
		return (B_FALSE);

	return (B_TRUE);
}

static uint64_t
l2arc_write_size(void)
{
	uint64_t size;

	/*
	 * Make sure our globals have meaningful values in case the user
	 * altered them.
	 */
	size = l2arc_write_max;
	if (size == 0) {
		cmn_err(CE_NOTE, "Bad value for l2arc_write_max, value must "
		    "be greater than zero, resetting it to the default (%d)",
		    L2ARC_WRITE_SIZE);
		size = l2arc_write_max = L2ARC_WRITE_SIZE;
	}

	if (arc_warm == B_FALSE)
		size += l2arc_write_boost;

	return (size);

}

static clock_t
l2arc_write_interval(clock_t began, uint64_t wanted, uint64_t wrote)
{
	clock_t interval, next, now;

	/*
	 * If the ARC lists are busy, increase our write rate; if the
	 * lists are stale, idle back.  This is achieved by checking
	 * how much we previously wrote - if it was more than half of
	 * what we wanted, schedule the next write much sooner.
	 */
	if (l2arc_feed_again && wrote > (wanted / 2))
		interval = (hz * l2arc_feed_min_ms) / 1000;
	else
		interval = hz * l2arc_feed_secs;

	now = ddi_get_lbolt();
	next = MAX(now, MIN(now + interval, began + interval));

	return (next);
}

typedef enum l2ad_feed {
	L2ARC_FEED_ALL = 1,
	L2ARC_FEED_DDT_DEV,
	L2ARC_FEED_NON_DDT_DEV,
} l2ad_feed_t;

/*
 * Cycle through L2ARC devices.  This is how L2ARC load balances.
 * If a device is returned, this also returns holding the spa config lock.
 */
static l2arc_dev_t *
l2arc_dev_get_next(l2ad_feed_t feed_type)
{
	l2arc_dev_t *start = NULL, *next = NULL;

	/*
	 * Lock out the removal of spas (spa_namespace_lock), then removal
	 * of cache devices (l2arc_dev_mtx).  Once a device has been selected,
	 * both locks will be dropped and a spa config lock held instead.
	 */
	mutex_enter(&spa_namespace_lock);
	mutex_enter(&l2arc_dev_mtx);

	/* if there are no vdevs, there is nothing to do */
	if (l2arc_ndev == 0)
		goto out;

	if (feed_type == L2ARC_FEED_DDT_DEV)
		next = l2arc_ddt_dev_last;
	else
		next = l2arc_dev_last;

	/* figure out what the next device we look at should be */
	if (next == NULL)
		next = list_head(l2arc_dev_list);
	else if (list_next(l2arc_dev_list, next) == NULL)
		next = list_head(l2arc_dev_list);
	else
		next = list_next(l2arc_dev_list, next);
	ASSERT(next);

	/* loop through L2ARC devs looking for the one we need */
	/* LINTED(E_CONSTANT_CONDITION) */
	while (1) {
		if (next == NULL) /* reached list end, start from beginning */
			next = list_head(l2arc_dev_list);

		if (start == NULL) { /* save starting dev */
			start = next;
		} else if (start == next) { /* full loop completed - stop now */
			next = NULL;
			if (feed_type == L2ARC_FEED_DDT_DEV) {
				l2arc_ddt_dev_last = NULL;
				goto out;
			} else {
				break;
			}
		}

		if (!vdev_is_dead(next->l2ad_vdev) && !next->l2ad_rebuild) {
			if (feed_type == L2ARC_FEED_DDT_DEV) {
				if (vdev_type_is_ddt(next->l2ad_vdev)) {
					l2arc_ddt_dev_last = next;
					goto out;
				}
			} else if (feed_type == L2ARC_FEED_NON_DDT_DEV) {
				if (!vdev_type_is_ddt(next->l2ad_vdev)) {
					break;
				}
			} else {
				ASSERT(feed_type == L2ARC_FEED_ALL);
				break;
			}
		}
		next = list_next(l2arc_dev_list, next);
	}
	l2arc_dev_last = next;

out:
	mutex_exit(&l2arc_dev_mtx);

	/*
	 * Grab the config lock to prevent the 'next' device from being
	 * removed while we are writing to it.
	 */
	if (next != NULL)
		spa_config_enter(next->l2ad_spa, SCL_L2ARC, next, RW_READER);
	mutex_exit(&spa_namespace_lock);

	return (next);
}

/*
 * Free buffers that were tagged for destruction.
 */
static void
l2arc_do_free_on_write()
{
	list_t *buflist;
	l2arc_data_free_t *df, *df_prev;

	mutex_enter(&l2arc_free_on_write_mtx);
	buflist = l2arc_free_on_write;

	for (df = list_tail(buflist); df; df = df_prev) {
		df_prev = list_prev(buflist, df);
		ASSERT3P(df->l2df_abd, !=, NULL);
		abd_free(df->l2df_abd);
		list_remove(buflist, df);
		kmem_free(df, sizeof (l2arc_data_free_t));
	}

	mutex_exit(&l2arc_free_on_write_mtx);
}

/*
 * A write to a cache device has completed.  Update all headers to allow
 * reads from these buffers to begin.
 */
static void
l2arc_write_done(zio_t *zio)
{
	l2arc_write_callback_t *cb;
	l2arc_dev_t *dev;
	list_t *buflist;
	arc_buf_hdr_t *head, *hdr, *hdr_prev;
	kmutex_t *hash_lock;
	int64_t bytes_dropped = 0;
	l2arc_log_blk_buf_t *lb_buf;

	cb = zio->io_private;
	ASSERT3P(cb, !=, NULL);
	dev = cb->l2wcb_dev;
	ASSERT3P(dev, !=, NULL);
	head = cb->l2wcb_head;
	ASSERT3P(head, !=, NULL);
	buflist = &dev->l2ad_buflist;
	ASSERT3P(buflist, !=, NULL);
	DTRACE_PROBE2(l2arc__iodone, zio_t *, zio,
	    l2arc_write_callback_t *, cb);

	if (zio->io_error != 0)
		ARCSTAT_BUMP(arcstat_l2_writes_error);

	/*
	 * All writes completed, or an error was hit.
	 */
top:
	mutex_enter(&dev->l2ad_mtx);
	for (hdr = list_prev(buflist, head); hdr; hdr = hdr_prev) {
		hdr_prev = list_prev(buflist, hdr);

		hash_lock = HDR_LOCK(hdr);

		/*
		 * We cannot use mutex_enter or else we can deadlock
		 * with l2arc_write_buffers (due to swapping the order
		 * the hash lock and l2ad_mtx are taken).
		 */
		if (!mutex_tryenter(hash_lock)) {
			/*
			 * Missed the hash lock. We must retry so we
			 * don't leave the ARC_FLAG_L2_WRITING bit set.
			 */
			ARCSTAT_BUMP(arcstat_l2_writes_lock_retry);

			/*
			 * We don't want to rescan the headers we've
			 * already marked as having been written out, so
			 * we reinsert the head node so we can pick up
			 * where we left off.
			 */
			list_remove(buflist, head);
			list_insert_after(buflist, hdr, head);

			mutex_exit(&dev->l2ad_mtx);

			/*
			 * We wait for the hash lock to become available
			 * to try and prevent busy waiting, and increase
			 * the chance we'll be able to acquire the lock
			 * the next time around.
			 */
			mutex_enter(hash_lock);
			mutex_exit(hash_lock);
			goto top;
		}

		/*
		 * We could not have been moved into the arc_l2c_only
		 * state while in-flight due to our ARC_FLAG_L2_WRITING
		 * bit being set. Let's just ensure that's being enforced.
		 */
		ASSERT(HDR_HAS_L1HDR(hdr));

		if (zio->io_error != 0) {
			/*
			 * Error - drop L2ARC entry.
			 */
			list_remove(buflist, hdr);
			arc_hdr_clear_flags(hdr, ARC_FLAG_HAS_L2HDR);

			ARCSTAT_INCR(arcstat_l2_psize, -arc_hdr_size(hdr));
			ARCSTAT_INCR(arcstat_l2_lsize, -HDR_GET_LSIZE(hdr));

			bytes_dropped += arc_hdr_size(hdr);
			(void) refcount_remove_many(&dev->l2ad_alloc,
			    arc_hdr_size(hdr), hdr);
		}

		/*
		 * Allow ARC to begin reads and ghost list evictions to
		 * this L2ARC entry.
		 */
		arc_hdr_clear_flags(hdr, ARC_FLAG_L2_WRITING);

		mutex_exit(hash_lock);
	}

	atomic_inc_64(&l2arc_writes_done);
	list_remove(buflist, head);
	ASSERT(!HDR_HAS_L1HDR(head));
	kmem_cache_free(hdr_l2only_cache, head);
	mutex_exit(&dev->l2ad_mtx);

	ASSERT(dev->l2ad_vdev != NULL);
	vdev_space_update(dev->l2ad_vdev, -bytes_dropped, 0, 0);

	l2arc_do_free_on_write();

	while ((lb_buf = list_remove_tail(&cb->l2wcb_log_blk_buflist)) != NULL)
		kmem_free(lb_buf, sizeof (*lb_buf));
	list_destroy(&cb->l2wcb_log_blk_buflist);
	kmem_free(cb, sizeof (l2arc_write_callback_t));
}

/*
 * A read to a cache device completed.  Validate buffer contents before
 * handing over to the regular ARC routines.
 */
static void
l2arc_read_done(zio_t *zio)
{
	l2arc_read_callback_t *cb;
	arc_buf_hdr_t *hdr;
	kmutex_t *hash_lock;
	boolean_t valid_cksum;

	ASSERT3P(zio->io_vd, !=, NULL);
	ASSERT(zio->io_flags & ZIO_FLAG_DONT_PROPAGATE);

	spa_config_exit(zio->io_spa, SCL_L2ARC, zio->io_vd);

	cb = zio->io_private;
	ASSERT3P(cb, !=, NULL);
	hdr = cb->l2rcb_hdr;
	ASSERT3P(hdr, !=, NULL);

	hash_lock = HDR_LOCK(hdr);
	mutex_enter(hash_lock);
	ASSERT3P(hash_lock, ==, HDR_LOCK(hdr));

	/*
	 * If the data was read into a temporary buffer,
	 * move it and free the buffer.
	 */
	if (cb->l2rcb_abd != NULL) {
		ASSERT3U(arc_hdr_size(hdr), <, zio->io_size);
		if (zio->io_error == 0) {
			abd_copy(hdr->b_l1hdr.b_pabd, cb->l2rcb_abd,
			    arc_hdr_size(hdr));
		}

		/*
		 * The following must be done regardless of whether
		 * there was an error:
		 * - free the temporary buffer
		 * - point zio to the real ARC buffer
		 * - set zio size accordingly
		 * These are required because zio is either re-used for
		 * an I/O of the block in the case of the error
		 * or the zio is passed to arc_read_done() and it
		 * needs real data.
		 */
		abd_free(cb->l2rcb_abd);
		zio->io_size = zio->io_orig_size = arc_hdr_size(hdr);
		zio->io_abd = zio->io_orig_abd = hdr->b_l1hdr.b_pabd;
	}

	ASSERT3P(zio->io_abd, !=, NULL);

	/*
	 * Check this survived the L2ARC journey.
	 */
	ASSERT3P(zio->io_abd, ==, hdr->b_l1hdr.b_pabd);
	zio->io_bp_copy = cb->l2rcb_bp;	/* XXX fix in L2ARC 2.0	*/
	zio->io_bp = &zio->io_bp_copy;	/* XXX fix in L2ARC 2.0	*/

	valid_cksum = arc_cksum_is_equal(hdr, zio);
	if (valid_cksum && zio->io_error == 0 && !HDR_L2_EVICTED(hdr)) {
		mutex_exit(hash_lock);
		zio->io_private = hdr;
		arc_read_done(zio);
	} else {
		mutex_exit(hash_lock);
		/*
		 * Buffer didn't survive caching.  Increment stats and
		 * reissue to the original storage device.
		 */
		if (zio->io_error != 0) {
			ARCSTAT_BUMP(arcstat_l2_io_error);
		} else {
			zio->io_error = SET_ERROR(EIO);
		}
		if (!valid_cksum)
			ARCSTAT_BUMP(arcstat_l2_cksum_bad);

		/*
		 * If there's no waiter, issue an async i/o to the primary
		 * storage now.  If there *is* a waiter, the caller must
		 * issue the i/o in a context where it's OK to block.
		 */
		if (zio->io_waiter == NULL) {
			zio_t *pio = zio_unique_parent(zio);

			ASSERT(!pio || pio->io_child_type == ZIO_CHILD_LOGICAL);

			zio_nowait(zio_read(pio, zio->io_spa, zio->io_bp,
			    hdr->b_l1hdr.b_pabd, zio->io_size, arc_read_done,
			    hdr, zio->io_priority, cb->l2rcb_flags,
			    &cb->l2rcb_zb));
		}
	}

	kmem_free(cb, sizeof (l2arc_read_callback_t));
}

/*
 * This is the list priority from which the L2ARC will search for pages to
 * cache.  This is used within loops to cycle through lists in the
 * desired order.  This order can have a significant effect on cache
 * performance.
 *
 * Currently the ddt lists are hit first (MFU then MRU),
 * followed by metadata then by the data lists.
 * This function returns a locked list, and also returns the lock pointer.
 */
static multilist_sublist_t *
l2arc_sublist_lock(enum l2arc_priorities prio)
{
	multilist_t *ml = NULL;
	unsigned int idx;

	ASSERT(prio >= PRIORITY_MFU_DDT);
	ASSERT(prio < PRIORITY_NUMTYPES);

	switch (prio) {
	case PRIORITY_MFU_DDT:
		ml = arc_mfu->arcs_list[ARC_BUFC_DDT];
		break;
	case PRIORITY_MRU_DDT:
		ml = arc_mru->arcs_list[ARC_BUFC_DDT];
		break;
	case PRIORITY_MFU_META:
		ml = arc_mfu->arcs_list[ARC_BUFC_METADATA];
		break;
	case PRIORITY_MRU_META:
		ml = arc_mru->arcs_list[ARC_BUFC_METADATA];
		break;
	case PRIORITY_MFU_DATA:
		ml = arc_mfu->arcs_list[ARC_BUFC_DATA];
		break;
	case PRIORITY_MRU_DATA:
		ml = arc_mru->arcs_list[ARC_BUFC_DATA];
		break;
	}

	/*
	 * Return a randomly-selected sublist. This is acceptable
	 * because the caller feeds only a little bit of data for each
	 * call (8MB). Subsequent calls will result in different
	 * sublists being selected.
	 */
	idx = multilist_get_random_index(ml);
	return (multilist_sublist_lock(ml, idx));
}

/*
 * Calculates the maximum overhead of L2ARC metadata log blocks for a given
 * L2ARC write size. l2arc_evict and l2arc_write_buffers need to include this
 * overhead in processing to make sure there is enough headroom available
 * when writing buffers.
 */
static inline uint64_t
l2arc_log_blk_overhead(uint64_t write_sz)
{
	return ((write_sz / SPA_MINBLOCKSIZE / L2ARC_LOG_BLK_ENTRIES) + 1) *
	    L2ARC_LOG_BLK_SIZE;
}

/*
 * Evict buffers from the device write hand to the distance specified in
 * bytes.  This distance may span populated buffers, it may span nothing.
 * This is clearing a region on the L2ARC device ready for writing.
 * If the 'all' boolean is set, every buffer is evicted.
 */
static void
l2arc_evict_impl(l2arc_dev_t *dev, uint64_t distance, boolean_t all)
{
	list_t *buflist;
	arc_buf_hdr_t *hdr, *hdr_prev;
	kmutex_t *hash_lock;
	uint64_t taddr;

	buflist = &dev->l2ad_buflist;

	if (!all && dev->l2ad_first) {
		/*
		 * This is the first sweep through the device.  There is
		 * nothing to evict.
		 */
		return;
	}

	/*
	 * We need to add in the worst case scenario of log block overhead.
	 */
	distance += l2arc_log_blk_overhead(distance);
	if (dev->l2ad_hand >= (dev->l2ad_end - (2 * distance))) {
		/*
		 * When nearing the end of the device, evict to the end
		 * before the device write hand jumps to the start.
		 */
		taddr = dev->l2ad_end;
	} else {
		taddr = dev->l2ad_hand + distance;
	}
	DTRACE_PROBE4(l2arc__evict, l2arc_dev_t *, dev, list_t *, buflist,
	    uint64_t, taddr, boolean_t, all);

top:
	mutex_enter(&dev->l2ad_mtx);
	for (hdr = list_tail(buflist); hdr; hdr = hdr_prev) {
		hdr_prev = list_prev(buflist, hdr);

		hash_lock = HDR_LOCK(hdr);

		/*
		 * We cannot use mutex_enter or else we can deadlock
		 * with l2arc_write_buffers (due to swapping the order
		 * the hash lock and l2ad_mtx are taken).
		 */
		if (!mutex_tryenter(hash_lock)) {
			/*
			 * Missed the hash lock.  Retry.
			 */
			ARCSTAT_BUMP(arcstat_l2_evict_lock_retry);
			mutex_exit(&dev->l2ad_mtx);
			mutex_enter(hash_lock);
			mutex_exit(hash_lock);
			goto top;
		}

		/*
		 * A header can't be on this list if it doesn't have L2 header.
		 */
		ASSERT(HDR_HAS_L2HDR(hdr));

		/* Ensure this header has finished being written. */
		ASSERT(!HDR_L2_WRITING(hdr));
		ASSERT(!HDR_L2_WRITE_HEAD(hdr));

		if (!all && (hdr->b_l2hdr.b_daddr >= taddr ||
		    hdr->b_l2hdr.b_daddr < dev->l2ad_hand)) {
			/*
			 * We've evicted to the target address,
			 * or the end of the device.
			 */
			mutex_exit(hash_lock);
			break;
		}

		if (!HDR_HAS_L1HDR(hdr)) {
			ASSERT(!HDR_L2_READING(hdr));
			/*
			 * This doesn't exist in the ARC.  Destroy.
			 * arc_hdr_destroy() will call list_remove()
			 * and decrement arcstat_l2_lsize.
			 */
			arc_change_state(arc_anon, hdr, hash_lock);
			arc_hdr_destroy(hdr);
		} else {
			ASSERT(hdr->b_l1hdr.b_state != arc_l2c_only);
			ARCSTAT_BUMP(arcstat_l2_evict_l1cached);
			/*
			 * Invalidate issued or about to be issued
			 * reads, since we may be about to write
			 * over this location.
			 */
			if (HDR_L2_READING(hdr)) {
				ARCSTAT_BUMP(arcstat_l2_evict_reading);
				arc_hdr_set_flags(hdr, ARC_FLAG_L2_EVICTED);
			}

			arc_hdr_l2hdr_destroy(hdr);
		}
		mutex_exit(hash_lock);
	}
	mutex_exit(&dev->l2ad_mtx);
}

static void
l2arc_evict_task(void *arg)
{
	l2arc_dev_t *dev = arg;
	ASSERT(dev);

	/*
	 * Evict l2arc buffers asynchronously; we need to keep the device
	 * around until we are sure there aren't any buffers referencing it.
	 * We do not need to hold any config locks, etc. because at this point,
	 * we are the only ones who knows about this device (the in-core
	 * structure), so no new buffers can be created (e.g. if the pool is
	 * re-imported while the asynchronous eviction is in progress) that
	 * reference this same in-core structure. Also remove the vdev link
	 * since further use of it as l2arc device is prohibited.
	 */
	dev->l2ad_vdev = NULL;
	l2arc_evict_impl(dev, 0LL, B_TRUE);

	/* Same cleanup as in the synchronous path */
	list_destroy(&dev->l2ad_buflist);
	mutex_destroy(&dev->l2ad_mtx);
	refcount_destroy(&dev->l2ad_alloc);
	kmem_free(dev->l2ad_dev_hdr, dev->l2ad_dev_hdr_asize);
	kmem_free(dev, sizeof (l2arc_dev_t));
}

boolean_t zfs_l2arc_async_evict = B_TRUE;

/*
 * Perform l2arc eviction for buffers associated with this device
 * If evicting all buffers (done at pool export time), try to evict
 * asynchronously, and fall back to synchronous eviction in case of error
 * Tell the caller whether to cleanup the device:
 *  - B_TRUE means "asynchronous eviction, do not cleanup"
 *  - B_FALSE means "synchronous eviction, done, please cleanup"
 */
static boolean_t
l2arc_evict(l2arc_dev_t *dev, uint64_t distance, boolean_t all)
{
	/*
	 *  If we are evicting all the buffers for this device, which happens
	 *  at pool export time, schedule asynchronous task
	 */
	if (all && zfs_l2arc_async_evict) {
		if ((taskq_dispatch(arc_flush_taskq, l2arc_evict_task,
		    dev, TQ_NOSLEEP) == NULL)) {
			/*
			 * Failed to dispatch asynchronous task
			 * cleanup, evict synchronously
			 */
			l2arc_evict_impl(dev, distance, all);
		} else {
			/*
			 * Successful dispatch, vdev space updated
			 */
			return (B_TRUE);
		}
	} else {
		/* Evict synchronously */
		l2arc_evict_impl(dev, distance, all);
	}

	return (B_FALSE);
}

/*
 * Find and write ARC buffers to the L2ARC device.
 *
 * An ARC_FLAG_L2_WRITING flag is set so that the L2ARC buffers are not valid
 * for reading until they have completed writing.
 * The headroom_boost is an in-out parameter used to maintain headroom boost
 * state between calls to this function.
 *
 * Returns the number of bytes actually written (which may be smaller than
 * the delta by which the device hand has changed due to alignment).
 */
static uint64_t
l2arc_write_buffers(spa_t *spa, l2arc_dev_t *dev, uint64_t target_sz,
    l2ad_feed_t feed_type)
{
	arc_buf_hdr_t *hdr, *hdr_prev, *head;
	/*
	 * We must carefully track the space we deal with here:
	 * - write_size: sum of the size of all buffers to be written
	 *	without compression or inter-buffer alignment applied.
	 *	This size is added to arcstat_l2_size, because subsequent
	 *	eviction of buffers decrements this kstat by only the
	 *	buffer's b_lsize (which doesn't take alignment into account).
	 * - write_asize: sum of the size of all buffers to be written
	 *	with inter-buffer alignment applied.
	 *	This size is used to estimate the maximum number of bytes
	 *	we could take up on the device and is thus used to gauge how
	 *	close we are to hitting target_sz.
	 */
	uint64_t write_asize, write_psize, write_lsize, headroom;
	boolean_t full;
	l2arc_write_callback_t *cb;
	zio_t *pio, *wzio;
	enum l2arc_priorities try;
	uint64_t guid = spa_load_guid(spa);
	boolean_t dev_hdr_update = B_FALSE;

	ASSERT3P(dev->l2ad_vdev, !=, NULL);

	pio = NULL;
	cb = NULL;
	write_lsize = write_asize = write_psize = 0;
	full = B_FALSE;
	head = kmem_cache_alloc(hdr_l2only_cache, KM_PUSHPAGE);
	arc_hdr_set_flags(head, ARC_FLAG_L2_WRITE_HEAD | ARC_FLAG_HAS_L2HDR);

	/*
	 * Copy buffers for L2ARC writing.
	 */
	for (try = PRIORITY_MFU_DDT; try < PRIORITY_NUMTYPES; try++) {
		multilist_sublist_t *mls = l2arc_sublist_lock(try);
		uint64_t passed_sz = 0;

		/*
		 * L2ARC fast warmup.
		 *
		 * Until the ARC is warm and starts to evict, read from the
		 * head of the ARC lists rather than the tail.
		 */
		if (arc_warm == B_FALSE)
			hdr = multilist_sublist_head(mls);
		else
			hdr = multilist_sublist_tail(mls);

		headroom = target_sz * l2arc_headroom;
		if (zfs_compressed_arc_enabled)
			headroom = (headroom * l2arc_headroom_boost) / 100;

		for (; hdr; hdr = hdr_prev) {
			kmutex_t *hash_lock;

			if (arc_warm == B_FALSE)
				hdr_prev = multilist_sublist_next(mls, hdr);
			else
				hdr_prev = multilist_sublist_prev(mls, hdr);

			hash_lock = HDR_LOCK(hdr);
			if (!mutex_tryenter(hash_lock)) {
				/*
				 * Skip this buffer rather than waiting.
				 */
				continue;
			}

			passed_sz += HDR_GET_LSIZE(hdr);
			if (passed_sz > headroom) {
				/*
				 * Searched too far.
				 */
				mutex_exit(hash_lock);
				break;
			}

			if (!l2arc_write_eligible(guid, hdr)) {
				mutex_exit(hash_lock);
				continue;
			}

			/*
			 * We rely on the L1 portion of the header below, so
			 * it's invalid for this header to have been evicted out
			 * of the ghost cache, prior to being written out. The
			 * ARC_FLAG_L2_WRITING bit ensures this won't happen.
			 */
			ASSERT(HDR_HAS_L1HDR(hdr));

			ASSERT3U(HDR_GET_PSIZE(hdr), >, 0);
			ASSERT3P(hdr->b_l1hdr.b_pabd, !=, NULL);
			ASSERT3U(arc_hdr_size(hdr), >, 0);
			uint64_t psize = arc_hdr_size(hdr);
			uint64_t asize = vdev_psize_to_asize(dev->l2ad_vdev,
			    psize);

			if ((write_asize + asize) > target_sz) {
				full = B_TRUE;
				mutex_exit(hash_lock);
				break;
			}

			/* make sure buf we select corresponds to feed_type */
			if ((feed_type == L2ARC_FEED_DDT_DEV &&
			    arc_buf_type(hdr) != ARC_BUFC_DDT) ||
			    (feed_type == L2ARC_FEED_NON_DDT_DEV &&
			    arc_buf_type(hdr) == ARC_BUFC_DDT)) {
					mutex_exit(hash_lock);
					continue;
			}

			if (pio == NULL) {
				/*
				 * Insert a dummy header on the buflist so
				 * l2arc_write_done() can find where the
				 * write buffers begin without searching.
				 */
				mutex_enter(&dev->l2ad_mtx);
				list_insert_head(&dev->l2ad_buflist, head);
				mutex_exit(&dev->l2ad_mtx);

				cb = kmem_zalloc(
				    sizeof (l2arc_write_callback_t), KM_SLEEP);
				cb->l2wcb_dev = dev;
				cb->l2wcb_head = head;
				list_create(&cb->l2wcb_log_blk_buflist,
				    sizeof (l2arc_log_blk_buf_t),
				    offsetof(l2arc_log_blk_buf_t, lbb_node));
				pio = zio_root(spa, l2arc_write_done, cb,
				    ZIO_FLAG_CANFAIL);
			}

			hdr->b_l2hdr.b_dev = dev;
			hdr->b_l2hdr.b_daddr = dev->l2ad_hand;
			arc_hdr_set_flags(hdr,
			    ARC_FLAG_L2_WRITING | ARC_FLAG_HAS_L2HDR);

			mutex_enter(&dev->l2ad_mtx);
			list_insert_head(&dev->l2ad_buflist, hdr);
			mutex_exit(&dev->l2ad_mtx);

			(void) refcount_add_many(&dev->l2ad_alloc, psize, hdr);

			/*
			 * Normally the L2ARC can use the hdr's data, but if
			 * we're sharing data between the hdr and one of its
			 * bufs, L2ARC needs its own copy of the data so that
			 * the ZIO below can't race with the buf consumer.
			 * Another case where we need to create a copy of the
			 * data is when the buffer size is not device-aligned
			 * and we need to pad the block to make it such.
			 * That also keeps the clock hand suitably aligned.
			 *
			 * To ensure that the copy will be available for the
			 * lifetime of the ZIO and be cleaned up afterwards, we
			 * add it to the l2arc_free_on_write queue.
			 */
			abd_t *to_write;
			if (!HDR_SHARED_DATA(hdr) && psize == asize) {
				to_write = hdr->b_l1hdr.b_pabd;
			} else {
				to_write = abd_alloc_for_io(asize,
				    !HDR_ISTYPE_DATA(hdr));
				abd_copy(to_write, hdr->b_l1hdr.b_pabd, psize);
				if (asize != psize) {
					abd_zero_off(to_write, psize,
					    asize - psize);
				}
				l2arc_free_abd_on_write(to_write, asize,
				    arc_buf_type(hdr));
			}
			wzio = zio_write_phys(pio, dev->l2ad_vdev,
			    hdr->b_l2hdr.b_daddr, asize, to_write,
			    ZIO_CHECKSUM_OFF, NULL, hdr,
			    ZIO_PRIORITY_ASYNC_WRITE,
			    ZIO_FLAG_CANFAIL, B_FALSE);

			write_lsize += HDR_GET_LSIZE(hdr);
			DTRACE_PROBE2(l2arc__write, vdev_t *, dev->l2ad_vdev,
			    zio_t *, wzio);

			write_psize += psize;
			write_asize += asize;
			dev->l2ad_hand += asize;

			mutex_exit(hash_lock);

			(void) zio_nowait(wzio);

			/*
			 * Append buf info to current log and commit if full.
			 * arcstat_l2_{size,asize} kstats are updated internally.
			 */
			if (l2arc_log_blk_insert(dev, hdr)) {
				l2arc_log_blk_commit(dev, pio, cb);
				dev_hdr_update = B_TRUE;
			}
		}

		multilist_sublist_unlock(mls);

		if (full == B_TRUE)
			break;
	}

	/* No buffers selected for writing? */
	if (pio == NULL) {
		ASSERT0(write_lsize);
		ASSERT(!HDR_HAS_L1HDR(head));
		kmem_cache_free(hdr_l2only_cache, head);
		return (0);
	}

	/*
	 * If we wrote any logs as part of this write, update dev hdr
	 * to point to it.
	 */
	if (dev_hdr_update)
		l2arc_dev_hdr_update(dev, pio);

	ASSERT3U(write_asize, <=, target_sz);
	ARCSTAT_BUMP(arcstat_l2_writes_sent);
	ARCSTAT_INCR(arcstat_l2_write_bytes, write_psize);
	if (feed_type == L2ARC_FEED_DDT_DEV)
		ARCSTAT_INCR(arcstat_l2_ddt_write_bytes, write_psize);
	ARCSTAT_INCR(arcstat_l2_lsize, write_lsize);
	ARCSTAT_INCR(arcstat_l2_psize, write_psize);
	vdev_space_update(dev->l2ad_vdev, write_psize, 0, 0);

	/*
	 * Bump device hand to the device start if it is approaching the end.
	 * l2arc_evict() will already have evicted ahead for this case.
	 */
	if (dev->l2ad_hand + target_sz + l2arc_log_blk_overhead(target_sz) >=
	    dev->l2ad_end) {
		dev->l2ad_hand = dev->l2ad_start;
		dev->l2ad_first = B_FALSE;
	}

	dev->l2ad_writing = B_TRUE;
	(void) zio_wait(pio);
	dev->l2ad_writing = B_FALSE;

	return (write_asize);
}

static boolean_t
l2arc_feed_dev(l2ad_feed_t feed_type, uint64_t *wrote)
{
	spa_t *spa;
	l2arc_dev_t *dev;
	uint64_t size;

	/*
	 * This selects the next l2arc device to write to, and in
	 * doing so the next spa to feed from: dev->l2ad_spa.   This
	 * will return NULL if there are now no l2arc devices or if
	 * they are all faulted.
	 *
	 * If a device is returned, its spa's config lock is also
	 * held to prevent device removal.  l2arc_dev_get_next()
	 * will grab and release l2arc_dev_mtx.
	 */
	if ((dev = l2arc_dev_get_next(feed_type)) == NULL)
		return (B_FALSE);

	spa = dev->l2ad_spa;
	ASSERT(spa != NULL);

	/*
	 * If the pool is read-only - skip it
	 */
	if (!spa_writeable(spa)) {
		spa_config_exit(spa, SCL_L2ARC, dev);
		return (B_FALSE);
	}

	ARCSTAT_BUMP(arcstat_l2_feeds);
	size = l2arc_write_size();

	/*
	 * Evict L2ARC buffers that will be overwritten.
	 * B_FALSE guarantees synchronous eviction.
	 */
	(void) l2arc_evict(dev, size, B_FALSE);

	/*
	 * Write ARC buffers.
	 */
	*wrote = l2arc_write_buffers(spa, dev, size, feed_type);

	spa_config_exit(spa, SCL_L2ARC, dev);

	return (B_TRUE);
}

/*
 * This thread feeds the L2ARC at regular intervals.  This is the beating
 * heart of the L2ARC.
 */
/* ARGSUSED */
static void
l2arc_feed_thread(void *unused)
{
	callb_cpr_t cpr;
	uint64_t size, total_written = 0;
	clock_t begin, next = ddi_get_lbolt();
	l2ad_feed_t feed_type = L2ARC_FEED_ALL;

	CALLB_CPR_INIT(&cpr, &l2arc_feed_thr_lock, callb_generic_cpr, FTAG);

	mutex_enter(&l2arc_feed_thr_lock);

	while (l2arc_thread_exit == 0) {
		CALLB_CPR_SAFE_BEGIN(&cpr);
		(void) cv_timedwait(&l2arc_feed_thr_cv, &l2arc_feed_thr_lock,
		    next);
		CALLB_CPR_SAFE_END(&cpr, &l2arc_feed_thr_lock);
		next = ddi_get_lbolt() + hz;

		/*
		 * Quick check for L2ARC devices.
		 */
		mutex_enter(&l2arc_dev_mtx);
		if (l2arc_ndev == 0) {
			mutex_exit(&l2arc_dev_mtx);
			continue;
		}
		mutex_exit(&l2arc_dev_mtx);
		begin = ddi_get_lbolt();

		/*
		 * Avoid contributing to memory pressure.
		 */
		if (arc_reclaim_needed()) {
			ARCSTAT_BUMP(arcstat_l2_abort_lowmem);
			continue;
		}

		/* try to write to DDT L2ARC device if any */
		if (l2arc_feed_dev(L2ARC_FEED_DDT_DEV, &size)) {
			total_written += size;
			feed_type = L2ARC_FEED_NON_DDT_DEV;
		}

		/* try to write to the regular L2ARC device if any */
		if (l2arc_feed_dev(feed_type, &size)) {
			total_written += size;
			if (feed_type == L2ARC_FEED_NON_DDT_DEV)
				total_written /= 2; /* avg written per device */
		}

		/*
		 * Calculate interval between writes.
		 */
		next = l2arc_write_interval(begin, l2arc_write_size(),
		    total_written);

		total_written = 0;
	}

	l2arc_thread_exit = 0;
	cv_broadcast(&l2arc_feed_thr_cv);
	CALLB_CPR_EXIT(&cpr);		/* drops l2arc_feed_thr_lock */
	thread_exit();
}

boolean_t
l2arc_vdev_present(vdev_t *vd)
{
	return (l2arc_vdev_get(vd) != NULL);
}

/*
 * Returns the l2arc_dev_t associated with a particular vdev_t or NULL if
 * the vdev_t isn't an L2ARC device.
 */
static l2arc_dev_t *
l2arc_vdev_get(vdev_t *vd)
{
	l2arc_dev_t	*dev;
	boolean_t	held = MUTEX_HELD(&l2arc_dev_mtx);

	if (!held)
		mutex_enter(&l2arc_dev_mtx);
	for (dev = list_head(l2arc_dev_list); dev != NULL;
	    dev = list_next(l2arc_dev_list, dev)) {
		if (dev->l2ad_vdev == vd)
			break;
	}
	if (!held)
		mutex_exit(&l2arc_dev_mtx);

	return (dev);
}

/*
 * Add a vdev for use by the L2ARC.  By this point the spa has already
 * validated the vdev and opened it. The `rebuild' flag indicates whether
 * we should attempt an L2ARC persistency rebuild.
 */
void
l2arc_add_vdev(spa_t *spa, vdev_t *vd, boolean_t rebuild)
{
	l2arc_dev_t *adddev;

	ASSERT(!l2arc_vdev_present(vd));

	/*
	 * Create a new l2arc device entry.
	 */
	adddev = kmem_zalloc(sizeof (l2arc_dev_t), KM_SLEEP);
	adddev->l2ad_spa = spa;
	adddev->l2ad_vdev = vd;
	/* leave extra size for an l2arc device header */
	adddev->l2ad_dev_hdr_asize = MAX(sizeof (*adddev->l2ad_dev_hdr),
	    1 << vd->vdev_ashift);
	adddev->l2ad_start = VDEV_LABEL_START_SIZE + adddev->l2ad_dev_hdr_asize;
	adddev->l2ad_end = VDEV_LABEL_START_SIZE + vdev_get_min_asize(vd);
	ASSERT3U(adddev->l2ad_start, <, adddev->l2ad_end);
	adddev->l2ad_hand = adddev->l2ad_start;
	adddev->l2ad_first = B_TRUE;
	adddev->l2ad_writing = B_FALSE;
	adddev->l2ad_dev_hdr = kmem_zalloc(adddev->l2ad_dev_hdr_asize,
	    KM_SLEEP);

	mutex_init(&adddev->l2ad_mtx, NULL, MUTEX_DEFAULT, NULL);
	/*
	 * This is a list of all ARC buffers that are still valid on the
	 * device.
	 */
	list_create(&adddev->l2ad_buflist, sizeof (arc_buf_hdr_t),
	    offsetof(arc_buf_hdr_t, b_l2hdr.b_l2node));

	vdev_space_update(vd, 0, 0, adddev->l2ad_end - adddev->l2ad_hand);
	refcount_create(&adddev->l2ad_alloc);

	/*
	 * Add device to global list
	 */
	mutex_enter(&l2arc_dev_mtx);
	list_insert_head(l2arc_dev_list, adddev);
	atomic_inc_64(&l2arc_ndev);
	if (rebuild && l2arc_rebuild_enabled &&
	    adddev->l2ad_end - adddev->l2ad_start > L2ARC_PERSIST_MIN_SIZE) {
		/*
		 * Just mark the device as pending for a rebuild. We won't
		 * be starting a rebuild in line here as it would block pool
		 * import. Instead spa_load_impl will hand that off to an
		 * async task which will call l2arc_spa_rebuild_start.
		 */
		adddev->l2ad_rebuild = B_TRUE;
	}
	mutex_exit(&l2arc_dev_mtx);
}

/*
 * Remove a vdev from the L2ARC.
 */
void
l2arc_remove_vdev(vdev_t *vd)
{
	l2arc_dev_t *dev, *nextdev, *remdev = NULL;

	/*
	 * Find the device by vdev
	 */
	mutex_enter(&l2arc_dev_mtx);
	for (dev = list_head(l2arc_dev_list); dev; dev = nextdev) {
		nextdev = list_next(l2arc_dev_list, dev);
		if (vd == dev->l2ad_vdev) {
			remdev = dev;
			break;
		}
	}
	ASSERT3P(remdev, !=, NULL);

	/*
	 * Cancel any ongoing or scheduled rebuild (race protection with
	 * l2arc_spa_rebuild_start provided via l2arc_dev_mtx).
	 */
	remdev->l2ad_rebuild_cancel = B_TRUE;
	if (remdev->l2ad_rebuild_did != 0) {
		/*
		 * N.B. it should be safe to thread_join with the rebuild
		 * thread while holding l2arc_dev_mtx because it is not
		 * accessed from anywhere in the l2arc rebuild code below
		 * (except for l2arc_spa_rebuild_start, which is ok).
		 */
		thread_join(remdev->l2ad_rebuild_did);
	}

	/*
	 * Remove device from global list
	 */
	list_remove(l2arc_dev_list, remdev);
	l2arc_dev_last = NULL;		/* may have been invalidated */
	l2arc_ddt_dev_last = NULL;	/* may have been invalidated */
	atomic_dec_64(&l2arc_ndev);
	mutex_exit(&l2arc_dev_mtx);

	if (vdev_type_is_ddt(remdev->l2ad_vdev))
		atomic_add_64(&remdev->l2ad_spa->spa_l2arc_ddt_devs_size,
		    -(vdev_get_min_asize(remdev->l2ad_vdev)));

	/*
	 * Clear all buflists and ARC references.  L2ARC device flush.
	 */
	if (l2arc_evict(remdev, 0, B_TRUE) == B_FALSE) {
		/*
		 * The eviction was done synchronously, cleanup here
		 * Otherwise, the asynchronous task will cleanup
		 */
		list_destroy(&remdev->l2ad_buflist);
		mutex_destroy(&remdev->l2ad_mtx);
		kmem_free(remdev->l2ad_dev_hdr, remdev->l2ad_dev_hdr_asize);
		kmem_free(remdev, sizeof (l2arc_dev_t));
	}
}

void
l2arc_init(void)
{
	l2arc_thread_exit = 0;
	l2arc_ndev = 0;
	l2arc_writes_sent = 0;
	l2arc_writes_done = 0;

	mutex_init(&l2arc_feed_thr_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&l2arc_feed_thr_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&l2arc_dev_mtx, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&l2arc_free_on_write_mtx, NULL, MUTEX_DEFAULT, NULL);

	l2arc_dev_list = &L2ARC_dev_list;
	l2arc_free_on_write = &L2ARC_free_on_write;
	list_create(l2arc_dev_list, sizeof (l2arc_dev_t),
	    offsetof(l2arc_dev_t, l2ad_node));
	list_create(l2arc_free_on_write, sizeof (l2arc_data_free_t),
	    offsetof(l2arc_data_free_t, l2df_list_node));
}

void
l2arc_fini(void)
{
	/*
	 * This is called from dmu_fini(), which is called from spa_fini();
	 * Because of this, we can assume that all l2arc devices have
	 * already been removed when the pools themselves were removed.
	 */

	l2arc_do_free_on_write();

	mutex_destroy(&l2arc_feed_thr_lock);
	cv_destroy(&l2arc_feed_thr_cv);
	mutex_destroy(&l2arc_dev_mtx);
	mutex_destroy(&l2arc_free_on_write_mtx);

	list_destroy(l2arc_dev_list);
	list_destroy(l2arc_free_on_write);
}

void
l2arc_start(void)
{
	if (!(spa_mode_global & FWRITE))
		return;

	(void) thread_create(NULL, 0, l2arc_feed_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);
}

void
l2arc_stop(void)
{
	if (!(spa_mode_global & FWRITE))
		return;

	mutex_enter(&l2arc_feed_thr_lock);
	cv_signal(&l2arc_feed_thr_cv);	/* kick thread out of startup */
	l2arc_thread_exit = 1;
	while (l2arc_thread_exit != 0)
		cv_wait(&l2arc_feed_thr_cv, &l2arc_feed_thr_lock);
	mutex_exit(&l2arc_feed_thr_lock);
}

/*
 * Punches out rebuild threads for the L2ARC devices in a spa. This should
 * be called after pool import from the spa async thread, since starting
 * these threads directly from spa_import() will make them part of the
 * "zpool import" context and delay process exit (and thus pool import).
 */
void
l2arc_spa_rebuild_start(spa_t *spa)
{
	/*
	 * Locate the spa's l2arc devices and kick off rebuild threads.
	 */
	mutex_enter(&l2arc_dev_mtx);
	for (int i = 0; i < spa->spa_l2cache.sav_count; i++) {
		l2arc_dev_t *dev =
		    l2arc_vdev_get(spa->spa_l2cache.sav_vdevs[i]);
		if (dev == NULL) {
			/* Don't attempt a rebuild if the vdev is UNAVAIL */
			continue;
		}
		if (dev->l2ad_rebuild && !dev->l2ad_rebuild_cancel) {
			VERIFY3U(dev->l2ad_rebuild_did, ==, 0);
#ifdef	_KERNEL
			dev->l2ad_rebuild_did = thread_create(NULL, 0,
			    l2arc_dev_rebuild_start, dev, 0, &p0, TS_RUN,
			    minclsyspri)->t_did;
#endif
		}
	}
	mutex_exit(&l2arc_dev_mtx);
}

/*
 * Main entry point for L2ARC rebuilding.
 */
static void
l2arc_dev_rebuild_start(l2arc_dev_t *dev)
{
	if (!dev->l2ad_rebuild_cancel) {
		VERIFY(dev->l2ad_rebuild);
		(void) l2arc_rebuild(dev);
		dev->l2ad_rebuild = B_FALSE;
	}
}

/*
 * This function implements the actual L2ARC metadata rebuild. It:
 *
 * 1) reads the device's header
 * 2) if a good device header is found, starts reading the log block chain
 * 3) restores each block's contents to memory (reconstructing arc_buf_hdr_t's)
 *
 * Operation stops under any of the following conditions:
 *
 * 1) We reach the end of the log blk chain (the back-reference in the blk is
 *    invalid or loops over our starting point).
 * 2) We encounter *any* error condition (cksum errors, io errors, looped
 *    blocks, etc.).
 */
static int
l2arc_rebuild(l2arc_dev_t *dev)
{
	vdev_t			*vd = dev->l2ad_vdev;
	spa_t			*spa = vd->vdev_spa;
	int			err;
	l2arc_log_blk_phys_t	*this_lb, *next_lb;
	uint8_t			*this_lb_buf, *next_lb_buf;
	zio_t			*this_io = NULL, *next_io = NULL;
	l2arc_log_blkptr_t	lb_ptrs[2];
	boolean_t		first_pass, lock_held;
	uint64_t		load_guid;

	this_lb = kmem_zalloc(sizeof (*this_lb), KM_SLEEP);
	next_lb = kmem_zalloc(sizeof (*next_lb), KM_SLEEP);
	this_lb_buf = kmem_zalloc(sizeof (l2arc_log_blk_phys_t), KM_SLEEP);
	next_lb_buf = kmem_zalloc(sizeof (l2arc_log_blk_phys_t), KM_SLEEP);

	/*
	 * We prevent device removal while issuing reads to the device,
	 * then during the rebuilding phases we drop this lock again so
	 * that a spa_unload or device remove can be initiated - this is
	 * safe, because the spa will signal us to stop before removing
	 * our device and wait for us to stop.
	 */
	spa_config_enter(spa, SCL_L2ARC, vd, RW_READER);
	lock_held = B_TRUE;

	load_guid = spa_load_guid(dev->l2ad_vdev->vdev_spa);
	/*
	 * Device header processing phase.
	 */
	if ((err = l2arc_dev_hdr_read(dev)) != 0) {
		/* device header corrupted, start a new one */
		bzero(dev->l2ad_dev_hdr, dev->l2ad_dev_hdr_asize);
		goto out;
	}

	/* Retrieve the persistent L2ARC device state */
	dev->l2ad_hand = vdev_psize_to_asize(dev->l2ad_vdev,
	    dev->l2ad_dev_hdr->dh_start_lbps[0].lbp_daddr +
	    LBP_GET_PSIZE(&dev->l2ad_dev_hdr->dh_start_lbps[0]));
	dev->l2ad_first = !!(dev->l2ad_dev_hdr->dh_flags &
	    L2ARC_DEV_HDR_EVICT_FIRST);

	/* Prepare the rebuild processing state */
	bcopy(dev->l2ad_dev_hdr->dh_start_lbps, lb_ptrs, sizeof (lb_ptrs));
	first_pass = B_TRUE;

	/* Start the rebuild process */
	for (;;) {
		if (!l2arc_log_blkptr_valid(dev, &lb_ptrs[0]))
			/* We hit an invalid block address, end the rebuild. */
			break;

		if ((err = l2arc_log_blk_read(dev, &lb_ptrs[0], &lb_ptrs[1],
		    this_lb, next_lb, this_lb_buf, next_lb_buf,
		    this_io, &next_io)) != 0)
			break;

		spa_config_exit(spa, SCL_L2ARC, vd);
		lock_held = B_FALSE;

		/* Protection against infinite loops of log blocks. */
		if (l2arc_range_check_overlap(lb_ptrs[1].lbp_daddr,
		    lb_ptrs[0].lbp_daddr,
		    dev->l2ad_dev_hdr->dh_start_lbps[0].lbp_daddr) &&
		    !first_pass) {
			ARCSTAT_BUMP(arcstat_l2_rebuild_abort_loop_errors);
			err = SET_ERROR(ELOOP);
			break;
		}

		/*
		 * Our memory pressure valve. If the system is running low
		 * on memory, rather than swamping memory with new ARC buf
		 * hdrs, we opt not to rebuild the L2ARC. At this point,
		 * however, we have already set up our L2ARC dev to chain in
		 * new metadata log blk, so the user may choose to re-add the
		 * L2ARC dev at a later time to reconstruct it (when there's
		 * less memory pressure).
		 */
		if (arc_reclaim_needed()) {
			ARCSTAT_BUMP(arcstat_l2_rebuild_abort_lowmem);
			cmn_err(CE_NOTE, "System running low on memory, "
			    "aborting L2ARC rebuild.");
			err = SET_ERROR(ENOMEM);
			break;
		}

		/*
		 * Now that we know that the next_lb checks out alright, we
		 * can start reconstruction from this lb - we can be sure
		 * that the L2ARC write hand has not yet reached any of our
		 * buffers.
		 */
		l2arc_log_blk_restore(dev, load_guid, this_lb,
		    LBP_GET_PSIZE(&lb_ptrs[0]));

		/*
		 * End of list detection. We can look ahead two steps in the
		 * blk chain and if the 2nd blk from this_lb dips below the
		 * initial chain starting point, then we know two things:
		 *	1) it can't be valid, and
		 *	2) the next_lb's ARC entries might have already been
		 *	partially overwritten and so we should stop before
		 *	we restore it
		 */
		if (l2arc_range_check_overlap(
		    this_lb->lb_back2_lbp.lbp_daddr, lb_ptrs[0].lbp_daddr,
		    dev->l2ad_dev_hdr->dh_start_lbps[0].lbp_daddr) &&
		    !first_pass)
			break;

		/* log blk restored, continue with next one in the list */
		lb_ptrs[0] = lb_ptrs[1];
		lb_ptrs[1] = this_lb->lb_back2_lbp;
		PTR_SWAP(this_lb, next_lb);
		PTR_SWAP(this_lb_buf, next_lb_buf);
		this_io = next_io;
		next_io = NULL;
		first_pass = B_FALSE;

		for (;;) {
			if (dev->l2ad_rebuild_cancel) {
				err = SET_ERROR(ECANCELED);
				goto out;
			}
			if (spa_config_tryenter(spa, SCL_L2ARC, vd,
			    RW_READER)) {
				lock_held = B_TRUE;
				break;
			}
			/*
			 * L2ARC config lock held by somebody in writer,
			 * possibly due to them trying to remove us. They'll
			 * likely to want us to shut down, so after a little
			 * delay, we check l2ad_rebuild_cancel and retry
			 * the lock again.
			 */
			delay(1);
		}
	}
out:
	if (next_io != NULL)
		l2arc_log_blk_prefetch_abort(next_io);
	kmem_free(this_lb, sizeof (*this_lb));
	kmem_free(next_lb, sizeof (*next_lb));
	kmem_free(this_lb_buf, sizeof (l2arc_log_blk_phys_t));
	kmem_free(next_lb_buf, sizeof (l2arc_log_blk_phys_t));
	if (err == 0)
		ARCSTAT_BUMP(arcstat_l2_rebuild_successes);

	if (lock_held)
		spa_config_exit(spa, SCL_L2ARC, vd);

	return (err);
}

/*
 * Attempts to read the device header on the provided L2ARC device and writes
 * it to `hdr'. On success, this function returns 0, otherwise the appropriate
 * error code is returned.
 */
static int
l2arc_dev_hdr_read(l2arc_dev_t *dev)
{
	int			err;
	uint64_t		guid;
	zio_cksum_t		cksum;
	l2arc_dev_hdr_phys_t	*hdr = dev->l2ad_dev_hdr;
	const uint64_t		hdr_asize = dev->l2ad_dev_hdr_asize;
	abd_t *abd;

	guid = spa_guid(dev->l2ad_vdev->vdev_spa);

	abd = abd_get_from_buf(hdr, hdr_asize);
	err = zio_wait(zio_read_phys(NULL, dev->l2ad_vdev,
	    VDEV_LABEL_START_SIZE, hdr_asize, abd,
	    ZIO_CHECKSUM_OFF, NULL, NULL, ZIO_PRIORITY_ASYNC_READ,
	    ZIO_FLAG_DONT_CACHE | ZIO_FLAG_CANFAIL |
	    ZIO_FLAG_DONT_PROPAGATE | ZIO_FLAG_DONT_RETRY, B_FALSE));
	abd_put(abd);
	if (err != 0) {
		ARCSTAT_BUMP(arcstat_l2_rebuild_abort_io_errors);
		return (err);
	}

	if (hdr->dh_magic == BSWAP_64(L2ARC_DEV_HDR_MAGIC_V1))
		byteswap_uint64_array(hdr, sizeof (*hdr));

	if (hdr->dh_magic != L2ARC_DEV_HDR_MAGIC_V1 ||
	    hdr->dh_spa_guid != guid) {
		/*
		 * Attempt to rebuild a device containing no actual dev hdr
		 * or containing a header from some other pool.
		 */
		ARCSTAT_BUMP(arcstat_l2_rebuild_abort_unsupported);
		return (SET_ERROR(ENOTSUP));
	}

	l2arc_dev_hdr_checksum(hdr, &cksum);
	if (!ZIO_CHECKSUM_EQUAL(hdr->dh_self_cksum, cksum)) {
		ARCSTAT_BUMP(arcstat_l2_rebuild_abort_cksum_errors);
		return (SET_ERROR(EINVAL));
	}

	return (0);
}

/*
 * Reads L2ARC log blocks from storage and validates their contents.
 *
 * This function implements a simple prefetcher to make sure that while
 * we're processing one buffer the L2ARC is already prefetching the next
 * one in the chain.
 *
 * The arguments this_lp and next_lp point to the current and next log blk
 * address in the block chain. Similarly, this_lb and next_lb hold the
 * l2arc_log_blk_phys_t's of the current and next L2ARC blk. The this_lb_buf
 * and next_lb_buf must be buffers of appropriate to hold a raw
 * l2arc_log_blk_phys_t (they are used as catch buffers for read ops prior
 * to buffer decompression).
 *
 * The `this_io' and `next_io' arguments are used for block prefetching.
 * When issuing the first blk IO during rebuild, you should pass NULL for
 * `this_io'. This function will then issue a sync IO to read the block and
 * also issue an async IO to fetch the next block in the block chain. The
 * prefetch IO is returned in `next_io'. On subsequent calls to this
 * function, pass the value returned in `next_io' from the previous call
 * as `this_io' and a fresh `next_io' pointer to hold the next prefetch IO.
 * Prior to the call, you should initialize your `next_io' pointer to be
 * NULL. If no prefetch IO was issued, the pointer is left set at NULL.
 *
 * On success, this function returns 0, otherwise it returns an appropriate
 * error code. On error the prefetching IO is aborted and cleared before
 * returning from this function. Therefore, if we return `success', the
 * caller can assume that we have taken care of cleanup of prefetch IOs.
 */
static int
l2arc_log_blk_read(l2arc_dev_t *dev,
    const l2arc_log_blkptr_t *this_lbp, const l2arc_log_blkptr_t *next_lbp,
    l2arc_log_blk_phys_t *this_lb, l2arc_log_blk_phys_t *next_lb,
    uint8_t *this_lb_buf, uint8_t *next_lb_buf,
    zio_t *this_io, zio_t **next_io)
{
	int		err = 0;
	zio_cksum_t	cksum;

	ASSERT(this_lbp != NULL && next_lbp != NULL);
	ASSERT(this_lb != NULL && next_lb != NULL);
	ASSERT(this_lb_buf != NULL && next_lb_buf != NULL);
	ASSERT(next_io != NULL && *next_io == NULL);
	ASSERT(l2arc_log_blkptr_valid(dev, this_lbp));

	/*
	 * Check to see if we have issued the IO for this log blk in a
	 * previous run. If not, this is the first call, so issue it now.
	 */
	if (this_io == NULL) {
		this_io = l2arc_log_blk_prefetch(dev->l2ad_vdev, this_lbp,
		    this_lb_buf);
	}

	/*
	 * Peek to see if we can start issuing the next IO immediately.
	 */
	if (l2arc_log_blkptr_valid(dev, next_lbp)) {
		/*
		 * Start issuing IO for the next log blk early - this
		 * should help keep the L2ARC device busy while we
		 * decompress and restore this log blk.
		 */
		*next_io = l2arc_log_blk_prefetch(dev->l2ad_vdev, next_lbp,
		    next_lb_buf);
	}

	/* Wait for the IO to read this log block to complete */
	if ((err = zio_wait(this_io)) != 0) {
		ARCSTAT_BUMP(arcstat_l2_rebuild_abort_io_errors);
		goto cleanup;
	}

	/* Make sure the buffer checks out */
	fletcher_4_native(this_lb_buf, LBP_GET_PSIZE(this_lbp), NULL, &cksum);
	if (!ZIO_CHECKSUM_EQUAL(cksum, this_lbp->lbp_cksum)) {
		ARCSTAT_BUMP(arcstat_l2_rebuild_abort_cksum_errors);
		err = SET_ERROR(EINVAL);
		goto cleanup;
	}

	/* Now we can take our time decoding this buffer */
	switch (LBP_GET_COMPRESS(this_lbp)) {
	case ZIO_COMPRESS_OFF:
		bcopy(this_lb_buf, this_lb, sizeof (*this_lb));
		break;
	case ZIO_COMPRESS_LZ4:
		err = zio_decompress_data_buf(LBP_GET_COMPRESS(this_lbp),
		    this_lb_buf, this_lb, LBP_GET_PSIZE(this_lbp),
		    sizeof (*this_lb));
		if (err != 0) {
			err = SET_ERROR(EINVAL);
			goto cleanup;
		}

		break;
	default:
		err = SET_ERROR(EINVAL);
		break;
	}

	if (this_lb->lb_magic == BSWAP_64(L2ARC_LOG_BLK_MAGIC))
		byteswap_uint64_array(this_lb, sizeof (*this_lb));

	if (this_lb->lb_magic != L2ARC_LOG_BLK_MAGIC) {
		err = SET_ERROR(EINVAL);
		goto cleanup;
	}

cleanup:
	/* Abort an in-flight prefetch I/O in case of error */
	if (err != 0 && *next_io != NULL) {
		l2arc_log_blk_prefetch_abort(*next_io);
		*next_io = NULL;
	}
	return (err);
}

/*
 * Restores the payload of a log blk to ARC. This creates empty ARC hdr
 * entries which only contain an l2arc hdr, essentially restoring the
 * buffers to their L2ARC evicted state. This function also updates space
 * usage on the L2ARC vdev to make sure it tracks restored buffers.
 */
static void
l2arc_log_blk_restore(l2arc_dev_t *dev, uint64_t load_guid,
    const l2arc_log_blk_phys_t *lb, uint64_t lb_psize)
{
	uint64_t	size = 0, psize = 0;

	for (int i = L2ARC_LOG_BLK_ENTRIES - 1; i >= 0; i--) {
		/*
		 * Restore goes in the reverse temporal direction to preserve
		 * correct temporal ordering of buffers in the l2ad_buflist.
		 * l2arc_hdr_restore also does a list_insert_tail instead of
		 * list_insert_head on the l2ad_buflist:
		 *
		 *		LIST	l2ad_buflist		LIST
		 *		HEAD  <------ (time) ------	TAIL
		 * direction	+-----+-----+-----+-----+-----+    direction
		 * of l2arc <== | buf | buf | buf | buf | buf | ===> of rebuild
		 * fill		+-----+-----+-----+-----+-----+
		 *		^				^
		 *		|				|
		 *		|				|
		 *	l2arc_fill_thread		l2arc_rebuild
		 *	places new bufs here		restores bufs here
		 *
		 * This also works when the restored bufs get evicted at any
		 * point during the rebuild.
		 */
		l2arc_hdr_restore(&lb->lb_entries[i], dev, load_guid);
		size += LE_GET_LSIZE(&lb->lb_entries[i]);
		psize += LE_GET_PSIZE(&lb->lb_entries[i]);
	}

	/*
	 * Record rebuild stats:
	 *	size		In-memory size of restored buffer data in ARC
	 *	psize		Physical size of restored buffers in the L2ARC
	 *	bufs		# of ARC buffer headers restored
	 *	log_blks	# of L2ARC log entries processed during restore
	 */
	ARCSTAT_INCR(arcstat_l2_rebuild_size, size);
	ARCSTAT_INCR(arcstat_l2_rebuild_psize, psize);
	ARCSTAT_INCR(arcstat_l2_rebuild_bufs, L2ARC_LOG_BLK_ENTRIES);
	ARCSTAT_BUMP(arcstat_l2_rebuild_log_blks);
	ARCSTAT_F_AVG(arcstat_l2_log_blk_avg_size, lb_psize);
	ARCSTAT_F_AVG(arcstat_l2_data_to_meta_ratio, psize / lb_psize);
	vdev_space_update(dev->l2ad_vdev, psize, 0, 0);
}

/*
 * Restores a single ARC buf hdr from a log block. The ARC buffer is put
 * into a state indicating that it has been evicted to L2ARC.
 */
static void
l2arc_hdr_restore(const l2arc_log_ent_phys_t *le, l2arc_dev_t *dev,
    uint64_t load_guid)
{
	arc_buf_hdr_t		*hdr, *exists;
	kmutex_t		*hash_lock;
	arc_buf_contents_t	type = LE_GET_TYPE(le);

	/*
	 * Do all the allocation before grabbing any locks, this lets us
	 * sleep if memory is full and we don't have to deal with failed
	 * allocations.
	 */
	hdr = arc_buf_alloc_l2only(load_guid, type, dev, le->le_dva,
	    le->le_daddr, LE_GET_LSIZE(le), LE_GET_PSIZE(le),
	    le->le_birth, le->le_freeze_cksum, LE_GET_CHECKSUM(le),
	    LE_GET_COMPRESS(le), LE_GET_ARC_COMPRESS(le));

	ARCSTAT_INCR(arcstat_l2_lsize, HDR_GET_LSIZE(hdr));
	ARCSTAT_INCR(arcstat_l2_psize, arc_hdr_size(hdr));

	mutex_enter(&dev->l2ad_mtx);
	/*
	 * We connect the l2hdr to the hdr only after the hdr is in the hash
	 * table, otherwise the rest of the arc hdr manipulation machinery
	 * might get confused.
	 */
	list_insert_tail(&dev->l2ad_buflist, hdr);
	(void) refcount_add_many(&dev->l2ad_alloc, arc_hdr_size(hdr), hdr);
	mutex_exit(&dev->l2ad_mtx);

	exists = buf_hash_insert(hdr, &hash_lock);
	if (exists) {
		/* Buffer was already cached, no need to restore it. */
		arc_hdr_destroy(hdr);
		mutex_exit(hash_lock);
		ARCSTAT_BUMP(arcstat_l2_rebuild_bufs_precached);
		return;
	}

	mutex_exit(hash_lock);
}

/*
 * Used by PL2ARC related functions that do
 * async read/write
 */
static void
pl2arc_io_done(zio_t *zio)
{
	abd_put(zio->io_private);
	zio->io_private = NULL;
}

/*
 * Starts an asynchronous read IO to read a log block. This is used in log
 * block reconstruction to start reading the next block before we are done
 * decoding and reconstructing the current block, to keep the l2arc device
 * nice and hot with read IO to process.
 * The returned zio will contain a newly allocated memory buffers for the IO
 * data which should then be freed by the caller once the zio is no longer
 * needed (i.e. due to it having completed). If you wish to abort this
 * zio, you should do so using l2arc_log_blk_prefetch_abort, which takes
 * care of disposing of the allocated buffers correctly.
 */
static zio_t *
l2arc_log_blk_prefetch(vdev_t *vd, const l2arc_log_blkptr_t *lbp,
    uint8_t *lb_buf)
{
	uint32_t	psize;
	zio_t		*pio;
	abd_t		*abd;

	psize = LBP_GET_PSIZE(lbp);
	ASSERT(psize <= sizeof (l2arc_log_blk_phys_t));
	pio = zio_root(vd->vdev_spa, NULL, NULL, ZIO_FLAG_DONT_CACHE |
	    ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_PROPAGATE |
	    ZIO_FLAG_DONT_RETRY);
	abd = abd_get_from_buf(lb_buf, psize);
	(void) zio_nowait(zio_read_phys(pio, vd, lbp->lbp_daddr, psize,
	    abd, ZIO_CHECKSUM_OFF, pl2arc_io_done, abd,
		ZIO_PRIORITY_ASYNC_READ, ZIO_FLAG_DONT_CACHE | ZIO_FLAG_CANFAIL |
	    ZIO_FLAG_DONT_PROPAGATE | ZIO_FLAG_DONT_RETRY, B_FALSE));

	return (pio);
}

/*
 * Aborts a zio returned from l2arc_log_blk_prefetch and frees the data
 * buffers allocated for it.
 */
static void
l2arc_log_blk_prefetch_abort(zio_t *zio)
{
	(void) zio_wait(zio);
}

/*
 * Creates a zio to update the device header on an l2arc device. The zio is
 * initiated as a child of `pio'.
 */
static void
l2arc_dev_hdr_update(l2arc_dev_t *dev, zio_t *pio)
{
	zio_t			*wzio;
	abd_t			*abd;
	l2arc_dev_hdr_phys_t	*hdr = dev->l2ad_dev_hdr;
	const uint64_t		hdr_asize = dev->l2ad_dev_hdr_asize;

	hdr->dh_magic = L2ARC_DEV_HDR_MAGIC_V1;
	hdr->dh_spa_guid = spa_guid(dev->l2ad_vdev->vdev_spa);
	hdr->dh_alloc_space = refcount_count(&dev->l2ad_alloc);
	hdr->dh_flags = 0;
	if (dev->l2ad_first)
		hdr->dh_flags |= L2ARC_DEV_HDR_EVICT_FIRST;

	/* checksum operation goes last */
	l2arc_dev_hdr_checksum(hdr, &hdr->dh_self_cksum);

	abd = abd_get_from_buf(hdr, hdr_asize);
	wzio = zio_write_phys(pio, dev->l2ad_vdev, VDEV_LABEL_START_SIZE,
	    hdr_asize, abd, ZIO_CHECKSUM_OFF, pl2arc_io_done, abd,
	    ZIO_PRIORITY_ASYNC_WRITE, ZIO_FLAG_CANFAIL, B_FALSE);
	DTRACE_PROBE2(l2arc__write, vdev_t *, dev->l2ad_vdev, zio_t *, wzio);
	(void) zio_nowait(wzio);
}

/*
 * Commits a log block to the L2ARC device. This routine is invoked from
 * l2arc_write_buffers when the log block fills up.
 * This function allocates some memory to temporarily hold the serialized
 * buffer to be written. This is then released in l2arc_write_done.
 */
static void
l2arc_log_blk_commit(l2arc_dev_t *dev, zio_t *pio,
    l2arc_write_callback_t *cb)
{
	l2arc_log_blk_phys_t	*lb = &dev->l2ad_log_blk;
	uint64_t		psize, asize;
	l2arc_log_blk_buf_t	*lb_buf;
	abd_t *abd;
	zio_t			*wzio;

	VERIFY(dev->l2ad_log_ent_idx == L2ARC_LOG_BLK_ENTRIES);

	/* link the buffer into the block chain */
	lb->lb_back2_lbp = dev->l2ad_dev_hdr->dh_start_lbps[1];
	lb->lb_magic = L2ARC_LOG_BLK_MAGIC;

	/* try to compress the buffer */
	lb_buf = kmem_zalloc(sizeof (*lb_buf), KM_SLEEP);
	list_insert_tail(&cb->l2wcb_log_blk_buflist, lb_buf);
	abd = abd_get_from_buf(lb, sizeof (*lb));
	psize = zio_compress_data(ZIO_COMPRESS_LZ4, abd, lb_buf->lbb_log_blk,
	    sizeof (*lb));
	abd_put(abd);
	/* a log block is never entirely zero */
	ASSERT(psize != 0);
	asize = vdev_psize_to_asize(dev->l2ad_vdev, psize);
	ASSERT(asize <= sizeof (lb_buf->lbb_log_blk));

	/*
	 * Update the start log blk pointer in the device header to point
	 * to the log block we're about to write.
	 */
	dev->l2ad_dev_hdr->dh_start_lbps[1] =
	    dev->l2ad_dev_hdr->dh_start_lbps[0];
	dev->l2ad_dev_hdr->dh_start_lbps[0].lbp_daddr = dev->l2ad_hand;
	_NOTE(CONSTCOND)
	LBP_SET_LSIZE(&dev->l2ad_dev_hdr->dh_start_lbps[0], sizeof (*lb));
	LBP_SET_PSIZE(&dev->l2ad_dev_hdr->dh_start_lbps[0], asize);
	LBP_SET_CHECKSUM(&dev->l2ad_dev_hdr->dh_start_lbps[0],
	    ZIO_CHECKSUM_FLETCHER_4);
	LBP_SET_TYPE(&dev->l2ad_dev_hdr->dh_start_lbps[0], 0);

	if (asize < sizeof (*lb)) {
		/* compression succeeded */
		bzero(lb_buf->lbb_log_blk + psize, asize - psize);
		LBP_SET_COMPRESS(&dev->l2ad_dev_hdr->dh_start_lbps[0],
		    ZIO_COMPRESS_LZ4);
	} else {
		/* compression failed */
		bcopy(lb, lb_buf->lbb_log_blk, sizeof (*lb));
		LBP_SET_COMPRESS(&dev->l2ad_dev_hdr->dh_start_lbps[0],
		    ZIO_COMPRESS_OFF);
	}

	/* checksum what we're about to write */
	fletcher_4_native(lb_buf->lbb_log_blk, asize,
	    NULL, &dev->l2ad_dev_hdr->dh_start_lbps[0].lbp_cksum);

	/* perform the write itself */
	CTASSERT(L2ARC_LOG_BLK_SIZE >= SPA_MINBLOCKSIZE &&
	    L2ARC_LOG_BLK_SIZE <= SPA_MAXBLOCKSIZE);
	abd = abd_get_from_buf(lb_buf->lbb_log_blk, asize);
	wzio = zio_write_phys(pio, dev->l2ad_vdev, dev->l2ad_hand,
	    asize, abd, ZIO_CHECKSUM_OFF, pl2arc_io_done, abd,
	    ZIO_PRIORITY_ASYNC_WRITE, ZIO_FLAG_CANFAIL, B_FALSE);
	DTRACE_PROBE2(l2arc__write, vdev_t *, dev->l2ad_vdev, zio_t *, wzio);
	(void) zio_nowait(wzio);

	dev->l2ad_hand += asize;
	vdev_space_update(dev->l2ad_vdev, asize, 0, 0);

	/* bump the kstats */
	ARCSTAT_INCR(arcstat_l2_write_bytes, asize);
	ARCSTAT_BUMP(arcstat_l2_log_blk_writes);
	ARCSTAT_F_AVG(arcstat_l2_log_blk_avg_size, asize);
	ARCSTAT_F_AVG(arcstat_l2_data_to_meta_ratio,
	    dev->l2ad_log_blk_payload_asize / asize);

	/* start a new log block */
	dev->l2ad_log_ent_idx = 0;
	dev->l2ad_log_blk_payload_asize = 0;
}

/*
 * Validates an L2ARC log blk address to make sure that it can be read
 * from the provided L2ARC device. Returns B_TRUE if the address is
 * within the device's bounds, or B_FALSE if not.
 */
static boolean_t
l2arc_log_blkptr_valid(l2arc_dev_t *dev, const l2arc_log_blkptr_t *lbp)
{
	uint64_t psize = LBP_GET_PSIZE(lbp);
	uint64_t end = lbp->lbp_daddr + psize;

	/*
	 * A log block is valid if all of the following conditions are true:
	 * - it fits entirely between l2ad_start and l2ad_end
	 * - it has a valid size
	 */
	return (lbp->lbp_daddr >= dev->l2ad_start && end <= dev->l2ad_end &&
	    psize > 0 && psize <= sizeof (l2arc_log_blk_phys_t));
}

/*
 * Computes the checksum of `hdr' and stores it in `cksum'.
 */
static void
l2arc_dev_hdr_checksum(const l2arc_dev_hdr_phys_t *hdr, zio_cksum_t *cksum)
{
	fletcher_4_native((uint8_t *)hdr +
	    offsetof(l2arc_dev_hdr_phys_t, dh_spa_guid),
	    sizeof (*hdr) - offsetof(l2arc_dev_hdr_phys_t, dh_spa_guid),
	    NULL, cksum);
}

/*
 * Inserts ARC buffer `ab' into the current L2ARC log blk on the device.
 * The buffer being inserted must be present in L2ARC.
 * Returns B_TRUE if the L2ARC log blk is full and needs to be committed
 * to L2ARC, or B_FALSE if it still has room for more ARC buffers.
 */
static boolean_t
l2arc_log_blk_insert(l2arc_dev_t *dev, const arc_buf_hdr_t *ab)
{
	l2arc_log_blk_phys_t	*lb = &dev->l2ad_log_blk;
	l2arc_log_ent_phys_t	*le;
	int			index = dev->l2ad_log_ent_idx++;

	ASSERT(index < L2ARC_LOG_BLK_ENTRIES);

	le = &lb->lb_entries[index];
	bzero(le, sizeof (*le));
	le->le_dva = ab->b_dva;
	le->le_birth = ab->b_birth;
	le->le_daddr = ab->b_l2hdr.b_daddr;
	LE_SET_LSIZE(le, HDR_GET_LSIZE(ab));
	LE_SET_PSIZE(le, HDR_GET_PSIZE(ab));

	if ((ab->b_flags & ARC_FLAG_COMPRESSED_ARC) != 0) {
		LE_SET_ARC_COMPRESS(le, 1);
		LE_SET_COMPRESS(le, HDR_GET_COMPRESS(ab));
	} else {
		ASSERT3U(HDR_GET_COMPRESS(ab), ==, ZIO_COMPRESS_OFF);
		LE_SET_ARC_COMPRESS(le, 0);
		LE_SET_COMPRESS(le, ZIO_COMPRESS_OFF);
	}

	if (ab->b_freeze_cksum != NULL) {
		le->le_freeze_cksum = *ab->b_freeze_cksum;
		LE_SET_CHECKSUM(le, ZIO_CHECKSUM_FLETCHER_2);
	} else {
		LE_SET_CHECKSUM(le, ZIO_CHECKSUM_OFF);
	}

	LE_SET_TYPE(le, arc_flags_to_bufc(ab->b_flags));
	dev->l2ad_log_blk_payload_asize += arc_hdr_size((arc_buf_hdr_t *)ab);

	return (dev->l2ad_log_ent_idx == L2ARC_LOG_BLK_ENTRIES);
}

/*
 * Checks whether a given L2ARC device address sits in a time-sequential
 * range. The trick here is that the L2ARC is a rotary buffer, so we can't
 * just do a range comparison, we need to handle the situation in which the
 * range wraps around the end of the L2ARC device. Arguments:
 *	bottom	Lower end of the range to check (written to earlier).
 *	top	Upper end of the range to check (written to later).
 *	check	The address for which we want to determine if it sits in
 *		between the top and bottom.
 *
 * The 3-way conditional below represents the following cases:
 *
 *	bottom < top : Sequentially ordered case:
 *	  <check>--------+-------------------+
 *	                 |  (overlap here?)  |
 *	 L2ARC dev       V                   V
 *	 |---------------<bottom>============<top>--------------|
 *
 *	bottom > top: Looped-around case:
 *	                      <check>--------+------------------+
 *	                                     |  (overlap here?) |
 *	 L2ARC dev                           V                  V
 *	 |===============<top>---------------<bottom>===========|
 *	 ^               ^
 *	 |  (or here?)   |
 *	 +---------------+---------<check>
 *
 *	top == bottom : Just a single address comparison.
 */
static inline boolean_t
l2arc_range_check_overlap(uint64_t bottom, uint64_t top, uint64_t check)
{
	if (bottom < top)
		return (bottom <= check && check <= top);
	else if (bottom > top)
		return (check <= top || bottom <= check);
	else
		return (check == top);
}
