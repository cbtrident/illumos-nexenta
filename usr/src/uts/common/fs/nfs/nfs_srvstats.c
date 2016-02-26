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
 * Implementation of the NFS server kstats.
 */

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/zone.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/disp.h>
#include <sys/note.h>
#include <sys/acl.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>
#include <nfs/nfs4_kprot.h>

/*
 * Atomic reads and writes.  This is simple generic implementation.
 */
#define	atomic_read_uchar(t)		atomic_cas_uchar((t), 0, 0)
#define	atomic_read_uint(t)		atomic_cas_uint((t), 0, 0)
#define	atomic_write_uchar(t, n)	(void) atomic_swap_uchar((t), (n))

/*
 * Object states.  Used for nses, nscs, and nsces objects.
 */
#define	NS_STATE_ALLOC	0	/* Allocated, uninitialized */
#define	NS_STATE_SETUP	1	/* The kstat creation/destruction in progress */
#define	NS_STATE_OK	2	/* Normal operation */
#define	NS_STATE_AGED	3	/* The entry is too old */

/*
 * Local object helper function prototypes.
 */
static int nfssrv_exp_stats_compar(const void *, const void *);
static int nfssrv_clnt_stats_compar(const void *, const void *);
static void nfssrv_clnt_stats_rele_norefresh(struct nfssrv_clnt_stats *);
static void nfssrv_clnt_stats_rele_aged(struct nfssrv_clnt_stats *, time_t);
static int nfssrv_clnt_exp_stats_compar(const void *, const void *);
static void nfssrv_clnt_exp_stats_rele_aged(struct nfssrv_clnt_exp_stats *,
    time_t);

/*
 * The NFS server ID generator functions
 */
static void nfssrv_idgen_init(struct nfssrv_idgen *, const char *, size_t,
    size_t, size_t);
static void nfssrv_idgen_fini(struct nfssrv_idgen *);

static bool_t nfssrv_stats_alloc_data(nfssrv_stats *, int);
static void nfssrv_stats_free_data(nfssrv_stats *);

/*
 * The zone key for the NFS server stats
 */
zone_key_t nfssrv_stat_zone_key;

/*
 * Object caches for nscs and nsces objects
 */
static struct kmem_cache *nscs_cache;
static struct kmem_cache *nsces_cache;

/*
 * Tunable: Various flags for NFS server kstats
 */
#define	SRV_STATS	(1 << 0)	/* Create per-server kstats */
#define	EXP_STATS	(1 << 1)	/* Create per-exportinfo kstats */
#define	CLNT_STATS	(1 << 2)	/* Create per-client kstats */
#define	CLNT_EXP_STATS	(1 << 3)	/* Create per-client/per-exportinfo */
					/* kstats */
#define	ALL_STATS	(SRV_STATS | EXP_STATS | CLNT_STATS | CLNT_EXP_STATS)

volatile int nfssrv_stats_flags = ALL_STATS;

/*
 * Tunable: By default we keep untouched entries for at least 6 hours
 */
volatile int nfssrv_clnt_stats_keeptime = 6 * 60 * 60;
volatile int nfssrv_clnt_exp_stats_keeptime = 6 * 60 * 60;

/*
 * Tunable: By default we reclaim entries older than 5 minutes
 */
volatile int nfssrv_clnt_stats_reclaimtime = 5 * 60;
volatile int nfssrv_clnt_exp_stats_reclaimtime = 5 * 60;

/*
 * Implementation of the nscs_cache
 */
static int
nscs_ctor(void *buf, void *user_arg, int kmflags)
{
	_NOTE(ARGUNUSED(user_arg))

	struct nfssrv_clnt_stats *nscs = buf;

	if (!nfssrv_stats_alloc_data(&nscs->nscs_stats, kmflags)) {
		nfssrv_stats_free_data(&nscs->nscs_stats);

		return (-1);
	}

	nscs->nscs_count = 0;

	mutex_init(&nscs->nscs_procio_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&nscs->nscs_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

static void
nscs_dtor(void *buf, void *user_arg)
{
	_NOTE(ARGUNUSED(user_arg))

	struct nfssrv_clnt_stats *nscs = buf;

	ASSERT(nscs->nscs_count == 0);

	nfssrv_stats_free_data(&nscs->nscs_stats);

	mutex_destroy(&nscs->nscs_procio_lock);
	cv_destroy(&nscs->nscs_cv);
}

static void
nscs_reap(struct nfssrv_zone_stats *nfsstatsp, time_t aged)
{
	struct nfssrv_clnt_stats *nscs;
	struct nfssrv_clnt_stats *nscs_next;

	/*
	 * Walk all clnt_stats (nscs) for the zone represented by nfsstatsp and
	 * check their age.  If they are older than 'aged', destroy them.
	 */

	ASSERT(nfsstatsp != NULL);

	rw_enter(&nfsstatsp->ns_clnt_stats_lock, RW_READER);
	nscs_next = avl_first(&nfsstatsp->ns_clnt_stats);
	while (nscs_next != NULL &&
	    atomic_read_uint(&nscs_next->nscs_count) == 0 &&
	    atomic_read_uchar(&nscs_next->nscs_state) == NS_STATE_SETUP) {
		nscs_next = AVL_NEXT(&nfsstatsp->ns_clnt_stats, nscs_next);
	}
	if (nscs_next != NULL)
		nfssrv_clnt_stats_hold(nscs_next);
	rw_exit(&nfsstatsp->ns_clnt_stats_lock);

	for (nscs = nscs_next; nscs != NULL; nscs = nscs_next) {
		rw_enter(&nfsstatsp->ns_clnt_stats_lock, RW_READER);
		do {
			nscs_next = AVL_NEXT(&nfsstatsp->ns_clnt_stats,
			    nscs_next);
		} while (nscs_next != NULL &&
		    atomic_read_uint(&nscs_next->nscs_count) == 0 &&
		    atomic_read_uchar(&nscs_next->nscs_state) ==
		    NS_STATE_SETUP);
		if (nscs_next != NULL)
			nfssrv_clnt_stats_hold(nscs_next);
		rw_exit(&nfsstatsp->ns_clnt_stats_lock);

		/*
		 * If the nscs is older than 'aged' destroy it, or mark it for
		 * destroy.
		 */
		nfssrv_clnt_stats_rele_aged(nscs, aged);
	}
}

static void
nscs_reaper(struct nfssrv_zone_stats *nfsstatsp)
{
	mutex_enter(&nfsstatsp->ns_reaper_lock);

	nfsstatsp->ns_reaper_threads++;
	cv_signal(&nfsstatsp->ns_reaper_ss_cv);

	for (;;) {
		int sleeptime;

		if (nfsstatsp->ns_reaper_terminate)
			break;

		/*
		 * Run the reaper every 1/20th of the keep time, but do not run
		 * it more often than once per 5 minutes and less often that
		 * once a hour.  These constants are chosen arbitrarily.
		 */
		sleeptime = nfssrv_clnt_stats_keeptime / 20;
		sleeptime = MAX(sleeptime, 5 * 60);
		sleeptime = MIN(sleeptime, 60 * 60);
		(void) cv_timedwait(&nfsstatsp->ns_reaper_cv,
		    &nfsstatsp->ns_reaper_lock,
		    ddi_get_lbolt() + SEC_TO_TICK(sleeptime));

		if (nfsstatsp->ns_reaper_terminate)
			break;

		mutex_exit(&nfsstatsp->ns_reaper_lock);

		nscs_reap(nfsstatsp,
		    gethrestime_sec() - nfssrv_clnt_stats_keeptime);

		mutex_enter(&nfsstatsp->ns_reaper_lock);
	}

	nfsstatsp->ns_reaper_threads--;
	cv_signal(&nfsstatsp->ns_reaper_ss_cv);

	mutex_exit(&nfsstatsp->ns_reaper_lock);

	zthread_exit();
}

static void
nscs_reclaim(void *arg)
{
	_NOTE(ARGUNUSED(arg))

	struct nfssrv_zone_stats *nfsstatsp;

	/*
	 * For now, the NFS server is supported in global zone only
	 */
	nfsstatsp = zone_getspecific(nfssrv_stat_zone_key, global_zone);
	ASSERT(nfsstatsp != NULL);

	nscs_reap(nfsstatsp, gethrestime_sec() - nfssrv_clnt_stats_reclaimtime);
}

/*
 * Implementation of the nsces_cache
 */
static int
nsces_ctor(void *buf, void *user_arg, int kmflags)
{
	_NOTE(ARGUNUSED(user_arg))

	struct nfssrv_clnt_exp_stats *nsces = buf;

	if (!nfssrv_stats_alloc_data(&nsces->nsces_stats, kmflags)) {
		nfssrv_stats_free_data(&nsces->nsces_stats);

		return (-1);
	}

	nsces->nsces_count = 0;

	mutex_init(&nsces->nsces_procio_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&nsces->nsces_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

static void
nsces_dtor(void *buf, void *user_arg)
{
	_NOTE(ARGUNUSED(user_arg))

	struct nfssrv_clnt_exp_stats *nsces = buf;

	ASSERT(nsces->nsces_count == 0);

	nfssrv_stats_free_data(&nsces->nsces_stats);

	mutex_destroy(&nsces->nsces_procio_lock);
	cv_destroy(&nsces->nsces_cv);
}

static void
nsces_reap(struct nfssrv_zone_stats *nfsstatsp, time_t aged)
{
	struct nfssrv_exp_stats *nses;
	struct nfssrv_exp_stats *nses_next;

	/*
	 * Walk all exp_stats (nses) for the zone represented by nfsstatsp.
	 * For every such exp_stat (nses) walk all its clnt_exp_stats (nsces)
	 * and check their age.  If they are older than 'aged', destroy them.
	 */

	ASSERT(nfsstatsp != NULL);

	rw_enter(&nfsstatsp->ns_exp_stats_lock, RW_READER);
	nses_next = avl_first(&nfsstatsp->ns_exp_stats);
	while (nses_next != NULL &&
	    atomic_read_uint(&nses_next->nses_count) == 0 &&
	    atomic_read_uchar(&nses_next->nses_state) == NS_STATE_SETUP) {
		nses_next = AVL_NEXT(&nfsstatsp->ns_exp_stats, nses_next);
	}
	if (nses_next != NULL)
		nfssrv_exp_stats_hold(nses_next);
	rw_exit(&nfsstatsp->ns_exp_stats_lock);

	for (nses = nses_next; nses != NULL; nses = nses_next) {
		struct nfssrv_clnt_exp_stats *nsces;
		struct nfssrv_clnt_exp_stats *nsces_next;

		rw_enter(&nfsstatsp->ns_exp_stats_lock, RW_READER);
		do {
			nses_next = AVL_NEXT(&nfsstatsp->ns_exp_stats,
			    nses_next);
		} while (nses_next != NULL &&
		    atomic_read_uint(&nses_next->nses_count) == 0 &&
		    atomic_read_uchar(&nses_next->nses_state) ==
		    NS_STATE_SETUP);
		if (nses_next != NULL)
			nfssrv_exp_stats_hold(nses_next);
		rw_exit(&nfsstatsp->ns_exp_stats_lock);

		/*
		 * Here walk all clnt_exp_stats (nsces) for the particular nses.
		 */
		rw_enter(&nses->nses_clnt_stats_lock, RW_READER);
		nsces_next = avl_first(&nses->nses_clnt_stats);
		while (nsces_next != NULL &&
		    atomic_read_uint(&nsces_next->nsces_count) == 0 &&
		    atomic_read_uchar(&nsces_next->nsces_state) ==
		    NS_STATE_SETUP) {
			nsces_next = AVL_NEXT(&nses->nses_clnt_stats,
			    nsces_next);
		}
		if (nsces_next != NULL)
			nfssrv_clnt_exp_stats_hold(nsces_next);
		rw_exit(&nses->nses_clnt_stats_lock);

		for (nsces = nsces_next; nsces != NULL; nsces = nsces_next) {
			rw_enter(&nses->nses_clnt_stats_lock, RW_READER);
			do {
				nsces_next = AVL_NEXT(&nses->nses_clnt_stats,
				    nsces_next);
			} while (nsces_next != NULL &&
			    atomic_read_uint(&nsces_next->nsces_count) == 0 &&
			    atomic_read_uchar(&nsces_next->nsces_state) ==
			    NS_STATE_SETUP);
			if (nsces_next != NULL)
				nfssrv_clnt_exp_stats_hold(nsces_next);
			rw_exit(&nses->nses_clnt_stats_lock);

			/*
			 * If the nsces is older than 'aged' destroy it, or
			 * mark it for destroy.
			 */
			nfssrv_clnt_exp_stats_rele_aged(nsces, aged);
		}

		/*
		 * Walking of all clnt_exp_stats (nsces) for the particular
		 * nses is complete.  Release the nses.
		 */
		nfssrv_exp_stats_rele(nses);
	}
}

static void
nsces_reaper(struct nfssrv_zone_stats *nfsstatsp)
{
	mutex_enter(&nfsstatsp->ns_reaper_lock);

	nfsstatsp->ns_reaper_threads++;
	cv_signal(&nfsstatsp->ns_reaper_ss_cv);

	for (;;) {
		int sleeptime;

		if (nfsstatsp->ns_reaper_terminate)
			break;

		/*
		 * Run the reaper every 1/20th of the keep time, but do not run
		 * it more often than once per 5 minutes and less often that
		 * once a hour.  These constants are chosen arbitrarily.
		 */
		sleeptime = nfssrv_clnt_exp_stats_keeptime / 20;
		sleeptime = MAX(sleeptime, 5 * 60);
		sleeptime = MIN(sleeptime, 60 * 60);
		(void) cv_timedwait(&nfsstatsp->ns_reaper_cv,
		    &nfsstatsp->ns_reaper_lock,
		    ddi_get_lbolt() + SEC_TO_TICK(sleeptime));

		if (nfsstatsp->ns_reaper_terminate)
			break;

		mutex_exit(&nfsstatsp->ns_reaper_lock);

		nsces_reap(nfsstatsp,
		    gethrestime_sec() - nfssrv_clnt_exp_stats_keeptime);

		mutex_enter(&nfsstatsp->ns_reaper_lock);
	}

	nfsstatsp->ns_reaper_threads--;
	cv_signal(&nfsstatsp->ns_reaper_ss_cv);

	mutex_exit(&nfsstatsp->ns_reaper_lock);

	zthread_exit();
}

static void
nsces_reclaim(void *arg)
{
	_NOTE(ARGUNUSED(arg))

	struct nfssrv_zone_stats *nfsstatsp;

	/*
	 * For now, the NFS server is supported in global zone only
	 */
	nfsstatsp = zone_getspecific(nfssrv_stat_zone_key, global_zone);
	ASSERT(nfsstatsp != NULL);

	nsces_reap(nfsstatsp,
	    gethrestime_sec() - nfssrv_clnt_exp_stats_reclaimtime);
}

/*
 * Support functions for the kstat_io init/fini
 */
static kstat_t **
nfssrv_kstat_io_init(zoneid_t zoneid, const char *module, int instance,
    const char *name_prefix, int vers, const char *class,
    const kstat_named_t *tmpl, int count, kstat_io_t *data, kmutex_t *lock)
{
	int i;
	kstat_t **ret = kmem_alloc(count * sizeof (*ret), KM_SLEEP);

	for (i = 0; i < count; i++) {
		char namebuf[KSTAT_STRLEN];

		(void) snprintf(namebuf, sizeof (namebuf), "%s_v%d_%s",
		    name_prefix, vers, tmpl[i].name);
		ret[i] = kstat_create_zone(module, instance, namebuf, class,
		    KSTAT_TYPE_IO, 1, data == NULL ? 0 : KSTAT_FLAG_VIRTUAL,
		    zoneid);
		if (ret[i] != NULL) {
			if (data != NULL)
				ret[i]->ks_data = &data[i];
			ret[i]->ks_lock = lock;
			kstat_install(ret[i]);
		}
	}

	return (ret);
}

static void
nfssrv_kstat_io_fini(kstat_t **ks, int count)
{
	int i;

	if (ks == NULL)
		return;

	for (i = 0; i < count; i++)
		if (ks[i] != NULL)
			kstat_delete(ks[i]);

	kmem_free(ks, count * sizeof (*ks));
}

/*
 * Support functions for nfssrv_stats struct
 */
static bool_t
nfssrv_stats_alloc_data(nfssrv_stats *s, int kmflags)
{
	bzero(s, sizeof (*s));

	s->aclprocio_v2_data = kmem_alloc(aclproccnt_v2_count *
	    sizeof (kstat_io_t), kmflags);
	if (s->aclprocio_v2_data == NULL)
		return (FALSE);

	s->aclprocio_v3_data = kmem_alloc(aclproccnt_v3_count *
	    sizeof (kstat_io_t), kmflags);
	if (s->aclprocio_v3_data == NULL)
		return (FALSE);

	s->rfsprocio_v2_data = kmem_alloc(rfsproccnt_v2_count *
	    sizeof (kstat_io_t), kmflags);
	if (s->rfsprocio_v2_data == NULL)
		return (FALSE);

	s->rfsprocio_v3_data = kmem_alloc(rfsproccnt_v3_count *
	    sizeof (kstat_io_t), kmflags);
	if (s->rfsprocio_v3_data == NULL)
		return (FALSE);

	s->rfsprocio_v4_data = kmem_alloc(rfsproccnt_v4_count *
	    sizeof (kstat_io_t), kmflags);
	if (s->rfsprocio_v4_data == NULL)
		return (FALSE);

	return (TRUE);
}

static void
nfssrv_stats_clear_data(nfssrv_stats *s)
{
	bzero(s->aclprocio_v2_data, aclproccnt_v2_count * sizeof (kstat_io_t));
	bzero(s->aclprocio_v3_data, aclproccnt_v3_count * sizeof (kstat_io_t));
	bzero(s->rfsprocio_v2_data, rfsproccnt_v2_count * sizeof (kstat_io_t));
	bzero(s->rfsprocio_v3_data, rfsproccnt_v3_count * sizeof (kstat_io_t));
	bzero(s->rfsprocio_v4_data, rfsproccnt_v4_count * sizeof (kstat_io_t));
}

static void
nfssrv_stats_free_data(nfssrv_stats *s)
{
	if (s->aclprocio_v2_data != NULL)
		kmem_free(s->aclprocio_v2_data,
		    aclproccnt_v2_count * sizeof (kstat_io_t));

	if (s->aclprocio_v3_data != NULL)
		kmem_free(s->aclprocio_v3_data,
		    aclproccnt_v3_count * sizeof (kstat_io_t));

	if (s->rfsprocio_v2_data != NULL)
		kmem_free(s->rfsprocio_v2_data,
		    rfsproccnt_v2_count * sizeof (kstat_io_t));

	if (s->rfsprocio_v3_data != NULL)
		kmem_free(s->rfsprocio_v3_data,
		    rfsproccnt_v3_count * sizeof (kstat_io_t));

	if (s->rfsprocio_v4_data != NULL)
		kmem_free(s->rfsprocio_v4_data,
		    rfsproccnt_v4_count * sizeof (kstat_io_t));
}

static void
nfssrv_stats_init(nfssrv_stats *s, zoneid_t zoneid, int instance,
    const char *name_prefix, const char *class, kmutex_t *lock)
{
	const char *nm;
	const char *cl;

	/*
	 * NFS_ACL
	 */
	nm = name_prefix != NULL ? name_prefix : "aclprocio";

	/*
	 * NFS_ACL version 2
	 */
	cl = class != NULL ? class : "aclprocio_v2";
	s->aclprocio_v2_ptr = nfssrv_kstat_io_init(zoneid, "nfs_acl", instance,
	    nm, NFS_ACL_V2, cl, aclproccnt_v2_tmpl, aclproccnt_v2_count,
	    s->aclprocio_v2_data, lock);

	/*
	 * NFS_ACL version 3
	 */
	cl = class != NULL ? class : "aclprocio_v3";
	s->aclprocio_v3_ptr = nfssrv_kstat_io_init(zoneid, "nfs_acl", instance,
	    nm, NFS_ACL_V3, cl, aclproccnt_v3_tmpl, aclproccnt_v3_count,
	    s->aclprocio_v3_data, lock);

	/*
	 * NFS
	 */
	nm = name_prefix != NULL ? name_prefix : "rfsprocio";

	/*
	 * NFS version 2
	 */
	cl = class != NULL ? class : "rfsprocio_v2";
	s->rfsprocio_v2_ptr = nfssrv_kstat_io_init(zoneid, "nfs", instance, nm,
	    NFS_VERSION, cl, rfsproccnt_v2_tmpl, rfsproccnt_v2_count,
	    s->rfsprocio_v2_data, lock);

	/*
	 * NFS version 3
	 */
	cl = class != NULL ? class : "rfsprocio_v3";
	s->rfsprocio_v3_ptr = nfssrv_kstat_io_init(zoneid, "nfs", instance, nm,
	    NFS_V3, cl, rfsproccnt_v3_tmpl, rfsproccnt_v3_count,
	    s->rfsprocio_v3_data, lock);

	/*
	 * NFS version 4
	 */
	cl = class != NULL ? class : "rfsprocio_v4";
	s->rfsprocio_v4_ptr = nfssrv_kstat_io_init(zoneid, "nfs", instance, nm,
	    NFS_V4, cl, rfsproccnt_v4_tmpl, rfsproccnt_v4_count,
	    s->rfsprocio_v4_data, lock);
}

static void
nfssrv_stats_fini(nfssrv_stats *s)
{
	/*
	 * NFS_ACL kstats
	 */
	nfssrv_kstat_io_fini(s->aclprocio_v2_ptr, aclproccnt_v2_count);
	s->aclprocio_v2_ptr = NULL;
	nfssrv_kstat_io_fini(s->aclprocio_v3_ptr, aclproccnt_v3_count);
	s->aclprocio_v3_ptr = NULL;

	/*
	 * NFS kstats
	 */
	nfssrv_kstat_io_fini(s->rfsprocio_v2_ptr, rfsproccnt_v2_count);
	s->rfsprocio_v2_ptr = NULL;
	nfssrv_kstat_io_fini(s->rfsprocio_v3_ptr, rfsproccnt_v3_count);
	s->rfsprocio_v3_ptr = NULL;
	nfssrv_kstat_io_fini(s->rfsprocio_v4_ptr, rfsproccnt_v4_count);
	s->rfsprocio_v4_ptr = NULL;
}

/*
 * The NFS server ID generator for NFS kstats.
 *
 * Negative IDs are considered invalid.
 *
 * ID = 0 is skipped to distinquish between the global NFS server stats and
 * specialized per-exportinfo, per-client, and per-exportinfo/per-client easier.
 */
static void
nfssrv_idgen_init(struct nfssrv_idgen *nsig, const char *name, size_t size,
    size_t list_off, size_t id_off)
{
	nsig->nsig_name = name;
	nsig->nsig_lastgen = 0;
	list_create(&nsig->nsig_list, size, list_off);
	nsig->nsig_next = NULL;
	nsig->nsig_offset = id_off;
	mutex_init(&nsig->nsig_lock, NULL, MUTEX_DEFAULT, NULL);
}

static void
nfssrv_idgen_fini(struct nfssrv_idgen *nsig)
{
	list_destroy(&nsig->nsig_list);
	mutex_destroy(&nsig->nsig_lock);
}

static void
nfssrv_idgen_generate(struct nfssrv_idgen *nsig, void *entry)
{
	int *idp = (int *)((uintptr_t)entry + nsig->nsig_offset);

	mutex_enter(&nsig->nsig_lock);

	*idp = nsig->nsig_lastgen;

	for (;;) {
		int *idp_next;

		if (++*idp <= 0) {
			zcmn_err(getzoneid(), CE_NOTE,
			    "%s wrap", nsig->nsig_name);

			*idp = 1;
			nsig->nsig_next = list_head(&nsig->nsig_list);
		}

		if (nsig->nsig_next == NULL)
			break;

		idp_next = (int *)((uintptr_t)nsig->nsig_next +
		    nsig->nsig_offset);
		if (*idp < *idp_next)
			break;

		ASSERT(*idp == *idp_next);

		nsig->nsig_next = list_next(&nsig->nsig_list, nsig->nsig_next);

		if (*idp == nsig->nsig_lastgen) {
			zcmn_err(getzoneid(), CE_WARN,
			    "%s exhausted", nsig->nsig_name);

			*idp = -1;
			break;
		}
	};

	if (*idp >= 0) {
		nsig->nsig_lastgen = *idp;
		if (nsig->nsig_next == NULL)
			list_insert_tail(&nsig->nsig_list, entry);
		else
			list_insert_before(&nsig->nsig_list, nsig->nsig_next,
			    entry);
	}

	mutex_exit(&nsig->nsig_lock);
}

static void
nfssrv_idgen_free(struct nfssrv_idgen *nsig, void *entry)
{
	/*
	 * Do not try to remove entries with invalid ID
	 */
	if (*(int *)((uintptr_t)entry + nsig->nsig_offset) < 0)
		return;

	mutex_enter(&nsig->nsig_lock);

	if (nsig->nsig_next == entry)
		nsig->nsig_next = list_next(&nsig->nsig_list, entry);

	list_remove(&nsig->nsig_list, entry);

	mutex_exit(&nsig->nsig_lock);
}

/*
 * Per-exportinfo NFS server stats
 */

void
nfssrv_exp_stats_rele(struct nfssrv_exp_stats *e)
{
	struct nfssrv_clnt_exp_stats *ce;
	struct nfssrv_zone_stats *nfsstatsp;
	void *cookie;

	ASSERT(e->nses_count > 0);
	if (atomic_dec_uint_nv(&e->nses_count) > 0)
		return;

	nfsstatsp = zone_getspecific(nfssrv_stat_zone_key, curzone);
	ASSERT(nfsstatsp != NULL);

	rw_enter(&nfsstatsp->ns_exp_stats_lock, RW_WRITER);
	if (e->nses_count > 0) {
		rw_exit(&nfsstatsp->ns_exp_stats_lock);
		return;
	}

	/*
	 * We hold the ns_exp_stats_lock as WRITER and the nses_count is zero
	 * so we are sure nobody else is referencing this entry.  Thus we are
	 * safe to change the nses_state even without holding the
	 * nses_procio_lock.
	 */
	e->nses_state = NS_STATE_SETUP;
	rw_exit(&nfsstatsp->ns_exp_stats_lock);

	cookie = NULL;
	while ((ce = avl_destroy_nodes(&e->nses_clnt_stats, &cookie)) != NULL) {
		nfssrv_stats_fini(&ce->nsces_stats);
		nfssrv_clnt_stats_rele_norefresh(ce->nsces_clnt_stats);
		kmem_cache_free(nsces_cache, ce);
	}
	avl_destroy(&e->nses_clnt_stats);
	rw_destroy(&e->nses_clnt_stats_lock);

	if (e->nses_share_kstat != NULL) {
		nfssrv_stats_fini(&e->nses_stats);
		kstat_delete(e->nses_share_kstat);
	}

	rw_enter(&nfsstatsp->ns_exp_stats_lock, RW_WRITER);
	if (e->nses_count > 0) {
		rw_exit(&nfsstatsp->ns_exp_stats_lock);

		mutex_enter(&e->nses_procio_lock);
		e->nses_state = NS_STATE_ALLOC;
		cv_signal(&e->nses_cv);
		mutex_exit(&e->nses_procio_lock);

		return;
	}
	avl_remove(&nfsstatsp->ns_exp_stats, e);
	rw_exit(&nfsstatsp->ns_exp_stats_lock);

	nfssrv_idgen_free(&nfsstatsp->ns_exp_idgen, e);
	strfree(e->nses_path);

	mutex_destroy(&e->nses_procio_lock);
	cv_destroy(&e->nses_cv);

	nfssrv_stats_free_data(&e->nses_stats);
	kmem_free(e, sizeof (*e));

	mutex_enter(&nfsstatsp->ns_reaper_lock);
	if (atomic_dec_ulong_nv(&nfsstatsp->ns_exp_stats_cnt) == 0 &&
	    nfsstatsp->ns_reaper_terminate)
		cv_signal(&nfsstatsp->ns_reaper_ss_cv);
	mutex_exit(&nfsstatsp->ns_reaper_lock);
}

struct nfssrv_exp_stats *
nfssrv_get_exp_stats(const char *path, size_t len, bool_t pseudo)
{
	struct nfssrv_exp_stats nses;	/* template for avl_find() */
	struct nfssrv_zone_stats *nfsstatsp;
	struct nfssrv_exp_stats *e;
	struct nfssrv_exp_stats *ne = NULL;

	len = strnlen(path, len);
	nses.nses_path = kmem_alloc(len + 1, KM_SLEEP);
	bcopy(path, nses.nses_path, len);
	nses.nses_path[len] = '\0';
	nses.nses_pseudo = pseudo;

	nfsstatsp = zone_getspecific(nfssrv_stat_zone_key, curzone);
	ASSERT(nfsstatsp != NULL);

	rw_enter(&nfsstatsp->ns_exp_stats_lock, RW_READER);
	e = (struct nfssrv_exp_stats *)avl_find(&nfsstatsp->ns_exp_stats, &nses,
	    NULL);

	if (e == NULL) {
		avl_index_t where;

		rw_exit(&nfsstatsp->ns_exp_stats_lock);

		ne = kmem_alloc(sizeof (*ne), KM_SLEEP);

		(void) nfssrv_stats_alloc_data(&ne->nses_stats, KM_SLEEP);
		nfssrv_stats_clear_data(&ne->nses_stats);
		nfssrv_idgen_generate(&nfsstatsp->ns_exp_idgen, ne);

		ne->nses_state = NS_STATE_ALLOC;
		ne->nses_count = 0;
		ne->nses_path = nses.nses_path;
		ne->nses_pseudo = pseudo;

		mutex_init(&ne->nses_procio_lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&ne->nses_cv, NULL, CV_DEFAULT, NULL);

		rw_enter(&nfsstatsp->ns_exp_stats_lock, RW_WRITER);
		e = (struct nfssrv_exp_stats *)avl_find(
		    &nfsstatsp->ns_exp_stats, &nses, &where);
		if (e == NULL) {
			avl_insert(&nfsstatsp->ns_exp_stats, ne, where);
			e = ne;
		}
	}

	nfssrv_exp_stats_hold(e);

	rw_exit(&nfsstatsp->ns_exp_stats_lock);

	/*
	 * Increment the entries counter for the newly added entry
	 */
	if (e == ne)
		atomic_inc_ulong(&nfsstatsp->ns_exp_stats_cnt);

	/*
	 * Free the no longer needed temporary and speculative allocations
	 */
	if (ne != NULL && ne != e) {
		mutex_destroy(&ne->nses_procio_lock);
		cv_destroy(&ne->nses_cv);

		nfssrv_idgen_free(&nfsstatsp->ns_exp_idgen, ne);
		nfssrv_stats_free_data(&ne->nses_stats);

		kmem_free(ne, sizeof (*ne));
	}
	if (e->nses_path != nses.nses_path)
		strfree(nses.nses_path);

	/*
	 * Complete the initialization if needed
	 */
	mutex_enter(&e->nses_procio_lock);

	while (e->nses_state == NS_STATE_SETUP)
		cv_wait(&e->nses_cv, &e->nses_procio_lock);

	if (e->nses_state == NS_STATE_ALLOC) {
		atomic_write_uchar(&e->nses_state, NS_STATE_SETUP);
		mutex_exit(&e->nses_procio_lock);

		avl_create(&e->nses_clnt_stats, nfssrv_clnt_exp_stats_compar,
		    sizeof (struct nfssrv_clnt_exp_stats),
		    offsetof(struct nfssrv_clnt_exp_stats, nsces_link));
		rw_init(&e->nses_clnt_stats_lock, NULL, RW_DEFAULT, NULL);

		/*
		 * Generic share kstat
		 */
		if ((nfssrv_stats_flags & (EXP_STATS | CLNT_EXP_STATS)) == 0 ||
		    e->nses_id < 0) {
			e->nses_share_kstat = NULL;
		} else {
			e->nses_share_kstat = kstat_create_zone("nfs",
			    e->nses_id, "share", "misc", KSTAT_TYPE_NAMED,
			    sizeof (e->nses_share_kstat_data) /
			    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL |
			    KSTAT_FLAG_VAR_SIZE, getzoneid());
		}

		if (e->nses_share_kstat != NULL) {
			e->nses_share_kstat->ks_data =
			    &e->nses_share_kstat_data;

			kstat_named_init(&e->nses_share_kstat_data.path, "path",
			    KSTAT_DATA_STRING);
			kstat_named_setstr(&e->nses_share_kstat_data.path,
			    e->nses_path);

			kstat_named_init(&e->nses_share_kstat_data.filesystem,
			    "filesystem", KSTAT_DATA_STRING);
			kstat_named_setstr(&e->nses_share_kstat_data.filesystem,
			    e->nses_pseudo ? "pseudo" : "real");

			e->nses_share_kstat->ks_lock = &e->nses_procio_lock;
			kstat_install(e->nses_share_kstat);

			/*
			 * Detailed share kstats
			 */
			if ((nfssrv_stats_flags & EXP_STATS) != 0) {
				nfssrv_stats_init(&e->nses_stats, getzoneid(),
				    e->nses_id, "share", NULL,
				    &e->nses_procio_lock);
			}
		}

		mutex_enter(&e->nses_procio_lock);
		atomic_write_uchar(&e->nses_state, NS_STATE_OK);
		cv_broadcast(&e->nses_cv);
	}

	mutex_exit(&e->nses_procio_lock);

	/*
	 * It is a bug to call this function during shutdown
	 */
	ASSERT(!nfsstatsp->ns_reaper_terminate);

	return (e);
}

static int
nfssrv_exp_stats_compar(const void *v1, const void *v2)
{
	int c;

	const struct nfssrv_exp_stats *e1 = (const struct nfssrv_exp_stats *)v1;
	const struct nfssrv_exp_stats *e2 = (const struct nfssrv_exp_stats *)v2;

	c = strcmp(e1->nses_path, e2->nses_path);
	if (c < 0)
		return (-1);
	if (c > 0)
		return (1);

	if (e1->nses_pseudo < e2->nses_pseudo)
		return (-1);
	if (e1->nses_pseudo > e2->nses_pseudo)
		return (1);

	return (0);
}

/*
 * Per-client NFS server stats
 */

static void
nfssrv_clnt_stats_rele_norefresh(struct nfssrv_clnt_stats *c)
{
	struct nfssrv_zone_stats *nfsstatsp;

	ASSERT(c->nscs_count > 0);
	if (atomic_dec_uint_nv(&c->nscs_count) > 0)
		return;

	nfsstatsp = zone_getspecific(nfssrv_stat_zone_key, curzone);
	ASSERT(nfsstatsp != NULL);

	rw_enter(&nfsstatsp->ns_clnt_stats_lock, RW_WRITER);
	if (c->nscs_count > 0) {
		rw_exit(&nfsstatsp->ns_clnt_stats_lock);
		return;
	}

	/*
	 * We hold the ns_clnt_stats_lock as WRITER and the nscs_count is
	 * zero so we are sure nobody else is referencing this entry.  Thus we
	 * are safe to work with the nscs_state even without holding the
	 * nscs_procio_lock.
	 */
	if (c->nscs_state != NS_STATE_AGED && !nfsstatsp->ns_reaper_terminate) {
		rw_exit(&nfsstatsp->ns_clnt_stats_lock);
		return;
	}
	c->nscs_state = NS_STATE_SETUP;
	rw_exit(&nfsstatsp->ns_clnt_stats_lock);

	if (c->nscs_clnt_kstat != NULL) {
		nfssrv_stats_fini(&c->nscs_stats);
		kstat_delete(c->nscs_clnt_kstat);
	}

	strfree(c->nscs_clnt_addr_str);

	rw_enter(&nfsstatsp->ns_clnt_stats_lock, RW_WRITER);
	if (c->nscs_count > 0) {
		rw_exit(&nfsstatsp->ns_clnt_stats_lock);

		mutex_enter(&c->nscs_procio_lock);
		c->nscs_state = NS_STATE_ALLOC;
		cv_signal(&c->nscs_cv);
		mutex_exit(&c->nscs_procio_lock);

		return;
	}
	avl_remove(&nfsstatsp->ns_clnt_stats, c);
	rw_exit(&nfsstatsp->ns_clnt_stats_lock);

	nfssrv_idgen_free(&nfsstatsp->ns_clnt_idgen, c);
	kmem_free(c->nscs_clnt_addr.buf, c->nscs_clnt_addr.maxlen);

	kmem_cache_free(nscs_cache, c);

	mutex_enter(&nfsstatsp->ns_reaper_lock);
	if (atomic_dec_ulong_nv(&nfsstatsp->ns_clnt_stats_cnt) == 0 &&
	    nfsstatsp->ns_reaper_terminate)
		cv_signal(&nfsstatsp->ns_reaper_ss_cv);
	mutex_exit(&nfsstatsp->ns_reaper_lock);
}

void
nfssrv_clnt_stats_rele(struct nfssrv_clnt_stats *c)
{
	time_t ts = gethrestime_sec();

	mutex_enter(&c->nscs_procio_lock);
	c->nscs_ts = ts;
	atomic_write_uchar(&c->nscs_state, NS_STATE_OK);
	mutex_exit(&c->nscs_procio_lock);

	nfssrv_clnt_stats_rele_norefresh(c);
}

static void
nfssrv_clnt_stats_rele_aged(struct nfssrv_clnt_stats *c, time_t aged)
{
	/*
	 * First, try to read nscs_ts without the nscs_procio_lock mutex held.
	 * In this case we do not mind about the possible data race because
	 * such a race is harmless here.  If a torn nscs_ts read occurs it
	 * simply means that some other thread is just updating the nscs_ts
	 * with the current timestamp, so the entry is not stale.  We will
	 * notice it either immediately (in a case the torn read produces the
	 * new enough timestamp), or later with mutex held (in a case we are
	 * unlucky here).
	 */
	if (c->nscs_ts < aged) {
		mutex_enter(&c->nscs_procio_lock);
		if (c->nscs_ts < aged)
			atomic_write_uchar(&c->nscs_state, NS_STATE_AGED);
		mutex_exit(&c->nscs_procio_lock);
	}

	nfssrv_clnt_stats_rele_norefresh(c);
}

extern const char *kinet_ntop6(uchar_t *, char *, size_t);

struct nfssrv_clnt_stats *
nfssrv_get_clnt_stats(SVCXPRT *xprt)
{
	struct netbuf addr;		/* client's address */
	const struct netbuf *addrp;	/* pointer to the client's address */
	struct netbuf *addrmask;	/* client's address mask */
	int i;
	struct nfssrv_zone_stats *nfsstatsp;
	struct nfssrv_clnt_stats nscs;	/* template for avl_find() */
	struct nfssrv_clnt_stats *c;
	struct nfssrv_clnt_stats *nc = NULL;

	/*
	 * Copy the client's address
	 */
	addrp = svc_getrpccaller(xprt);
	ASSERT(addrp != NULL);
	addr = *addrp;
	addr.buf = kmem_alloc(addr.maxlen, KM_SLEEP);
	bcopy(addrp->buf, addr.buf, addrp->len);

	/*
	 * Mask off the parts that do not identify the host (port number, etc)
	 */
	SVC_GETADDRMASK(xprt, SVC_TATTR_ADDRMASK, (void **)&addrmask);
	ASSERT(addrmask != NULL);
	ASSERT(addr.len == addrmask->len);
	for (i = 0; i < addr.len; i++)
		addr.buf[i] &= addrmask->buf[i];

	nscs.nscs_clnt_addr = addr;

	nfsstatsp = zone_getspecific(nfssrv_stat_zone_key, curzone);
	ASSERT(nfsstatsp != NULL);

	rw_enter(&nfsstatsp->ns_clnt_stats_lock, RW_READER);
	c = (struct nfssrv_clnt_stats *)avl_find(&nfsstatsp->ns_clnt_stats,
	    &nscs, NULL);

	if (c == NULL) {
		avl_index_t where;

		rw_exit(&nfsstatsp->ns_clnt_stats_lock);

		nc = kmem_cache_alloc(nscs_cache, KM_SLEEP);

		nfssrv_stats_clear_data(&nc->nscs_stats);
		nfssrv_idgen_generate(&nfsstatsp->ns_clnt_idgen, nc);

		nc->nscs_state = NS_STATE_ALLOC;
		nc->nscs_ts = 0;
		nc->nscs_clnt_addr = addr;

		rw_enter(&nfsstatsp->ns_clnt_stats_lock, RW_WRITER);
		c = (struct nfssrv_clnt_stats *)avl_find(
		    &nfsstatsp->ns_clnt_stats, &nscs, &where);
		if (c == NULL) {
			avl_insert(&nfsstatsp->ns_clnt_stats, nc, where);
			c = nc;
		}
	}

	nfssrv_clnt_stats_hold(c);

	rw_exit(&nfsstatsp->ns_clnt_stats_lock);

	/*
	 * Increment the entries counter for the newly added entry
	 */
	if (c == nc)
		atomic_inc_ulong(&nfsstatsp->ns_clnt_stats_cnt);

	/*
	 * Free the no longer needed temporary and speculative allocations
	 */
	if (nc != NULL && nc != c) {
		nfssrv_idgen_free(&nfsstatsp->ns_clnt_idgen, nc);
		kmem_cache_free(nscs_cache, nc);
	}
	if (c->nscs_clnt_addr.buf != addr.buf)
		kmem_free(addr.buf, addr.maxlen);

	/*
	 * Complete the initialization if needed
	 */
	mutex_enter(&c->nscs_procio_lock);

	while (c->nscs_state == NS_STATE_SETUP)
		cv_wait(&c->nscs_cv, &c->nscs_procio_lock);

	if (c->nscs_state == NS_STATE_ALLOC) {
		atomic_write_uchar(&c->nscs_state, NS_STATE_SETUP);
		mutex_exit(&c->nscs_procio_lock);

		/*
		 * Initialize nscs_clnt_addr_family and nscs_clnt_addr_str
		 */
		if (c->nscs_clnt_addr.len <
		    offsetof(struct sockaddr, sa_family) +
		    sizeof (((struct sockaddr *)0)->sa_family)) {
			c->nscs_clnt_addr_family = AF_UNSPEC;
			c->nscs_clnt_addr_str = strdup("<unknown>");
		} else {
			struct sockaddr *sa =
			    (struct sockaddr *)c->nscs_clnt_addr.buf;

			c->nscs_clnt_addr_family = sa->sa_family;
			c->nscs_clnt_addr_str = NULL;

			if (sa->sa_family == AF_INET &&
			    c->nscs_clnt_addr.len >=
			    offsetof(struct sockaddr_in, sin_addr) +
			    sizeof (((struct sockaddr_in *)0)->sin_addr)) {
				char buf[INET_ADDRSTRLEN];
				uint8_t *b;
				int r;

				b = (uint8_t *)&((struct sockaddr_in *)sa)->
				    sin_addr;
				r = snprintf(buf, sizeof (buf), "%d.%d.%d.%d",
				    b[0] & 0xff, b[1] & 0xff, b[2] & 0xff,
				    b[3] & 0xff);
				if (r >= 0 && r < sizeof (buf))
					c->nscs_clnt_addr_str = strdup(buf);
			} else if (sa->sa_family == AF_INET6 &&
			    c->nscs_clnt_addr.len >=
			    offsetof(struct sockaddr_in6, sin6_addr)
			    + sizeof (((struct sockaddr_in6 *)0)->sin6_addr)) {
				char buf[INET6_ADDRSTRLEN];
				struct sockaddr_in6 *sin6;

				sin6 = (struct sockaddr_in6 *)sa;
				if (kinet_ntop6((uchar_t *)&sin6->sin6_addr,
				    buf, sizeof (buf)) != NULL)
					c->nscs_clnt_addr_str = strdup(buf);
			}

			if (c->nscs_clnt_addr_str == NULL) {
				unsigned int l = 0;
				uint8_t *s;
				char *p;

				if (c->nscs_clnt_addr.len >
				    offsetof(struct sockaddr, sa_data))
					l = c->nscs_clnt_addr.len -
					    offsetof(struct sockaddr, sa_data);

				c->nscs_clnt_addr_str = kmem_alloc(l * 2 + 1,
				    KM_SLEEP);

				s = (uint8_t *)&((struct sockaddr *)
				    c->nscs_clnt_addr.buf)->sa_data;
				p = c->nscs_clnt_addr_str;

				for (; l > 0; l--) {
					if (snprintf(p, 2, "%02x", *s++ & 0xff)
					    != 2) {
						p[0] = '?';
						p[1] = '?';
					}

					p += 2;
				}
				*p = '\0';
			}
		}

		/*
		 * Generic client kstat
		 */
		if ((nfssrv_stats_flags & (CLNT_STATS | CLNT_EXP_STATS)) == 0 ||
		    c->nscs_id < 0) {
			c->nscs_clnt_kstat = NULL;
		} else {
			c->nscs_clnt_kstat = kstat_create_zone("nfs",
			    c->nscs_id, "client", "misc", KSTAT_TYPE_NAMED,
			    sizeof (c->nscs_clnt_kstat_data) /
			    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL |
			    KSTAT_FLAG_VAR_SIZE, getzoneid());
		}

		if (c->nscs_clnt_kstat != NULL) {
			c->nscs_clnt_kstat->ks_data = &c->nscs_clnt_kstat_data;

			kstat_named_init(&c->nscs_clnt_kstat_data.addr_family,
			    "addr_family", KSTAT_DATA_UINT32);
			c->nscs_clnt_kstat_data.addr_family.value.ui32 =
			    c->nscs_clnt_addr_family;

			kstat_named_init(&c->nscs_clnt_kstat_data.address,
			    "address", KSTAT_DATA_STRING);
			kstat_named_setstr(&c->nscs_clnt_kstat_data.address,
			    c->nscs_clnt_addr_str);

			c->nscs_clnt_kstat->ks_lock = &c->nscs_procio_lock;
			kstat_install(c->nscs_clnt_kstat);

			/*
			 * Detailed client kstats
			 */
			if ((nfssrv_stats_flags & CLNT_STATS) != 0) {
				nfssrv_stats_init(&c->nscs_stats, getzoneid(),
				    c->nscs_id, "client", NULL,
				    &c->nscs_procio_lock);
			}
		}

		mutex_enter(&c->nscs_procio_lock);
		atomic_write_uchar(&c->nscs_state, NS_STATE_OK);
		cv_broadcast(&c->nscs_cv);
	}

	mutex_exit(&c->nscs_procio_lock);

	/*
	 * It is a bug to call this function during shutdown
	 */
	ASSERT(!nfsstatsp->ns_reaper_terminate);

	return (c);
}

static int
nfssrv_clnt_stats_compar(const void *v1, const void *v2)
{
	int c;

	const struct nfssrv_clnt_stats *c1 =
	    (const struct nfssrv_clnt_stats *)v1;
	const struct nfssrv_clnt_stats *c2 =
	    (const struct nfssrv_clnt_stats *)v2;

	if (c1->nscs_clnt_addr.len < c2->nscs_clnt_addr.len)
		return (-1);
	if (c1->nscs_clnt_addr.len > c2->nscs_clnt_addr.len)
		return (1);

	c = memcmp(c1->nscs_clnt_addr.buf, c2->nscs_clnt_addr.buf,
	    c1->nscs_clnt_addr.len);
	if (c < 0)
		return (-1);
	if (c > 0)
		return (1);

	return (0);
}

/*
 * Per-client/per-exportinfo NFS server stats
 */

void
nfssrv_clnt_exp_stats_hold(struct nfssrv_clnt_exp_stats *ce)
{
	nfssrv_exp_stats_hold(ce->nsces_exp_stats);
	atomic_inc_uint(&ce->nsces_count);
}

static void
nfssrv_clnt_exp_stats_rele_norefresh(struct nfssrv_clnt_exp_stats *ce)
{
	struct nfssrv_exp_stats *nses = ce->nsces_exp_stats;

	ASSERT(ce->nsces_count > 0);
	if (atomic_dec_uint_nv(&ce->nsces_count) > 0)
		goto out;

	rw_enter(&nses->nses_clnt_stats_lock, RW_WRITER);
	if (ce->nsces_count > 0) {
		rw_exit(&nses->nses_clnt_stats_lock);
		goto out;
	}

	/*
	 * We hold the nses_clnt_stats_lock as WRITER and the nsces_count is
	 * zero so we are sure nobody else is referencing this entry.  Thus we
	 * are safe to work with the nsces_state even without holding the
	 * nsces_procio_lock.
	 */
	if (ce->nsces_state != NS_STATE_AGED) {
		rw_exit(&nses->nses_clnt_stats_lock);
		goto out;
	}
	ce->nsces_state = NS_STATE_SETUP;
	rw_exit(&nses->nses_clnt_stats_lock);

	nfssrv_stats_fini(&ce->nsces_stats);

	rw_enter(&nses->nses_clnt_stats_lock, RW_WRITER);
	if (ce->nsces_count > 0) {
		rw_exit(&nses->nses_clnt_stats_lock);

		mutex_enter(&ce->nsces_procio_lock);
		ce->nsces_state = NS_STATE_ALLOC;
		cv_signal(&ce->nsces_cv);
		mutex_exit(&ce->nsces_procio_lock);

		goto out;
	}
	avl_remove(&nses->nses_clnt_stats, ce);
	rw_exit(&nses->nses_clnt_stats_lock);

	nfssrv_clnt_stats_rele_norefresh(ce->nsces_clnt_stats);
	kmem_cache_free(nsces_cache, ce);

out:
	nfssrv_exp_stats_rele(nses);
}

void
nfssrv_clnt_exp_stats_rele(struct nfssrv_clnt_exp_stats *ce)
{
	time_t ts = gethrestime_sec();

	mutex_enter(&ce->nsces_procio_lock);
	ce->nsces_ts = ts;
	atomic_write_uchar(&ce->nsces_state, NS_STATE_OK);
	mutex_exit(&ce->nsces_procio_lock);

	nfssrv_clnt_exp_stats_rele_norefresh(ce);
}

static void
nfssrv_clnt_exp_stats_rele_aged(struct nfssrv_clnt_exp_stats *ce, time_t aged)
{
	/*
	 * First, try to read nsces_ts without the nsces_procio_lock mutex
	 * held.  In this case we do not mind about the possible data race
	 * because such a race is harmless here.  If a torn nsces_ts read
	 * occurs it simply means that some other thread is just updating the
	 * nsces_ts with the current timestamp, so the entry is not stale.  We
	 * will notice it either immediately (in a case the torn read produces
	 * the new enough timestamp), or later with mutex held (in a case we
	 * are unlucky here).
	 */
	if (ce->nsces_ts < aged) {
		mutex_enter(&ce->nsces_procio_lock);
		if (ce->nsces_ts < aged)
			atomic_write_uchar(&ce->nsces_state, NS_STATE_AGED);
		mutex_exit(&ce->nsces_procio_lock);
	}

	nfssrv_clnt_exp_stats_rele_norefresh(ce);
}

struct nfssrv_clnt_exp_stats *
nfssrv_get_clnt_exp_stats(struct nfssrv_clnt_stats *c,
    struct nfssrv_exp_stats *e)
{
	struct nfssrv_clnt_exp_stats nsces;	/* template for avl_find() */
	struct nfssrv_clnt_exp_stats *ce;
	struct nfssrv_clnt_exp_stats *nce = NULL;

	nsces.nsces_clnt_stats = c;

	rw_enter(&e->nses_clnt_stats_lock, RW_READER);
	ce = (struct nfssrv_clnt_exp_stats *)avl_find(&e->nses_clnt_stats,
	    &nsces, NULL);

	if (ce == NULL) {
		avl_index_t where;

		rw_exit(&e->nses_clnt_stats_lock);

		nce = kmem_cache_alloc(nsces_cache, KM_SLEEP);

		nfssrv_stats_clear_data(&nce->nsces_stats);

		nce->nsces_state = NS_STATE_ALLOC;
		nce->nsces_ts = 0;
		nce->nsces_exp_stats = e;
		nce->nsces_clnt_stats = c;
		nfssrv_clnt_stats_hold(c);

		rw_enter(&e->nses_clnt_stats_lock, RW_WRITER);
		ce = (struct nfssrv_clnt_exp_stats *)avl_find(
		    &e->nses_clnt_stats, &nsces, &where);
		if (ce == NULL) {
			avl_insert(&e->nses_clnt_stats, nce, where);
			ce = nce;
		}
	}

	nfssrv_clnt_exp_stats_hold(ce);

	rw_exit(&e->nses_clnt_stats_lock);

	/*
	 * Free the no longer needed temporary and speculative allocations
	 */
	if (nce != NULL && nce != ce) {
		nfssrv_clnt_stats_rele_norefresh(c);
		kmem_cache_free(nsces_cache, nce);
	}

	/*
	 * Complete the initialization if needed
	 */
	mutex_enter(&ce->nsces_procio_lock);

	while (ce->nsces_state == NS_STATE_SETUP)
		cv_wait(&ce->nsces_cv, &ce->nsces_procio_lock);

	if (ce->nsces_state == NS_STATE_ALLOC) {
		atomic_write_uchar(&ce->nsces_state, NS_STATE_SETUP);
		mutex_exit(&ce->nsces_procio_lock);

		/*
		 * If we do not have the generic share or client kstat or the
		 * per-exportinfo/per-client kstats are disabled do not create
		 * the detailed kstats.
		 */
		if (ce->nsces_exp_stats->nses_share_kstat != NULL &&
		    ce->nsces_clnt_stats->nscs_clnt_kstat != NULL &&
		    (nfssrv_stats_flags & CLNT_EXP_STATS) != 0) {
			char class[KSTAT_STRLEN];
			int r;

			ASSERT(ce->nsces_exp_stats->nses_id >= 0);
			ASSERT(ce->nsces_clnt_stats->nscs_id >= 0);

			r = snprintf(class, sizeof (class), "client%d",
			    ce->nsces_clnt_stats->nscs_id);
			if (r >= 0 && r < sizeof (class)) {
				nfssrv_stats_init(&ce->nsces_stats, getzoneid(),
				    ce->nsces_exp_stats->nses_id, NULL, class,
				    &ce->nsces_procio_lock);
			}
		}

		mutex_enter(&ce->nsces_procio_lock);
		atomic_write_uchar(&ce->nsces_state, NS_STATE_OK);
		cv_broadcast(&ce->nsces_cv);
	}

	mutex_exit(&ce->nsces_procio_lock);

#ifdef DEBUG
	{
		struct nfssrv_zone_stats *nfsstatsp;

		nfsstatsp = zone_getspecific(nfssrv_stat_zone_key, curzone);
		ASSERT(nfsstatsp != NULL);

		/*
		 * It is a bug to call this function during shutdown
		 */
		ASSERT(!nfsstatsp->ns_reaper_terminate);
	}
#endif	/* DEBUG */

	return (ce);
}

static int
nfssrv_clnt_exp_stats_compar(const void *v1, const void *v2)
{
	const struct nfssrv_clnt_exp_stats *ce1 =
	    (const struct nfssrv_clnt_exp_stats *)v1;
	const struct nfssrv_clnt_exp_stats *ce2 =
	    (const struct nfssrv_clnt_exp_stats *)v2;

	if (ce1->nsces_clnt_stats < ce2->nsces_clnt_stats)
		return (-1);
	if (ce1->nsces_clnt_stats > ce2->nsces_clnt_stats)
		return (1);

	return (0);
}

/*
 * nfssrv_kstat_do_io()
 */
void
nfssrv_kstat_do_io(kstat_io_t *kiop, kmutex_t *lock, int flag, size_t write,
    size_t read)
{
	ASSERT((flag & (NFSSRV_KST_ENTER | NFSSRV_KST_EXIT)) !=
	    (NFSSRV_KST_ENTER | NFSSRV_KST_EXIT));

	mutex_enter(lock);
	if ((flag & NFSSRV_KST_ENTER) != 0)
		kstat_runq_enter(kiop);
	if ((flag & NFSSRV_KST_EXIT) != 0)
		kstat_runq_exit(kiop);
	if ((flag & NFSSRV_KST_WRITE) != 0) {
		kiop->nwritten += write;
		kiop->writes++;
	}
	if ((flag & NFSSRV_KST_READ) != 0) {
		kiop->nread += read;
		kiop->reads++;
	}
	mutex_exit(lock);
}

/*
 * Pointers to global zone NFS server kstat data
 */
kstat_io_t *aclprocio_v2_ptr;
kstat_io_t *aclprocio_v3_ptr;
kstat_io_t *rfsprocio_v2_ptr;
kstat_io_t *rfsprocio_v3_ptr;
kstat_io_t *rfsprocio_v4_ptr;
kmutex_t *nfssrv_stat_procio_lock;

/*
 * Zone initialization/deinitialization for NFS server stats
 */
static void *
nfssrv_stat_zone_init(zoneid_t zoneid)
{
	_NOTE(ARGUNUSED(zoneid))

	struct nfssrv_zone_stats *nfsstatsp;

	nfsstatsp = kmem_zalloc(sizeof (*nfsstatsp), KM_SLEEP);

	/*
	 * Initialize detailed per-server NFS stats
	 */
	mutex_init(&nfsstatsp->ns_procio_lock, NULL, MUTEX_DEFAULT, NULL);
	(void) nfssrv_stats_alloc_data(&nfsstatsp->ns_stats, KM_SLEEP);
	nfssrv_stats_clear_data(&nfsstatsp->ns_stats);
	if ((nfssrv_stats_flags & SRV_STATS) != 0) {
		nfssrv_stats_init(&nfsstatsp->ns_stats, getzoneid(), 0, NULL,
		    NULL, &nfsstatsp->ns_procio_lock);
	}
	if (zoneid == GLOBAL_ZONEID) {
		aclprocio_v2_ptr = nfsstatsp->ns_stats.aclprocio_v2_data;
		aclprocio_v3_ptr = nfsstatsp->ns_stats.aclprocio_v3_data;
		rfsprocio_v2_ptr = nfsstatsp->ns_stats.rfsprocio_v2_data;
		rfsprocio_v3_ptr = nfsstatsp->ns_stats.rfsprocio_v3_data;
		rfsprocio_v4_ptr = nfsstatsp->ns_stats.rfsprocio_v4_data;
		nfssrv_stat_procio_lock = &nfsstatsp->ns_procio_lock;
	}

	/*
	 * Initialize the ID generators
	 */
	nfssrv_idgen_init(&nfsstatsp->ns_exp_idgen,
	    "NFS server per-exportinfo kstat ID",
	    sizeof (struct nfssrv_exp_stats),
	    offsetof(struct nfssrv_exp_stats, nses_id_node),
	    offsetof(struct nfssrv_exp_stats, nses_id));
	nfssrv_idgen_init(&nfsstatsp->ns_clnt_idgen,
	    "NFS server per-client kstat ID",
	    sizeof (struct nfssrv_clnt_stats),
	    offsetof(struct nfssrv_clnt_stats, nscs_id_node),
	    offsetof(struct nfssrv_clnt_stats, nscs_id));

	/*
	 * Initialize AVL trees
	 */
	avl_create(&nfsstatsp->ns_exp_stats, nfssrv_exp_stats_compar,
	    sizeof (struct nfssrv_exp_stats),
	    offsetof(struct nfssrv_exp_stats, nses_link));
	rw_init(&nfsstatsp->ns_exp_stats_lock, NULL, RW_DEFAULT, NULL);

	avl_create(&nfsstatsp->ns_clnt_stats, nfssrv_clnt_stats_compar,
	    sizeof (struct nfssrv_clnt_stats),
	    offsetof(struct nfssrv_clnt_stats, nscs_link));
	rw_init(&nfsstatsp->ns_clnt_stats_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Start the reapers
	 */
	mutex_init(&nfsstatsp->ns_reaper_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&nfsstatsp->ns_reaper_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&nfsstatsp->ns_reaper_ss_cv, NULL, CV_DEFAULT, NULL);

	mutex_enter(&nfsstatsp->ns_reaper_lock);
	nfsstatsp->ns_reaper_threads = 0;
	(void) zthread_create(NULL, 0, nscs_reaper, nfsstatsp, 0,
	    minclsyspri);
	(void) zthread_create(NULL, 0, nsces_reaper, nfsstatsp, 0,
	    minclsyspri);
	while (nfsstatsp->ns_reaper_threads != 2)
		cv_wait(&nfsstatsp->ns_reaper_ss_cv,
		    &nfsstatsp->ns_reaper_lock);
	mutex_exit(&nfsstatsp->ns_reaper_lock);

	return (nfsstatsp);
}

static void
nfssrv_stat_zone_fini(zoneid_t zoneid, void *data)
{
	_NOTE(ARGUNUSED(zoneid))

	struct nfssrv_zone_stats *nfsstatsp = data;

	/*
	 * Stop the reapers
	 */
	mutex_enter(&nfsstatsp->ns_reaper_lock);
	nfsstatsp->ns_reaper_terminate = TRUE;
	cv_broadcast(&nfsstatsp->ns_reaper_cv);
	ASSERT(nfsstatsp->ns_reaper_threads == 2);
	while (nfsstatsp->ns_reaper_threads != 0)
		cv_wait(&nfsstatsp->ns_reaper_ss_cv,
		    &nfsstatsp->ns_reaper_lock);
	mutex_exit(&nfsstatsp->ns_reaper_lock);

	/*
	 * Cleanup leftovers, if any
	 */
	nsces_reap(nfsstatsp, 0);
	nscs_reap(nfsstatsp, 0);

	/*
	 * Wait until all AVLs are empty and all release threads are completed
	 */
	mutex_enter(&nfsstatsp->ns_reaper_lock);
	while (nfsstatsp->ns_exp_stats_cnt != 0 ||
	    nfsstatsp->ns_clnt_stats_cnt != 0)
		cv_wait(&nfsstatsp->ns_reaper_ss_cv,
		    &nfsstatsp->ns_reaper_lock);
	mutex_exit(&nfsstatsp->ns_reaper_lock);

	mutex_destroy(&nfsstatsp->ns_reaper_lock);
	cv_destroy(&nfsstatsp->ns_reaper_cv);
	cv_destroy(&nfsstatsp->ns_reaper_ss_cv);

	/*
	 * ID generators cleanup
	 */
	nfssrv_idgen_fini(&nfsstatsp->ns_exp_idgen);
	nfssrv_idgen_fini(&nfsstatsp->ns_clnt_idgen);

	/*
	 * Destroy AVL trees
	 */
	avl_destroy(&nfsstatsp->ns_exp_stats);
	rw_destroy(&nfsstatsp->ns_exp_stats_lock);

	avl_destroy(&nfsstatsp->ns_clnt_stats);
	rw_destroy(&nfsstatsp->ns_clnt_stats_lock);

	/*
	 * Detailed per-server NFS stats cleanup
	 */
	if (zoneid == GLOBAL_ZONEID) {
		aclprocio_v2_ptr = NULL;
		aclprocio_v3_ptr = NULL;
		rfsprocio_v2_ptr = NULL;
		rfsprocio_v3_ptr = NULL;
		rfsprocio_v4_ptr = NULL;
		nfssrv_stat_procio_lock = NULL;
	}
	nfssrv_stats_fini(&nfsstatsp->ns_stats);
	nfssrv_stats_free_data(&nfsstatsp->ns_stats);
	mutex_destroy(&nfsstatsp->ns_procio_lock);

	kmem_free(nfsstatsp, sizeof (*nfsstatsp));
}

/*
 * The NFS server stats subsystem initialization and deinitialization.
 */
void
nfssrv_stat_init(void)
{
	nscs_cache = kmem_cache_create("nfssrv_clnt_stats",
	    sizeof (struct nfssrv_clnt_stats), 0, nscs_ctor, nscs_dtor,
	    nscs_reclaim, NULL, NULL, 0);

	nsces_cache = kmem_cache_create("nfssrv_clnt_exp_stats",
	    sizeof (struct nfssrv_clnt_exp_stats), 0, nsces_ctor, nsces_dtor,
	    nsces_reclaim, NULL, NULL, 0);

	zone_key_create(&nfssrv_stat_zone_key, nfssrv_stat_zone_init, NULL,
	    nfssrv_stat_zone_fini);
}

void
nfssrv_stat_fini(void)
{
	(void) zone_key_delete(nfssrv_stat_zone_key);

	kmem_cache_destroy(nsces_cache);
	kmem_cache_destroy(nscs_cache);
}
