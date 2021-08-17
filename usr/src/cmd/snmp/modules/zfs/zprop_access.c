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
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/debug.h>
#include <sys/time.h>

#include <sys/fs/zfs.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <libnvpair.h>
#include <libzfs_core.h>

#include <errno.h>
#include <inttypes.h>
#include <strings.h>
#include <synch.h>

#include "zfs_snmp.h"
#include "zprop_access.h"

/* XXX There should be better place for these than zio.h */
#define	ZIO_FAILURE_MODE_WAIT		0
#define	ZIO_FAILURE_MODE_CONTINUE	1
#define	ZIO_FAILURE_MODE_PANIC		2

/* Cache timeout in seconds converted to ns */
static hrtime_t cache_timeout = (ZPOOL_CACHE_TIMEOUT * 1E9);

/*
 * We are really an nvlist, and any pool properties that appear here and are
 * pointers are references to data interned in the nvlists. We only use
 * non-pointer values where the nvlist will return a literal (because the
 * value can be represented with a 64-bit value or if we need to tranform the
 * data for SNMP representation, in which case we size sufficiently large
 * buffers on the members that we don't need to perform further
 * allocations. By consequence, then, we only need to manage memory directly
 * for the pool nodes.
 */
typedef struct pool_node {
	char			*pn_name;
	uint64_t		pn_guid;
	char			pn_guidstr[21];
	nvlist_t		*pn_props;
	struct pool_node	*pn_next;
} pool_node_t;

static pool_node_t *ph_first;
static nvlist_t *ph_cfg;
static uint64_t ph_gen;
static rwlock_t ph_lock = DEFAULTRWLOCK;
static hrtime_t ph_ts;

/*
 * If the pool was there and now it's not, the pool has been removed, so we
 * need not propagate errors back to callers.
 */
static void
refresh_pool_node(pool_node_t *pnp, const char *name, const uint64_t guid)
{
	int ret;
	nvlist_t *props, *cfg;
	nvpair_t *nvp;

	/* Returns errno value on failure. */
	if ((ret = lzc_pool_get_props(name, &props)) != 0) {
		(void) snmp_log(LOG_ERR,
		    "%s: props retrieval failed for %s: %s",
		    MODULE_NAME, name, strerror(ret));
		return;
	} else { /* XXX Should we double-check against GUID? */
		nvlist_t *prune = NULL;

		if (pnp->pn_props != NULL)
			prune = pnp->pn_props;
		pnp->pn_props = props;
		nvlist_free(prune);
	}

	/*
	 * Retrieve our name pointer from the durable cache rather than the
	 * scratch copy.
	 */
	cfg = ph_cfg;
	nvp = nvlist_next_nvpair(cfg, NULL);
	while (nvp != NULL) {
		char *pname = nvpair_name(nvp);

		if (strcmp(pname, name) == 0)
			pnp->pn_name = pname;
		nvp = nvlist_next_nvpair(cfg, nvp);
	}
	pnp->pn_guid = guid;
	(void) sprintf(pnp->pn_guidstr, "%"PRIu64, pnp->pn_guid);

	DEBUGMSGTL((MODULE_NAME, "%s: success for %s(%"PRIu64")\n", __func__,
	    name, guid));
}

static int
init_pool_node(const char *name, const uint64_t guid, pool_node_t **pnpp)
{
	int ret;
	pool_node_t *pnp;

	pnp = SNMP_MALLOC_TYPEDEF(pool_node_t);
	if (pnp == NULL) {
		ret = errno;
		(void) snmp_log(LOG_ERR, "%s: pool node allocation failed: %s",
		    MODULE_NAME, strerror(ret));
		return (ret);
	}
	refresh_pool_node(pnp, name, guid);
	*pnpp = pnp;

	DEBUGMSGTL((MODULE_NAME, "initialized %s(%"PRIu64")\n",
	    name, guid));
	return (0);
}

static void
destroy_pool_node(pool_node_t *pnp)
{
	DEBUGMSGTL((MODULE_NAME, "destroying %s(%"PRIu64")\n",
	    pnp->pn_name, pnp->pn_guid));
	nvlist_free(pnp->pn_props);
	SNMP_FREE(pnp);
}

static int
findcreate_pool_node(nvlist_t *cfg, pool_node_t **pnpp, boolean_t create)
{
	int err = 0;
	nvpair_t *nvp;
	pool_node_t *pnp = *pnpp;
	boolean_t match = B_FALSE;

	nvp = nvlist_next_nvpair(cfg, NULL);
	while (nvp != NULL) {
		char *name;
		uint64_t guid;
		nvlist_t *nvl;
		data_type_t nvt;

		name = nvpair_name(nvp);
		if ((nvt = nvpair_type(nvp)) != DATA_TYPE_NVLIST) {
			(void) snmp_log(LOG_ERR,
			    "%s:%s: non-nvl cfg pair %s(%d)\n",
			    MODULE_NAME, __func__, name, nvt);
			fnvlist_remove_nvpair(cfg, nvp);
			continue;
		}

		nvl = fnvlist_lookup_nvlist(cfg, name);
		guid = fnvlist_lookup_uint64(nvl, ZPOOL_CONFIG_POOL_GUID);

		if (create) {
			if ((err = init_pool_node(name, guid, pnpp)) != 0)
				break;
			DEBUGMSGTL((MODULE_NAME, "%s: %s(%"PRIu64") created\n",
			    __func__, name, guid));
			fnvlist_remove_nvpair(cfg, nvp);
			match = B_TRUE;
			break;
		} else { /* find */
			/* Match by GUID in case of renames */
			if (pnp->pn_guid == guid) {
				DEBUGMSGTL((MODULE_NAME,
				    "%s: matched %s(%"PRIu64")\n", __func__,
				    name, guid));
				refresh_pool_node(pnp, name, guid);
				fnvlist_remove_nvpair(cfg, nvp);
				match = B_TRUE;
				break;
			}
		}
		nvp = nvlist_next_nvpair(cfg, nvp);
	}

	if (err == 0 && match != B_TRUE)
		err = ESRCH;

	return (err);
}

/*
 * Returns with pool cache locked if successful, as caller will need the lock
 * to make use of the cache.
 */
static int
refresh_pool_cache(void)
{
	int ret;
	nvlist_t *cfg;
	pool_node_t *pnp, *prev;

	(void) rw_wrlock(&ph_lock);

	DEBUGMSGTL((MODULE_NAME, "refreshing pool cache\n"));
	/*
	 * Check whether there's a new config generation. If so, refresh
	 * ourselves with that. We need two copies of the nvlist: one for
	 * caching, and a scratch copy that's pared down by parsing, which
	 * should be empty by the time we're done.
	 */
	ret = lzc_pool_configs(&ph_gen, &cfg);
	switch (ret) {
	case 0:
		nvlist_free(ph_cfg);
		ph_cfg = fnvlist_dup(cfg);
		break;
	case EEXIST:
		nvlist_free(cfg);
		cfg = fnvlist_dup(ph_cfg);
		break;
	default:
		(void) snmp_log(LOG_ERR, "%s: pool config error: %s\n",
		    MODULE_NAME, strerror(ret));
		(void) rw_unlock(&ph_lock);
		return (ret);
	}

	prev = NULL;
	pnp = ph_first;
	/*
	 * Walk the cache, refreshing existing entries that are in the config,
	 * pruning out anything that isn't. Anything in the config nvlist that
	 * isn't matched will be created after this loop.
	 */
	DEBUGMSGTL((MODULE_NAME, "cache matching\n"));
	while (pnp != NULL) {
		if (findcreate_pool_node(cfg, &pnp, B_FALSE) == 0) {
			prev = pnp;
			pnp = pnp->pn_next;
		} else {
			if (prev != NULL)
				prev->pn_next = pnp->pn_next;
			destroy_pool_node(pnp);
			pnp = prev->pn_next;
		}
	}
	if (prev == NULL)
		ph_first = NULL;

	DEBUGMSGTL((MODULE_NAME, "appending new entries\n"));
	while (findcreate_pool_node(cfg, &pnp, B_TRUE) == 0) {
		if (prev != NULL)
			prev->pn_next = pnp;
		else if (ph_first == NULL)
			ph_first = pnp;
		prev = pnp;
	}
	if (prev != NULL)
		prev->pn_next = NULL;

	ph_ts = gethrtime();
	(void) rw_unlock(&ph_lock);
	(void) rw_rdlock(&ph_lock);

	ASSERT(nvlist_empty(cfg));
	nvlist_free(cfg);

	DEBUGMSGTL((MODULE_NAME, "pool cache successfully refreshed\n"));

	return (0);
}

void
zprop_release(void)
{
	if (RW_LOCK_HELD(&ph_lock))
		(void) rw_unlock(&ph_lock);
}

static int
check_cache(void)
{
	hrtime_t now, ts;
	int err = 0;

	(void) rw_rdlock(&ph_lock);
	now = gethrtime();
	ts = ph_ts;
	if ((now - ts) > cache_timeout) {
		(void) rw_unlock(&ph_lock);
		err = refresh_pool_cache();
	}

	return (err);
}

/*
 * We set the initial values for a cache walk, but the work to render the
 * current entry and iterate to the next is done by get_next, hence the
 * recursion.
 */
netsnmp_variable_list *
zprop_pool_get_first_data_point(void **loop_ctx, void **data_ctx,
    netsnmp_variable_list *idx, netsnmp_iterator_info *data)
{
	if (check_cache() != 0) {
		(void) snmp_log(LOG_ERR, "%s:%s: cache check failed\n",
		    MODULE_NAME, __func__);
		return (NULL);
	}
	if (ph_first == NULL) {
		DEBUGMSGTL((MODULE_NAME, "%s: empty cache\n", __func__));
		return (NULL);
	}
	*loop_ctx = (void *)ph_first;

	DEBUGMSGTL((MODULE_NAME, "%s: loop context initialised\n", __func__));

	return (zprop_pool_get_next_data_point(loop_ctx, data_ctx, idx, data));
}

netsnmp_variable_list *
zprop_pool_get_next_data_point(void **loop_ctx, void **data_ctx,
    netsnmp_variable_list *idx, netsnmp_iterator_info *data)
{
	pool_node_t *pnp;
	char *name, *guidstr;
	int err;

	if (loop_ctx == NULL || *loop_ctx == NULL)
		return (NULL);

	pnp = (pool_node_t *)*loop_ctx;
	name = pnp->pn_name, guidstr = pnp->pn_guidstr;
	/* We need to get node props as well as nvlist contents */
	*data_ctx = (void *)pnp;
	/* Terminator does not need to be included in length */
	err = snmp_set_var_value(idx, (uchar_t *)name, strlen(name));
	if (err != 0) {
		(void) snmp_log(LOG_ERR, "%s:%s: %s set index name failed (%d)",
		    MODULE_NAME, __func__, SNMP_STRORNULL(name), err);
	}
	err = snmp_set_var_value(idx->next_variable, (uchar_t *)guidstr,
	    strlen(guidstr));
	if (err != 0) {
		(void) snmp_log(LOG_ERR, "%s:%s: %s set index guid failed (%d)",
		    MODULE_NAME, __func__, SNMP_STRORNULL(guidstr), err);
	}

	DEBUGMSGTL((MODULE_NAME, "loop context name %s/guid %"PRIu64"\n",
	    SNMP_STRORNULL(name), pnp->pn_guid));

	*loop_ctx = (void *)pnp->pn_next;

	return (idx);
}

/* We have to handle both indexed and non-indexed columns */
int
zprop_pool_get(void *ctx, zpool_table_col_t col, uint64_t *val, char **str)
{
	int err;
	uint64_t v;
	char *key;
	boolean_t kbconv = B_FALSE;
	boolean_t dual = B_FALSE;
	boolean_t low = B_FALSE;
	boolean_t def = B_FALSE;
	nvlist_t *nvl, *nestl;
	pool_node_t *pnp = (pool_node_t *)ctx;

	nvl = pnp->pn_props;

	switch (col) {
	case ZPOOL_TC_GUID:
		*str = pnp->pn_guidstr;
		return (0);
	case ZPOOL_TC_NAME:
		*str = pnp->pn_name;
		return (0);
	case ZPOOL_TC_HEALTH:
		key = "health";
		break;
	case ZPOOL_TC_FAILMODE:
		key = "failmode";
		v = ZIO_FAILURE_MODE_WAIT;
		def = B_TRUE;
		break;
	case ZPOOL_TC_CAPACITY:
		key = "capacity";
		break;
	case ZPOOL_TC_SIZE_HIGH:
	case ZPOOL_TC_SIZE_LOW:
		key = "size";
		kbconv = B_TRUE;
		dual = B_TRUE;
		if (col == ZPOOL_TC_SIZE_LOW)
			low = B_TRUE;
		break;
	case ZPOOL_TC_ALLOC_HIGH:
	case ZPOOL_TC_ALLOC_LOW:
		key = "allocated";
		kbconv = B_TRUE;
		dual = B_TRUE;
		if (col == ZPOOL_TC_ALLOC_LOW)
			low = B_TRUE;
		break;
	case ZPOOL_TC_FREE_HIGH:
	case ZPOOL_TC_FREE_LOW:
		key = "free";
		kbconv = B_TRUE;
		dual = B_TRUE;
		if (col == ZPOOL_TC_FREE_LOW)
			low = B_TRUE;
		break;
	case ZPOOL_TC_FREEING_HIGH:
	case ZPOOL_TC_FREEING_LOW:
		key = "freeing";
		kbconv = B_TRUE;
		dual = B_TRUE;
		if (col == ZPOOL_TC_FREEING_LOW)
			low = B_TRUE;
		break;
	case ZPOOL_TC_EXPANDSIZE_HIGH:
	case ZPOOL_TC_EXPANDSIZE_LOW:
		key = "expandsize";
		kbconv = B_TRUE;
		dual = B_TRUE;
		if (col == ZPOOL_TC_EXPANDSIZE_LOW)
			low = B_TRUE;
		break;
	case ZPOOL_TC_DEDUPRATIO:
		key = "dedupratio";
		break;
	case ZPOOL_TC_AUTOEXPAND:
		key = "autoexpand";
		/* This is another value with a default. See failmode above */
		v = 0;
		def = B_TRUE;
		break;
	default:
		(void) snmp_log(LOG_ERR, "%s: unknown column %d\n",
		    MODULE_NAME, col);
		return (EINVAL);
	}

	if (nvl == NULL) {
		(void) snmp_log(LOG_ERR, "%s:%s: NULL props nvlist\n",
		    MODULE_NAME, __func__);
		return (EINVAL);
	}

	if ((err = nvlist_lookup_nvlist(nvl, key, &nestl)) == 0) {
		v = fnvlist_lookup_uint64(nestl, "value");
	} else if (!(err == ENOENT && def == B_TRUE)) {
		(void) snmp_log(LOG_ERR, "%s:%s: error retrieving %s: %s\n",
		    MODULE_NAME, __func__, key, strerror(err));
		return (err);
	}

	if (kbconv)
		v = v / 1024;
	if (dual) {
		if (low) {
			v = v & 0xffffffff;
		} else {
			v = v >> 32;
		}
	}
	*val = v;

	DEBUGMSGTL((MODULE_NAME,
	    "%s: value %"PRIu64" for col %d for %s(%"PRIu64")\n", __func__,
	    *val, col, pnp->pn_name, pnp->pn_guid));

	return (0);
}

/*
 * We use VERIFY here for the following reasons: 1) if we fail, it's probably
 * because of a memory allocation failure, so we fall back on SMF restarts to
 * recycle us through a shortfall in the hope that we will come up cleanly. 2)
 * if we consistently fail to allocate, we'd be stuck with silent gaps in
 * monitoring that are by definition invisible to an NMS, whereas SMF can
 * notify on failure via an ireport FMA trap (which should be enabled by
 * default) and prompt administrative intervention.
 */
void
zprop_init(void)
{
	DEBUGMSGTL((MODULE_NAME, "initialising zprop\n"));

	VERIFY0(libzfs_core_init());
	VERIFY0(refresh_pool_cache());
}

void
zprop_fini(void)
{
	pool_node_t	*pnp;

	DEBUGMSGTL((MODULE_NAME, "finalizing zprop\n"));

	while ((pnp = ph_first) != NULL) {
		ph_first = pnp->pn_next;
		destroy_pool_node(pnp);
	}
	libzfs_core_fini();
}
