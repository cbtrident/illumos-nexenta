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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <errno.h>
#include <inttypes.h>
#include <kstat.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <thread.h>

#include "arc_access.h"
#include "zfs_snmp.h"

static kstat_ctl_t *as_kc;
static kstat_t *as_ks;
static rwlock_t	as_lock = DEFAULTRWLOCK;
static hrtime_t as_ts;

/* Cache timeout in seconds converted to ns */
static hrtime_t cache_timeout = (ZPOOL_CACHE_TIMEOUT * 1E9);

/*
 * If cache is expired or not yet populated, readers will race to update the
 * cache via this function. If we find that the timestamp has increased since
 * the caller copied it out for comparison, an update already happened.
 */
static void
arcstat_update(hrtime_t *ts)
{
	(void) rw_wrlock(&as_lock);
	if (as_ts > *ts) {
		(void) rw_unlock(&as_lock);
		return;
	}
	/* This shouldn't happen */
	if (kstat_read(as_kc, as_ks, NULL) == -1) {
		(void) snmp_log(LOG_ERR, "%s: %s: kstat_read failed: %s\n",
		    MODULE_NAME, __func__, strerror(errno));
		goto invalid;
	}
	as_ts = gethrtime();
invalid:
	(void) rw_unlock(&as_lock);

	DEBUGMSGTL((MODULE_NAME, "arcstat updated\n"));
}

static void
arcstat_check(void)
{
	hrtime_t now;

	(void) rw_rdlock(&as_lock);
	now = gethrtime();
	if ((now - as_ts) > cache_timeout) {
		(void) rw_unlock(&as_lock);
		arcstat_update(&as_ts);
	}
	(void) rw_rdlock(&as_lock);
}

void
arcstat_release()
{
	if (RW_LOCK_HELD(&as_lock))
		(void) rw_unlock(&as_lock);
}

/*
 * Part of the table_iterator helper pattern (see netsnmp_table_iterator),
 * returns the first data point within the arcstat table data and establishes
 * context for subsequent operations against the table in terms of the data we
 * need to render (arcstat) and its indexes (the kstat instance ID). The API
 * gives us access to my_data_context via netsnmp_extract_iterator_context().
 * We don't really need this context information in this case, we only need to
 * set index values, as we only allow for a single conceptual row, but we set
 * things up here as though we allow for and need context, leaving the laming
 * for the get_next function.
 */
netsnmp_variable_list *
arcstat_get_first_data_point(void **my_loop_context, void **my_data_context,
    netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	netsnmp_variable_list *vptr;

	arcstat_check();

	*my_loop_context = &as_ks;
	*my_data_context = &as_ks;

	vptr = put_index_data;
	(void) snmp_set_var_value(vptr, (uchar_t *)&as_ks->ks_instance,
	    sizeof (as_ks->ks_instance));
	return (put_index_data);
}

/*
 * There never is a next data point, since instance 0 is the only one for us.
 */
netsnmp_variable_list *
arcstat_get_next_data_point(void **my_loop_context, void **my_data_context,
    netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
	return (NULL);
}

/*
 * Internal helper function to retrieve arcstat kstat values. The arcstats
 * kstat is a kstat with a series of named kstats. We take column identifiers
 * and convert those to the names to read out. All the values within the ARC
 * stats proper are uint64s, but we also have to handle the timestamp values
 * for crtime and snaptime. Where possible, normalise sizes from bytes to KB.
 * We have to deal directly with special-casing for L2ARC space representation,
 * as even with KB conversion, we have to user higher and lower order bits to
 * pass a non-counter value that can't be represented with 32 bits.
 */
int
arcstat_read(arc_table_col_t col, uint64_t *val, hrtime_t *ts)
{
	kstat_named_t	*knp;
	char		*name;
	boolean_t	kbconv = B_FALSE;
	boolean_t	dual = B_FALSE;
	boolean_t	low = B_FALSE;
	uint64_t	v;

	DEBUGMSGTL((MODULE_NAME, "arcstat column %d\n", col));

	switch (col) {
	case ARC_TC_INST:
		v = as_ks->ks_instance;
		*val = v;
		return (0);
	case ARC_TC_META_USED:
		kbconv = B_TRUE;
		name = "arc_meta_used";
		break;
	case ARC_TC_C:
		kbconv = B_TRUE;
		name = "c";
		break;
	case ARC_TC_P:
		kbconv = B_TRUE;
		name = "p";
		break;
	case ARC_TC_SIZE:
		kbconv = B_TRUE;
		name = "size";
		break;
	case ARC_TC_L2_SIZE_LOW:
	case ARC_TC_L2_SIZE_HIGH:
		dual = B_TRUE;
		kbconv = B_TRUE;
		name = "l2_size";
		if (col == ARC_TC_L2_SIZE_LOW)
			low = B_TRUE;
		break;
	case ARC_TC_HITS:
		name = "hits";
		break;
	case ARC_TC_MISSES:
		name = "misses";
		break;
	case ARC_TC_DEMAND_DATA_HITS:
		name = "demand_data_hits";
		break;
	case ARC_TC_DEMAND_DATA_MISSES:
		name = "demand_data_misses";
		break;
	case ARC_TC_DEMAND_METADATA_HITS:
		name = "demand_metadata_hits";
		break;
	case ARC_TC_DEMAND_METADATA_MISSES:
		name = "demand_metadata_misses";
		break;
	case ARC_TC_PREFETCH_DATA_HITS:
		name = "prefetch_data_hits";
		break;
	case ARC_TC_PREFETCH_DATA_MISSES:
		name = "prefetch_data_misses";
		break;
	case ARC_TC_PREFETCH_METADATA_HITS:
		name = "prefetch_metadata_hits";
		break;
	case ARC_TC_PREFETCH_METADATA_MISSES:
		name = "prefetch_metadata_misses";
		break;
	case ARC_TC_MFU_GHOST_HITS:
		name = "mfu_ghost_hits";
		break;
	case ARC_TC_MFU_HITS:
		name = "mfu_hits";
		break;
	case ARC_TC_MRU_GHOST_HITS:
		name = "mru_ghost_hits";
		break;
	case ARC_TC_MRU_HITS:
		name = "mru_hits";
		break;
	case ARC_TC_L2_HITS:
		name = "l2_hits";
		break;
	case ARC_TC_L2_MISSES:
		name = "l2_misses";
		break;
	case ARC_TC_CRTIME:
		*ts = as_ks->ks_crtime;
		return (0);
	case ARC_TC_SNAPTIME:
		*ts = as_ks->ks_snaptime;
		return (0);
	default:
		(void) snmp_log(LOG_ERR, "%s: %s: invalid column %d\n",
		    MODULE_NAME, __func__, col);
		return (EINVAL);
	}

	if ((knp = kstat_data_lookup(as_ks, (char *)name)) == NULL) {
		(void) snmp_log(LOG_ERR, "%s: %s: arcstat %s lookup error: %s",
		    MODULE_NAME, __func__, name, strerror(errno));
		return (errno);
	}
	/* All values should be uint64, so this shouldn't happen at runtime */
	ASSERT3U(knp->data_type, ==, KSTAT_DATA_UINT64);

	v = (kbconv) ? knp->value.ui64 / 1024 : knp->value.ui64;
	if (dual) {
		if (low) {
			v = v & 0xffffffff;
		} else {
			v = v >> 32;
		}
	}
	*val = v;

	DEBUGMSGTL((MODULE_NAME, "%s: value %"PRIu64" for column %d\n",
	    __func__, *val, col));

	return (0);
}

void
arcstat_init(void)
{
	DEBUGMSGTL((MODULE_NAME, "initializing arcstat\n"));

	as_kc = kstat_open();
	VERIFY3P(as_kc, !=, NULL);
	as_ks = kstat_lookup(as_kc, "zfs", 0, "arcstats");
	VERIFY3P(as_ks, !=, NULL);
}

void
arcstat_fini(void)
{
	DEBUGMSGTL((MODULE_NAME, "finalizing arcstat\n"));

	(void) kstat_close(as_kc);
	as_kc = NULL;
	as_ks = NULL;
	as_ts = 0;
}
