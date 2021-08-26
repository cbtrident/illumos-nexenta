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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/debug.h>

#include <fm/fmd_adm.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <errno.h>
#include <libuutil.h>
#include <pthread.h>
#include <stddef.h>

#include "fm_snmp.h"
#include "resource.h"

static uu_avl_pool_t	*rsrc_fmri_avl_pool;
static uu_avl_pool_t	*rsrc_index_avl_pool;
static uu_avl_t		*rsrc_fmri_avl;
static uu_avl_t		*rsrc_index_avl;

#define	VALID_AVL_STATE	(rsrc_fmri_avl_pool != NULL &&		\
	rsrc_index_avl_pool != NULL && rsrc_fmri_avl != NULL &&	\
	rsrc_index_avl != NULL)

/*
 * Update types: single-index and all are mutually exclusive; a count
 * update is optional.
 */
#define	UCT_INDEX	0x1
#define	UCT_ALL		0x2
#define	UCT_COUNT	0x4
#define	UCT_FLAGS	0x7

#define	RESOURCE_DATA_VALID(d)	((d)->d_valid == valid_stamp)

static ulong_t		max_index;
static int		valid_stamp;
static uint32_t		rsrc_count;
static pthread_mutex_t	update_lock = PTHREAD_MUTEX_INITIALIZER;

static oid sunFmResourceTable_oid[] = { SUNFMRESOURCETABLE_OID };
static oid sunFmResourceCount_oid[] = { SUNFMRESOURCECOUNT_OID, 0 };

static netsnmp_table_registration_info *rsrc_tinfo;
static netsnmp_handler_registration *rsrc_handler;
static netsnmp_handler_registration *cnt_handler;

static sunFmResource_data_t *
key_build(const char *fmri, const ulong_t index)
{
	static sunFmResource_data_t	key;

	key.d_index = index;
	if (fmri)
		(void) strlcpy(key.d_ari_fmri, fmri, sizeof (key.d_ari_fmri));
	else
		key.d_ari_fmri[0] = '\0';

	return (&key);
}

/*
 * If fmri is the fmri of a resource we have previously seen and indexed, return
 * data for it.  Otherwise, return NULL.  Note that the resource may not be
 * valid; that is, it may have been removed from the fault manager since its
 * information was last updated.
 */
static sunFmResource_data_t *
resource_lookup_fmri(const char *fmri)
{
	sunFmResource_data_t	*key;

	key = key_build(fmri, 0);
	return (uu_avl_find(rsrc_fmri_avl, key, NULL, NULL));
}

/*
 * If index corresponds to a resource we have previously seen and indexed,
 * return data for it.  Otherwise, return NULL.  Note that the resource may
 * not be valid; that is, it may have been expired from the fault manager
 * since its information was last updated.
 */
static sunFmResource_data_t *
resource_lookup_index_exact(const ulong_t index)
{
	sunFmResource_data_t	*key;

	key = key_build(NULL, index);
	return (uu_avl_find(rsrc_index_avl, key, NULL, NULL));
}

/*
 * If index corresponds to a valid (that is, extant as of latest information
 * from the fault manager) resource, return the data for that resource.
 * Otherwise, return the data for the valid resource whose index is as close as
 * possible to index but not lower.  This preserves the lexicographical
 * ordering required for GETNEXT processing.
 */
static sunFmResource_data_t *
resource_lookup_index_nextvalid(const ulong_t index)
{
	sunFmResource_data_t	*key, *data;
	uu_avl_index_t		idx;

	key = key_build(NULL, index);

	if ((data = uu_avl_find(rsrc_index_avl, key, NULL, &idx)) != NULL &&
	    RESOURCE_DATA_VALID(data))
		return (data);

	data = uu_avl_nearest_next(rsrc_index_avl, idx);

	while (data != NULL && !RESOURCE_DATA_VALID(data))
		data = uu_avl_next(rsrc_index_avl, data);

	return (data);
}

/*
 * Possible update the contents of a single resource within the cache.  This
 * is our callback from fmd_rsrc_iter.
 */
static int
rsrcinfo_update_one(const fmd_adm_rsrcinfo_t *rsrcinfo, void *arg)
{
	const sunFmResource_update_ctx_t *update_ctx =
	    (sunFmResource_update_ctx_t *)arg;
	sunFmResource_data_t *data = resource_lookup_fmri(rsrcinfo->ari_fmri);

	++rsrc_count;

	/*
	 * A resource we haven't seen before.  We're obligated to index
	 * it and link it into our cache so that we can find it, but we're
	 * not obligated to fill it in completely unless we're doing a
	 * full update or this is the resource we were asked for.  This
	 * avoids unnecessary iteration and memory manipulation for data
	 * we're not going to return for this request.
	 */
	if (data == NULL) {
		uu_avl_index_t idx;

		DEBUGMSGTL((MODNAME_STR, "found new resource %s\n",
		    rsrcinfo->ari_fmri));
		if ((data = SNMP_MALLOC_TYPEDEF(sunFmResource_data_t)) ==
		    NULL) {
			(void) snmp_log(LOG_ERR, MODNAME_STR ": Out of memory "
			    "for new resource data at %s:%d\n", __FILE__,
			    __LINE__);
			return (1);
		}
		/*
		 * We allocate indices sequentially and never reuse them.
		 * This ensures we can always return valid GETNEXT responses
		 * without having to reindex, and it provides the user a
		 * more consistent view of the fault manager.
		 */
		data->d_index = ++max_index;
		DEBUGMSGTL((MODNAME_STR, "index %lu is %s@%p\n", data->d_index,
		    rsrcinfo->ari_fmri, data));

		(void) strlcpy(data->d_ari_fmri, rsrcinfo->ari_fmri,
		    sizeof (data->d_ari_fmri));

		uu_avl_node_init(data, &data->d_fmri_avl, rsrc_fmri_avl_pool);
		(void) uu_avl_find(rsrc_fmri_avl, data, NULL, &idx);
		uu_avl_insert(rsrc_fmri_avl, data, idx);

		uu_avl_node_init(data, &data->d_index_avl, rsrc_index_avl_pool);
		(void) uu_avl_find(rsrc_index_avl, data, NULL, &idx);
		uu_avl_insert(rsrc_index_avl, data, idx);

		DEBUGMSGTL((MODNAME_STR, "completed new resource %lu/%s@%p\n",
		    data->d_index, data->d_ari_fmri, data));
	}

	data->d_valid = valid_stamp;

	DEBUGMSGTL((MODNAME_STR, "timestamp updated for %lu/%s@%p: %d\n",
	    data->d_index, data->d_ari_fmri, data, data->d_valid));

	if ((update_ctx->uc_type & UCT_ALL) ||
	    update_ctx->uc_index == data->d_index) {
		(void) strlcpy(data->d_ari_case, rsrcinfo->ari_case,
		    sizeof (data->d_ari_case));
		data->d_ari_flags = rsrcinfo->ari_flags;
	}

	return (!(update_ctx->uc_type & UCT_ALL) &&
	    update_ctx->uc_index == data->d_index);
}

/*
 * Update some or all resource data from fmd.  If type includes UCT_ALL, all
 * resources will be indexed and their data cached.  If type includes
 * UCT_INDEX, updates will stop once the resource matching index has been
 * updated.  If UCT_COUNT is set, the number of faulted resources will be
 * set.
 *
 * Returns appropriate SNMP error codes.
 */
static int
rsrcinfo_update(sunFmResource_update_ctx_t *update_ctx)
{
	fmd_adm_t *adm;
	int err;

	ASSERT(update_ctx != NULL);
	ASSERT((update_ctx->uc_type & (UCT_ALL|UCT_INDEX)) !=
	    (UCT_ALL|UCT_INDEX));
	ASSERT((update_ctx->uc_type & ~UCT_FLAGS) == 0);
	ASSERT(VALID_AVL_STATE);

	if ((adm = fmd_adm_open(update_ctx->uc_host, update_ctx->uc_prog,
	    update_ctx->uc_version)) == NULL) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": Communication with fmd "
		    "failed: %s\n", strerror(errno));
		return (SNMP_ERR_RESOURCEUNAVAILABLE);
	}

	if (update_ctx->uc_type == UCT_COUNT) {
		err = fmd_adm_rsrc_count(adm, update_ctx->uc_all, &rsrc_count);
	} else {
		++valid_stamp;
		rsrc_count = 0;
		err = fmd_adm_rsrc_iter(adm, update_ctx->uc_all,
		    rsrcinfo_update_one, update_ctx);
		DEBUGMSGTL((MODNAME_STR, "resource iteration completed\n"));
	}

	fmd_adm_close(adm);

	if (err != 0) {
		(void) snmp_log(LOG_ERR, MODNAME_STR ": fmd resource "
		    "information update failed: %s\n", fmd_adm_errmsg(adm));
		return (SNMP_ERR_RESOURCEUNAVAILABLE);
	}

	return (SNMP_ERR_NOERROR);
}

static void
request_update(void)
{
	sunFmResource_update_ctx_t	uc;

	/*
	 * The current rsrcinfo_update implementation offers minimal savings
	 * for the use of index-only updates; therefore we always do a full
	 * update.  If it becomes advantageous to limit updates to a single
	 * index, the contexts can be queued by the handler instead.
	 */

	uc.uc_host = NULL;
	uc.uc_prog = FMD_ADM_PROGRAM;
	uc.uc_version = FMD_ADM_VERSION;

	uc.uc_all = 0;
	uc.uc_index = 0;
	uc.uc_type = UCT_ALL;

	(void) rsrcinfo_update(&uc);
}

static int
resource_compare_fmri(const void *l, const void *r, void *private)
{
	sunFmResource_data_t	*l_data = (sunFmResource_data_t *)l;
	sunFmResource_data_t	*r_data = (sunFmResource_data_t *)r;

	ASSERT(l_data != NULL && r_data != NULL);

	return (strcmp(l_data->d_ari_fmri, r_data->d_ari_fmri));
}

static int
resource_compare_index(const void *l, const void *r, void *private)
{
	sunFmResource_data_t	*l_data = (sunFmResource_data_t *)l;
	sunFmResource_data_t	*r_data = (sunFmResource_data_t *)r;

	ASSERT(l_data != NULL && r_data != NULL);

	return (l_data->d_index < r_data->d_index ? -1 :
	    l_data->d_index > r_data->d_index ? 1 : 0);
}

/*
 * These two functions form the core of GET/GETNEXT handling (the
 * only kind we do).  They perform two functions:
 *
 * - First, frob the request to set all the index variables to correspond
 *   to the value that's going to be returned.  For GET, this is a nop;
 *   for GETNEXT it always requires some work.
 * - Second, find and return the fmd resource information corresponding to
 *   the (possibly updated) indices.
 *
 * These should be as fast as possible; they run in the agent thread.
 */
static sunFmResource_data_t *
sunFmResourceTable_nextrsrc(netsnmp_handler_registration *reginfo,
    netsnmp_table_request_info *table_info)
{
	sunFmResource_data_t	*data;
	netsnmp_variable_list	*var;
	ulong_t index;

	/*
	 * If we have no index, we must make one.
	 */
	if (table_info->number_indexes < 1) {
		oid tmpoid[MAX_OID_LEN];
		index = 1;

		DEBUGMSGTL((MODNAME_STR, "nextrsrc: no indexes given\n"));
		var = SNMP_MALLOC_TYPEDEF(netsnmp_variable_list);
		(void) snmp_set_var_typed_value(var, ASN_UNSIGNED,
		    (uchar_t *)&index, sizeof (index));
		(void) memcpy(tmpoid, reginfo->rootoid,
		    reginfo->rootoid_len * sizeof (oid));
		tmpoid[reginfo->rootoid_len] = 1;
		tmpoid[reginfo->rootoid_len + 1] = table_info->colnum;
		if (build_oid(&var->name, &var->name_length, tmpoid,
		    reginfo->rootoid_len + 2, var) != SNMPERR_SUCCESS) {
			snmp_free_varbind(var);
			return (NULL);
		}
		DEBUGMSGTL((MODNAME_STR, "nextrsrc: built fake index:\n"));
		DEBUGMSGVAR((MODNAME_STR, var));
		DEBUGMSG((MODNAME_STR, "\n"));
	} else {
		var = snmp_clone_varbind(table_info->indexes);
		index = *var->val.integer;
		DEBUGMSGTL((MODNAME_STR, "nextrsrc: received index:\n"));
		DEBUGMSGVAR((MODNAME_STR, var));
		DEBUGMSG((MODNAME_STR, "\n"));
		index++;
	}

	snmp_free_varbind(table_info->indexes);
	table_info->indexes = NULL;
	table_info->number_indexes = 0;

	if ((data = resource_lookup_index_nextvalid(index)) == NULL) {
		DEBUGMSGTL((MODNAME_STR, "nextrsrc: exact match not found for "
		    "index %lu; trying next column\n", index));
		if (table_info->colnum >=
		    netsnmp_find_table_registration_info(reginfo)->max_column) {
			snmp_free_varbind(var);
			DEBUGMSGTL((MODNAME_STR, "nextrsrc: out of columns\n"));
			return (NULL);
		}
		table_info->colnum++;
		index = 1;

		data = resource_lookup_index_nextvalid(index);
	}

	if (data == NULL) {
		DEBUGMSGTL((MODNAME_STR, "nextrsrc: exact match not found for "
		    "index %lu; stopping\n", index));
		snmp_free_varbind(var);
		return (NULL);
	}

	*var->val.integer = data->d_index;
	table_info->indexes = var;
	table_info->number_indexes = 1;

	DEBUGMSGTL((MODNAME_STR, "matching data is %lu/%s@%p\n", data->d_index,
	    data->d_ari_fmri, data));

	return (data);
}

static sunFmResource_data_t *
sunFmResourceTable_rsrc(netsnmp_handler_registration *reginfo,
    netsnmp_table_request_info *table_info)
{
	ASSERT(table_info->number_indexes == 1);

	return (resource_lookup_index_exact(table_info->index_oid[0]));
}

static int
sunFmResourceTable_handler(netsnmp_mib_handler *handler,
    netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo,
    netsnmp_request_info *request)
{
	netsnmp_table_request_info	*table_info;
	sunFmResource_data_t		*data;
	ulong_t				rsrcstate;
	int				ret = SNMP_ERR_NOERROR;

	/*
	 * We don't support MODE_GETBULK directly, so all bulk requests should
	 * come through bulk_to_next helper.  Make sure it stays that way.
	 */
	ASSERT(reqinfo->mode == MODE_GET || reqinfo->mode == MODE_GETNEXT);

	(void) pthread_mutex_lock(&update_lock);
	request_update();

	for (; request != NULL; request = request->next) {
		table_info = netsnmp_extract_table_info(request);
		if (table_info == NULL)
			continue;

		ASSERT(table_info->colnum >= SUNFMRESOURCE_COLMIN);
		ASSERT(table_info->colnum <= SUNFMRESOURCE_COLMAX);

		/*
		 * table_info->colnum contains the column number requested.
		 * table_info->indexes contains a linked list of snmp variable
		 * bindings for the indexes of the table.  Values in the list
		 * have been set corresponding to the indexes of the
		 * request.  We have other guarantees as well:
		 *
		 * - The column number is always within range.
		 * - If we have no index data, table_info->index_oid_len is 0.
		 * - We will never receive requests outside our table nor
		 *   those with the first subid anything other than 1 (Entry)
		 *   nor those without a column number.  This is true even
		 *   for GETNEXT requests.
		 */
		switch (reqinfo->mode) {
		case MODE_GET:
			data = sunFmResourceTable_rsrc(reginfo, table_info);
			if (data == NULL)
				goto out;
			break;
		case MODE_GETNEXT:
			data = sunFmResourceTable_nextrsrc(reginfo, table_info);
			if (data == NULL)
				goto out;
			break;
		default:
			(void) snmp_log(LOG_ERR, MODNAME_STR
			    ": unsupported request mode %d\n", reqinfo->mode);
			ret = SNMP_ERR_GENERR;
			goto out;
		}

		switch (table_info->colnum) {
		case SUNFMRESOURCE_COL_FMRI:
			(void) netsnmp_table_build_result(reginfo, request,
			    table_info, ASN_OCTET_STR,
			    (uchar_t *)data->d_ari_fmri,
			    strlen(data->d_ari_fmri));
			break;
		case SUNFMRESOURCE_COL_STATUS:
			switch (data->d_ari_flags &
			    (FMD_ADM_RSRC_FAULTY|FMD_ADM_RSRC_UNUSABLE)) {
			default:
				rsrcstate = SUNFMRESOURCE_STATE_OK;
				break;
			case FMD_ADM_RSRC_FAULTY:
				rsrcstate = SUNFMRESOURCE_STATE_DEGRADED;
				break;
			case FMD_ADM_RSRC_UNUSABLE:
				rsrcstate = SUNFMRESOURCE_STATE_UNKNOWN;
				break;
			case FMD_ADM_RSRC_FAULTY | FMD_ADM_RSRC_UNUSABLE:
				rsrcstate = SUNFMRESOURCE_STATE_FAULTED;
				break;
			}
			(void) netsnmp_table_build_result(reginfo, request,
			    table_info, ASN_INTEGER, (uchar_t *)&rsrcstate,
			    sizeof (rsrcstate));
			break;
		case SUNFMRESOURCE_COL_DIAGNOSISUUID:
			(void) netsnmp_table_build_result(reginfo, request,
			    table_info, ASN_OCTET_STR,
			    (uchar_t *)data->d_ari_case,
			    strlen(data->d_ari_case));
			break;
		default:
			break;
		}
	}

out:
	(void) pthread_mutex_unlock(&update_lock);
	return (ret);
}

static int
sunFmResourceCount_handler(netsnmp_mib_handler *handler,
    netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo,
    netsnmp_request_info *request)
{
	ulong_t				rsrc_count_long;
	int				ret = SNMP_ERR_NOERROR;

	/*
	 * We don't support MODE_GETBULK directly, so all bulk requests should
	 * come through bulk_to_next helper.  Make sure it stays that way.
	 */
	ASSERT(reqinfo->mode == MODE_GET || reqinfo->mode == MODE_GETNEXT);

	(void) pthread_mutex_lock(&update_lock);
	request_update();

	for (; request != NULL; request = request->next) {
		switch (reqinfo->mode) {
		/*
		 * According to the documentation, it's not possible for us ever
		 * to be called with MODE_GETNEXT.  However, Net-SNMP does the
		 * following:
		 * - set reqinfo->mode to MODE_GET
		 * - invoke the handler
		 * - set reqinfo->mode to MODE_GETNEXT (even if the request was
		 *   not actually processed; i.e. it's been delegated)
		 * Since we're called back later with the same reqinfo, we see
		 * GETNEXT.  Therefore this case is needed to work around the
		 * Net-SNMP bug.
		 */
		case MODE_GET:
		case MODE_GETNEXT:
			DEBUGMSGTL((MODNAME_STR, "resource count is %u\n",
			    rsrc_count));
			rsrc_count_long = (ulong_t)rsrc_count;
			(void) snmp_set_var_typed_value(request->requestvb,
			    ASN_GAUGE, (uchar_t *)&rsrc_count_long,
			    sizeof (rsrc_count_long));
			break;
		default:
			(void) snmp_log(LOG_ERR, MODNAME_STR
			    ": unsupported request mode: %d\n", reqinfo->mode);
			ret = SNMP_ERR_GENERR;
		}
	}

	(void) pthread_mutex_unlock(&update_lock);
	return (ret);
}

void
sunFmResourceTable_init(void)
{
	DEBUGMSGTL((MODNAME_STR, "initializing resource\n"));

	rsrc_tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
	VERIFY3P(rsrc_tinfo, !=, NULL);
	rsrc_handler = netsnmp_create_handler_registration("sunFmResourceTable",
	    sunFmResourceTable_handler, sunFmResourceTable_oid,
	    OID_LENGTH(sunFmResourceTable_oid), HANDLER_CAN_RONLY);
	VERIFY3P(rsrc_handler, !=, NULL);
	cnt_handler = netsnmp_create_handler_registration("sunFmResourceCount",
	    sunFmResourceCount_handler, sunFmResourceCount_oid,
	    OID_LENGTH(sunFmResourceCount_oid), HANDLER_CAN_RONLY);
	VERIFY3P(cnt_handler, !=, NULL);

	netsnmp_table_helper_add_indexes(rsrc_tinfo, ASN_UNSIGNED, 0);

	rsrc_tinfo->min_column = SUNFMRESOURCE_COLMIN;
	rsrc_tinfo->max_column = SUNFMRESOURCE_COLMAX;

	rsrc_fmri_avl_pool = uu_avl_pool_create("rsrc_fmri",
	    sizeof (sunFmResource_data_t),
	    offsetof(sunFmResource_data_t, d_fmri_avl), resource_compare_fmri,
	    UU_AVL_DEBUG);
	VERIFY3P(rsrc_fmri_avl_pool, !=, NULL);

	rsrc_fmri_avl = uu_avl_create(rsrc_fmri_avl_pool, NULL, UU_AVL_DEBUG);
	VERIFY3P(rsrc_fmri_avl, !=, NULL);

	rsrc_index_avl_pool = uu_avl_pool_create("rsrc_index",
	    sizeof (sunFmResource_data_t),
	    offsetof(sunFmResource_data_t, d_index_avl), resource_compare_index,
	    UU_AVL_DEBUG);
	VERIFY3P(rsrc_index_avl_pool, !=, NULL);

	rsrc_index_avl = uu_avl_create(rsrc_index_avl_pool, NULL, UU_AVL_DEBUG);
	VERIFY3P(rsrc_index_avl, !=, NULL);

	VERIFY3U(netsnmp_register_table(rsrc_handler, rsrc_tinfo), ==,
	    MIB_REGISTERED_OK);

	VERIFY3U(netsnmp_register_read_only_instance(cnt_handler), ==,
	    MIB_REGISTERED_OK);
}

void
sunFmResourceTable_fini(void)
{
	uu_avl_walk_t *walk;
	sunFmResource_data_t *node;

	DEBUGMSGTL((MODNAME_STR, "finalizing resource\n"));

	VERIFY3U(unregister_mib(sunFmResourceTable_oid,
	    OID_LENGTH(sunFmResourceTable_oid)), ==, MIB_UNREGISTERED_OK);
	netsnmp_handler_registration_free(rsrc_handler);
	snmp_free_varbind(rsrc_tinfo->indexes);
	SNMP_FREE(rsrc_tinfo);

	VERIFY3U(unregister_mib(sunFmResourceCount_oid,
	    OID_LENGTH(sunFmResourceCount_oid)), ==, MIB_UNREGISTERED_OK);
	netsnmp_handler_registration_free(cnt_handler);

	walk = uu_avl_walk_start(rsrc_fmri_avl, UU_WALK_ROBUST);
	VERIFY3P(walk, !=, NULL);
	while ((node = uu_avl_walk_next(walk)) != NULL) {
		uu_avl_remove(rsrc_fmri_avl, node);
		uu_avl_remove(rsrc_index_avl, node);
		SNMP_FREE(node);
	}
	uu_avl_walk_end(walk);
	uu_avl_destroy(rsrc_fmri_avl);
	uu_avl_pool_destroy(rsrc_fmri_avl_pool);
	uu_avl_destroy(rsrc_index_avl);
	uu_avl_pool_destroy(rsrc_index_avl_pool);
}
