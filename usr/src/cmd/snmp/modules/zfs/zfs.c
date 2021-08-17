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

#include "arc_access.h"
#include "zfs_snmp.h"
#include "zprop_access.h"

static oid arcTable_oid[] = { ARCTABLE_OID };
static oid zpoolTable_oid[] = { ZPOOLTABLE_OID };

static netsnmp_table_registration_info *arc_tinfo;
static netsnmp_table_registration_info *zpool_tinfo;
static netsnmp_handler_registration *arc_handler;
static netsnmp_handler_registration *zpool_handler;
static netsnmp_iterator_info *arc_iinfo;
static netsnmp_iterator_info *zpool_iinfo;

/*
 * This table handler is a bit different than others, as we have a number of
 * related records that we've chosen to represent as table with a single
 * conceptual record. Thus we have a reduced reliance on context and only need
 * to keep track of where we are in terms of columns.
 */
static int
arcTable_handler(netsnmp_mib_handler *handler,
    netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo,
    netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *tinfo;
	netsnmp_variable_list *var;
	hrtime_t ts;
	int i = 0;
	uint64_t val;
	void *ctx = NULL;

	for (request = requests; request; request = request->next) {
		var = request->requestvb;
		if (request->processed != 0)
			continue;
		if (reqinfo->mode != MODE_GET) {
			(void) snmp_log(LOG_ERR,
			    "%s: %s handler: unsupported mode\n",
			    MODULE_NAME, ARCTABLE_NAME);
			continue;
		}

		DEBUGMSGTL((MODULE_NAME, "%s request item no %d\n",
		    ARCTABLE_NAME, ++i));

		ctx = netsnmp_extract_iterator_context(request);
		if (ctx == NULL) {
			(void) netsnmp_set_request_error(reqinfo, request,
			    SNMP_NOSUCHINSTANCE);
			continue;
		}

		tinfo = netsnmp_extract_table_info(request);
		if (tinfo == NULL)
			continue;

		DEBUGMSGTL((MODULE_NAME, "%s: column %d\n",
		    ARCTABLE_NAME, tinfo->colnum));
		/*
		 * We handle the index, although that should be taken care of
		 * in the get_first/get_next context handlers.
		 */
		if (tinfo->colnum < ARC_TC_MIN_COL ||
		    tinfo->colnum > ARC_TC_MAX_COL) {
			(void) snmp_log(LOG_ERR,
			    "%s: %s handler: unknown column %d\n", MODULE_NAME,
			    ARCTABLE_NAME, tinfo->colnum);
			(void) netsnmp_set_request_error(reqinfo, request,
			    SNMP_ERR_GENERR);
			continue;
		}

		if (arcstat_read(tinfo->colnum, &val, &ts) != 0) {
			(void) snmp_log(LOG_ERR,
			    "%s: failed to retrieve values for table %s\n",
			    MODULE_NAME, ARCTABLE_NAME);
			(void) netsnmp_set_request_error(reqinfo, request,
			    SNMP_ERR_GENERR);
			continue;
		}

		if (tinfo->colnum >= ARC_TC_C64_MIN &&
		    tinfo->colnum <= ARC_TC_C64_MAX) {
			struct counter64 c64;
			/*
			 * snmpd doesn't provide 64-bit support via native
			 * 64-bit representations, so we have to convert to the
			 * API's split 32-bit structure.
			 */
			c64.high = val >> 32;
			c64.low = val & 0xffffffff;
			(void) snmp_set_var_typed_value(var, ASN_COUNTER64,
			    (uchar_t *)&c64, sizeof (c64));
		} else if (tinfo->colnum >= ARC_TC_UI32_MIN &&
		    tinfo->colnum <= ARC_TC_UI32_MAX) {
			/*
			 * Should handle truncation for us and log
			 * overflow without failure we need to handle.
			 */
			(void) snmp_set_var_typed_value(var, ASN_UNSIGNED,
			    (uchar_t *)&val, sizeof (val));
		} else if (tinfo->colnum >= ARC_TC_TS_MIN &&
		    tinfo->colnum <= ARC_TC_TS_MAX) {
			uint64_t tval = ts/10000000;
			/*
			 * SNMP timeticks have resolution to hundreths of sec,
			 * may display funny with tools like snmpwalk, which
			 * assume ticks since epoch.  Similar story for the
			 * conversion function handling 32-bit
			 * conversion/truncation as for the UI32 case.
			 */
			(void) snmp_set_var_typed_value(var, ASN_TIMETICKS,
			    (uchar_t *)&tval, sizeof (tval));
		} else { /* should not happen */
			(void) snmp_log(LOG_ERR,
			    "%s: %s handler: unknown type for column %d\n",
			    MODULE_NAME, ARCTABLE_NAME, tinfo->colnum);
		}
		/*
		 * XXX We release the lock around the cache between requests,
		 * so it's possible for a client to read from two different
		 * reads of the kstats. This is tolerable given that we're
		 * rolling our own caching to compensate for what doesn't work
		 * in snmpd.
		 */
		arcstat_release();
	}

	return (SNMP_ERR_NOERROR);
}

/*
 * Register our MIB table with snmpd, define table structure, and set up
 * handler.  We set up handler for the separate count oid at the same time, as
 * it's intimately linked to the table.  This function is called from the module
 * load function, which can't return any errors, so we return void.
 */
static void
arc_init(void)
{
	arcstat_init();

	arc_iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
	VERIFY3P(arc_iinfo, !=, NULL);
	arc_tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
	VERIFY3P(arc_tinfo, !=, NULL);
	arc_handler = netsnmp_create_handler_registration(ARCTABLE_NAME,
	    arcTable_handler, arcTable_oid, OID_LENGTH(arcTable_oid),
	    HANDLER_CAN_RONLY);
	VERIFY3P(arc_handler, !=, NULL);

	/* Although the table has a single row, index just in case */
	netsnmp_table_helper_add_indexes(arc_tinfo, ASN_UNSIGNED, 0);
	/* Index for this table is accessible as read-only */
	arc_tinfo->min_column = ARC_TC_MIN_COL;
	arc_tinfo->max_column = ARC_TC_MAX_COL;
	DEBUGMSGTL((MODULE_NAME, "%s: first %d last %d\n",
	    ARCTABLE_NAME, arc_tinfo->min_column, arc_tinfo->max_column));

	arc_iinfo->get_first_data_point = arcstat_get_first_data_point;
	arc_iinfo->get_next_data_point = arcstat_get_next_data_point;
	arc_iinfo->table_reginfo = arc_tinfo;
	arc_iinfo->flags = NETSNMP_HANDLER_OWNS_IINFO;

	VERIFY3U(netsnmp_register_table_iterator(arc_handler, arc_iinfo),
	    ==, MIB_REGISTERED_OK);
}

static void
arc_fini(void)
{
	VERIFY3U(unregister_mib(arcTable_oid, OID_LENGTH(arcTable_oid)),
	    ==, MIB_UNREGISTERED_OK);

	netsnmp_handler_registration_free(arc_handler);
	arc_handler = NULL;
	netsnmp_iterator_delete_table(arc_iinfo);
	arc_iinfo = NULL;
	arc_tinfo = NULL;

	arcstat_fini();

	DEBUGMSGTL((MODULE_NAME, "deinitialized %s\n", ARCTABLE_NAME));
}

static int
zpoolTable_handler(netsnmp_mib_handler *handler,
    netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo,
    netsnmp_request_info *requests)
{
	netsnmp_request_info *request;
	netsnmp_table_request_info *tinfo;
	netsnmp_variable_list *var;
	char *str;
	int i = 0;
	uint64_t val;
	void *ctx;

	for (request = requests; request; request = request->next) {
		var = request->requestvb;
		if (request->processed != 0)
			continue;
		if (reqinfo->mode != MODE_GET) {
			(void) snmp_log(LOG_ERR,
			    "%s: %s handler: unsupported mode\n", MODULE_NAME,
			    ZPOOLTABLE_NAME);
			continue;
		}

		DEBUGMSGTL((MODULE_NAME, "%s request item no %d\n",
		    ZPOOLTABLE_NAME, ++i));

		ctx = netsnmp_extract_iterator_context(request);
		if (ctx == NULL) {
			(void) netsnmp_set_request_error(reqinfo, request,
			    SNMP_NOSUCHINSTANCE);
			continue;
		}

		tinfo = netsnmp_extract_table_info(request);
		if (tinfo == NULL)
			continue;

		if (tinfo->colnum < ZPOOL_TC_MIN_COL ||
		    tinfo->colnum > ZPOOL_TC_MAX_COL) {
			(void) snmp_log(LOG_ERR,
			    "%s: %s handler: unknown column %d\n",
			    MODULE_NAME, ZPOOLTABLE_NAME, tinfo->colnum);
			(void) netsnmp_set_request_error(reqinfo, request,
			    SNMP_ERR_GENERR);
			continue;
		}

		DEBUGMSGTL((MODULE_NAME, "%s table column %d\n",
		    ZPOOLTABLE_NAME, tinfo->colnum));

		if (zprop_pool_get(ctx, tinfo->colnum, &val, &str) != 0) {
			(void) snmp_log(LOG_ERR,
			    "%s: failed to retrieve values for table %s\n",
			    MODULE_NAME, ZPOOLTABLE_NAME);
			(void) netsnmp_set_request_error(reqinfo,
			    request, SNMP_ERR_GENERR);
			continue;
		}

		if (tinfo->colnum >= ZPOOL_TC_STR_MIN &&
		    tinfo->colnum <= ZPOOL_TC_STR_MAX) {
			DEBUGMSGTL((MODULE_NAME, "table %s column %d = %s\n",
			    ZPOOLTABLE_NAME, tinfo->colnum,
			    SNMP_STRORNULL(str)));
			/*
			 * snmpd doesn't need NUL terminators included in string
			 * length, but we have to to check to make sure it can
			 * allocate buffers for ASN.1 representation.
			 */
			if (snmp_set_var_typed_value(var, ASN_OCTET_STR,
			    (uchar_t *)str, strlen(str)) != 0) {
				(void) snmp_log(LOG_ERR, "%s: failed to render "
				    "string for column %d (%s)\n", MODULE_NAME,
				    tinfo->colnum, SNMP_STRORNULL(str));
				(void) netsnmp_set_request_error(
				    reqinfo, request, SNMP_ERR_GENERR);
			}
		} else if (tinfo->colnum >= ZPOOL_TC_UI32_MIN &&
		    tinfo->colnum <= ZPOOL_TC_UI32_MAX) {
			/*
			 * These are effectively gauge representations, so we
			 * use unsigned 32-bit representation.  Some of these
			 * values are 64-bit values that don't have a 64-bit
			 * gauge in the SMIv2 base types, so we break them down
			 * in to higher and lower order bits.
			 */
			(void) snmp_set_var_typed_value(var, ASN_UNSIGNED,
			    (uchar_t *)&val, sizeof (val));
		} else if (tinfo->colnum >= ZPOOL_TC_ENUM_MIN &&
		    tinfo->colnum <= ZPOOL_TC_ENUM_MAX) {
			/*
			 * See comments to zpool_prop_init() in
			 * common/zfs/zpool_prop.c -- property types include
			 * indexes, which have integer representation within the
			 * kernel but have string representations mediated by
			 * enums for userland.  We use textual conventions
			 * mapped to integers as the SNMP equivalent.
			 * Fortunately for us the C enums for all of these start
			 * at 1, which conforms to SMIv2's recommendation for
			 * textual conventions (RFC2578 7.1.1), which passes
			 * "smilint -l3".
			 */
			(void) snmp_set_var_typed_value(var, ASN_INTEGER,
			    (uchar_t *)&val, sizeof (val));
		} else if (tinfo->colnum >= ZPOOL_TC_INT_MIN &&
		    tinfo->colnum <= ZPOOL_TC_INT_MAX) {
			/*
			 * These values are integers but use different textual
			 * conventions: either TruthValue (RFC2579 2) or
			 * DISPLAY-HINT (3.1), where the kernel passes values as
			 * whole numbers that should be represented externally
			 * with decimals.
			 */
			(void) snmp_set_var_typed_value(var, ASN_INTEGER,
			    (uchar_t *)&val, sizeof (val));
		} else { /* should not happen */
			(void) snmp_log(LOG_ERR,
			    "%s: %s handler: unknown type for column %d\n",
			    MODULE_NAME, ZPOOLTABLE_NAME, tinfo->colnum);
		}
	}

	zprop_release();
	return (SNMP_ERR_NOERROR);
}

/*
 * Register our MIB table with snmpd, define table structure, and set up
 * handler.  We set up handler for the separate count oid at the same time, as
 * it's intimately linked to the table.  This function is called from the module
 * load function, which can't return any errors, so we return void.
 */
static void
zpool_init(void)
{
	zprop_init();

	zpool_iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
	VERIFY3P(zpool_iinfo, !=, NULL);
	zpool_tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
	VERIFY3P(zpool_tinfo, !=, NULL);
	zpool_handler = netsnmp_create_handler_registration(ZPOOLTABLE_NAME,
	    zpoolTable_handler, zpoolTable_oid, OID_LENGTH(zpoolTable_oid),
	    HANDLER_CAN_RONLY);
	VERIFY3P(zpool_handler, !=, NULL);

	/* We index on both GUID and name */
	netsnmp_table_helper_add_indexes(zpool_tinfo, ASN_OCTET_STR,
	    ASN_OCTET_STR, 0);
	/* Index for this table is accessible as read-only */
	zpool_tinfo->min_column = ZPOOL_TC_MIN_COL;
	zpool_tinfo->max_column = ZPOOL_TC_MAX_COL;
	DEBUGMSGTL((MODULE_NAME, "%s: first %d last %d\n",
	    ZPOOLTABLE_NAME, zpool_tinfo->min_column, zpool_tinfo->max_column));

	zpool_iinfo->get_first_data_point = zprop_pool_get_first_data_point;
	zpool_iinfo->get_next_data_point = zprop_pool_get_next_data_point;
	zpool_iinfo->table_reginfo = zpool_tinfo;
	zpool_iinfo->flags = NETSNMP_HANDLER_OWNS_IINFO;

	VERIFY3U(netsnmp_register_table_iterator(zpool_handler, zpool_iinfo),
	    ==, MIB_REGISTERED_OK);
}

static void
zpool_fini(void)
{

	VERIFY3U(unregister_mib(zpoolTable_oid, OID_LENGTH(zpoolTable_oid)),
	    ==, MIB_UNREGISTERED_OK);

	netsnmp_handler_registration_free(zpool_handler);
	zpool_handler = NULL;
	netsnmp_iterator_delete_table(zpool_iinfo);
	zpool_iinfo = NULL;
	zpool_tinfo = NULL;

	zprop_fini();

	DEBUGMSGTL((MODULE_NAME, "deinitialized %s\n", ZPOOLTABLE_NAME));
}

/* Module initialisation function defined by SNMP API */
void
init_zfs(void)
{
	DEBUGMSGTL((MODULE_NAME, "initializing zfs module\n"));
	arc_init();
	zpool_init();
}

void
deinit_zfs(void)
{
	DEBUGMSGTL((MODULE_NAME, "terminating zfs module\n"));
	arc_fini();
	zpool_fini();
}
