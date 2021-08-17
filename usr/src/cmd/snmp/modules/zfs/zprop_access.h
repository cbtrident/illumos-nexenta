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

#ifndef _ZPROP_ACCESS_H
#define	_ZPROP_ACCESS_H

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <stdio.h>

typedef enum zpool_table_col {
	ZPOOL_TC_NAME = 1,
	ZPOOL_TC_GUID,
	ZPOOL_TC_HEALTH,
	ZPOOL_TC_FAILMODE,
	ZPOOL_TC_CAPACITY,
	ZPOOL_TC_SIZE_HIGH,
	ZPOOL_TC_SIZE_LOW,
	ZPOOL_TC_ALLOC_HIGH,
	ZPOOL_TC_ALLOC_LOW,
	ZPOOL_TC_FREE_HIGH,
	ZPOOL_TC_FREE_LOW,
	ZPOOL_TC_FREEING_HIGH,
	ZPOOL_TC_FREEING_LOW,
	ZPOOL_TC_EXPANDSIZE_HIGH,
	ZPOOL_TC_EXPANDSIZE_LOW,
	ZPOOL_TC_DEDUPRATIO,
	ZPOOL_TC_AUTOEXPAND
#define	ZPOOL_TC_STR_MIN	ZPOOL_TC_NAME
#define	ZPOOL_TC_STR_MAX	ZPOOL_TC_GUID
#define	ZPOOL_TC_ENUM_MIN	ZPOOL_TC_HEALTH
#define	ZPOOL_TC_ENUM_MAX	ZPOOL_TC_FAILMODE
#define	ZPOOL_TC_UI32_MIN	ZPOOL_TC_CAPACITY
#define	ZPOOL_TC_UI32_MAX	ZPOOL_TC_EXPANDSIZE_LOW
#define	ZPOOL_TC_INT_MIN	ZPOOL_TC_DEDUPRATIO
#define	ZPOOL_TC_INT_MAX	ZPOOL_TC_AUTOEXPAND
#define	ZPOOL_TC_MIN_COL	ZPOOL_TC_NAME
#define	ZPOOL_TC_MAX_COL	ZPOOL_TC_AUTOEXPAND
} zpool_table_col_t;

Netsnmp_First_Data_Point	zprop_pool_get_first_data_point;
Netsnmp_Next_Data_Point		zprop_pool_get_next_data_point;

extern void zprop_init(void);
extern void zprop_fini(void);
extern int zprop_pool_get(void *, zpool_table_col_t, uint64_t *, char **);
extern void zprop_release(void);

#endif /* _ZPROP_ACCESS_H */
