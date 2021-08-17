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

#ifndef _ZFS_SNMP_H
#define	_ZFS_SNMP_H

#define	ZPOOL_CACHE_TIMEOUT	60

/*
 * (1, 3, 6, 1, 4 , 1: enterprises) (40045: nexentaMIB) (1: core) (1: storage)
 * (1: zfs) (1: nexentaZfsMIB) (1: nexentaZfsObjects)
 */
#define	ZFSMIBOBJ_OID	1, 3, 6, 1, 4, 1, 40045, 1, 1, 1, 1, 1
#define	ARC_OID		ZFSMIBOBJ_OID, 1
#define	ZPOOL_OID	ZFSMIBOBJ_OID, 2

#define	ARCTABLE_OID	ARC_OID, 1
#define	ZPOOLTABLE_OID	ZPOOL_OID, 1

#define	MODULE_NAME	"zfs"
#define	ARCTABLE_NAME	"nexentaZfsArcTable"
#define	ZPOOLTABLE_NAME	"nexentaZfsPoolTable"

#endif /* _ZFS_SNMP_H */
