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

#ifndef	_ZFS_ERRNO_H
#define	_ZFS_ERRNO_H


enum {
	EKZFS_WBCCHILD	= 200,
	EKZFS_WBCPARENT,
	EKZFS_WBCCONFLICT,
	EKZFS_WBCNOTSUP,
};

#endif	/* _ZFS_ERRNO_H */
