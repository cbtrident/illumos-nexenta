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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef _ZFS_SENDRECV_H
#define	_ZFS_SENDRECV_H

#ifdef _KERNEL
#include <sys/nvpair.h>
#else
#include <libnvpair.h>
#endif

#include <sys/avl.h>


#ifdef	__cplusplus
extern "C" {
#endif

int fsavl_create(nvlist_t *fss, avl_tree_t **fsavl_result);
void fsavl_destroy(avl_tree_t *avl);
nvlist_t *fsavl_find(avl_tree_t *avl, uint64_t snapguid, char **snapname);


#ifdef	__cplusplus
}
#endif

#endif	/* _ZFS_SENDRECV_H */
