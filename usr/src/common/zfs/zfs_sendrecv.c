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

#ifndef _KERNEL
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <umem.h>
#include <stddef.h>
#else
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#endif

#include "zfs_sendrecv.h"

typedef struct fsavl_node {
	avl_node_t fn_node;
	nvlist_t *fn_nvfs;
	char *fn_snapname;
	uint64_t fn_guid;
} fsavl_node_t;

/*
 * Routines for dealing with the AVL tree of fs-nvlists
 */

static int
fsavl_compare(const void *arg1, const void *arg2)
{
	const fsavl_node_t *fn1 = arg1;
	const fsavl_node_t *fn2 = arg2;

	if (fn1->fn_guid > fn2->fn_guid)
		return (+1);
	else if (fn1->fn_guid < fn2->fn_guid)
		return (-1);
	else
		return (0);
}

/*
 * Given the GUID of a snapshot, find its containing filesystem and
 * (optionally) name.
 */
nvlist_t *
fsavl_find(avl_tree_t *avl, uint64_t snapguid, char **snapname)
{
	fsavl_node_t fn_find;
	fsavl_node_t *fn;

	fn_find.fn_guid = snapguid;

	fn = avl_find(avl, &fn_find, NULL);
	if (fn != NULL) {
		if (snapname != NULL)
			*snapname = fn->fn_snapname;

		return (fn->fn_nvfs);
	}

	return (NULL);
}

void
fsavl_destroy(avl_tree_t *avl)
{
	fsavl_node_t *fn;
	void *cookie;

	if (avl == NULL)
		return;

	cookie = NULL;
	while ((fn = avl_destroy_nodes(avl, &cookie)) != NULL) {
#ifdef _KERNEL
		kmem_free(fn, sizeof (fsavl_node_t));
#else
		free(fn);
#endif
	}

	avl_destroy(avl);

#ifdef _KERNEL
	kmem_free(avl, sizeof (avl_tree_t));
#else
	free(avl);
#endif
}

static int
fsavl_create_nodes(avl_tree_t *fsavl, nvlist_t *nvfs)
{
	int err;
	fsavl_node_t *fn, fn_find;
	nvlist_t *snaps = NULL;
	nvpair_t *snapelem = NULL;
	uint64_t guid;

	err = nvlist_lookup_nvlist(nvfs, "snaps", &snaps);
	if (err != 0)
		return (err);

	while ((snapelem = nvlist_next_nvpair(snaps, snapelem)) != NULL) {
		err = nvpair_value_uint64(snapelem, &guid);
		if (err != 0)
			return (err);

		/*
		 * Note: if there are multiple snaps with the
		 * same GUID, we ignore all but one.
		 */
		fn_find.fn_guid = guid;
		if (avl_find(fsavl, &fn_find, NULL) != NULL)
			continue;

#ifdef _KERNEL
		fn = kmem_alloc(sizeof (fsavl_node_t), KM_SLEEP);
#else
		if ((fn = malloc(sizeof (fsavl_node_t))) == NULL)
			return (ENOMEM);
#endif

		fn->fn_nvfs = nvfs;
		fn->fn_snapname = nvpair_name(snapelem);
		fn->fn_guid = guid;

		avl_add(fsavl, fn);
	}

	return (0);
}

/*
 * Given an nvlist, produce an avl tree of snapshots, ordered by guid
 */
int
fsavl_create(nvlist_t *fss, avl_tree_t **fsavl_result)
{
	int err;
	avl_tree_t *fsavl;
	nvpair_t *fselem = NULL;

#ifdef _KERNEL
	fsavl = kmem_zalloc(sizeof (avl_tree_t), KM_SLEEP);
#else
	if ((fsavl = malloc(sizeof (avl_tree_t))) == NULL)
		return (ENOMEM);
#endif

	avl_create(fsavl, fsavl_compare, sizeof (fsavl_node_t),
	    offsetof(fsavl_node_t, fn_node));

	while ((fselem = nvlist_next_nvpair(fss, fselem)) != NULL) {
		nvlist_t *nvfs = NULL;

		err = nvpair_value_nvlist(fselem, &nvfs);
		if (err != 0)
			break;

		err = fsavl_create_nodes(fsavl, nvfs);
		if (err != 0)
			break;
	}

	if (err != 0)
		fsavl_destroy(fsavl);
	else
		*fsavl_result = fsavl;

	return (err);
}
