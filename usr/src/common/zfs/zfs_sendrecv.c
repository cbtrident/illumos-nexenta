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
 * Copyright (c) 2011, 2015 by Delphix. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef _KERNEL
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <umem.h>
#include <stddef.h>
#include <zlib.h>
#include <libnvpair.h>
#else
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/nvpair.h>

#include <util/sscanf.h>
#endif

#include <sys/zfs_context.h>
#include <sys/zfs_ioctl.h>
#include <sys/zio_compress.h>
#include <sys/zio_checksum.h>
#include "zfs_fletcher.h"
#include "zfs_sendrecv.h"

#ifndef _KERNEL
#ifndef SET_ERROR
#define	SET_ERROR(err) (err)
#endif
#endif

static int
zfs_mem_alloc(void **data, size_t data_sz)
{
#ifdef _KERNEL
		*data = kmem_zalloc(data_sz, KM_SLEEP);
#else
		if ((*data = calloc(1, data_sz)) == NULL)
			return (SET_ERROR(ENOMEM));
#endif
		return (0);
}

/* ARGSUSED */
static void
zfs_mem_free(void *data, size_t data_sz)
{
#ifdef _KERNEL
		kmem_free(data, data_sz);
#else
		free(data);
#endif
}

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
	while ((fn = avl_destroy_nodes(avl, &cookie)) != NULL)
		zfs_mem_free(fn, sizeof (fsavl_node_t));

	avl_destroy(avl);

	zfs_mem_free(avl, sizeof (avl_tree_t));
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
		return (SET_ERROR(err));

	while ((snapelem = nvlist_next_nvpair(snaps, snapelem)) != NULL) {
		err = nvpair_value_uint64(snapelem, &guid);
		if (err != 0)
			return (SET_ERROR(err));

		/*
		 * Note: if there are multiple snaps with the
		 * same GUID, we ignore all but one.
		 */
		fn_find.fn_guid = guid;
		if (avl_find(fsavl, &fn_find, NULL) != NULL)
			continue;

		err = zfs_mem_alloc((void **)&fn, sizeof (fsavl_node_t));
		if (err != 0)
			return (err);

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

	err = zfs_mem_alloc((void **)&fsavl, sizeof (avl_tree_t));
	if (err != 0)
		return (err);

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

int
zfs_send_resume_token_to_nvlist_impl(const char *token, nvlist_t **result_nvl)
{
	int err;
	unsigned int version;
	int nread, len;
	uint64_t checksum, packed_len;
	unsigned char *compressed = NULL;
	void *packed = NULL;

	/*
	 * Decode token header, which is:
	 *   <token version>-<checksum of payload>-<uncompressed payload length>
	 * Note that the only supported token version is 1.
	 */
	nread = sscanf(token, "%u-%llx-%llx-",
	    &version, (unsigned long long *)&checksum,
	    (unsigned long long *)&packed_len);
	if (nread != 3)
		return (SET_ERROR(EINVAL));

	if (version != ZFS_SEND_RESUME_TOKEN_VERSION)
		return (SET_ERROR(ENOTSUP));

	/* convert hexadecimal representation to binary */
	token = strrchr(token, '-') + 1;
	len = strlen(token) / 2;
	err = zfs_mem_alloc((void **)&compressed, len + 1);
	if (err != 0)
		return (err);

	for (int i = 0; i < len; i++) {
		nread = sscanf(token + i * 2, "%2hhx", compressed + i);
		if (nread != 1) {
			zfs_mem_free(compressed, len + 1);
			return (SET_ERROR(EBADMSG));
		}
	}

	/* verify checksum */
	zio_cksum_t cksum;
	fletcher_4_native(compressed, len, NULL, &cksum);
	if (cksum.zc_word[0] != checksum) {
		zfs_mem_free(compressed, len + 1);
		return (SET_ERROR(ECKSUM));
	}

	/* uncompress */
	err = zfs_mem_alloc(&packed, packed_len);
	if (err != 0) {
		zfs_mem_free(compressed, len + 1);
		return (err);
	}

#ifdef _KERNEL
	err = gzip_decompress(compressed, packed, len, packed_len, 0);
#else
	uLongf packed_len_long = packed_len;
	if (uncompress(packed, &packed_len_long, compressed, len) != Z_OK ||
	    packed_len_long != packed_len)
		err = -1;
#endif

	if (err != 0) {
		zfs_mem_free(packed, packed_len);
		zfs_mem_free(compressed, len + 1);
		return (SET_ERROR(ENOSR));
	}

	/* unpack nvlist */
	nvlist_t *nv = NULL;
#ifdef _KERNEL
	err = nvlist_unpack(packed, packed_len, &nv, KM_SLEEP);
#else
	err = nvlist_unpack(packed, packed_len, &nv, 0);
#endif

	zfs_mem_free(packed, packed_len);
	zfs_mem_free(compressed, len + 1);
	if (err != 0)
		return (SET_ERROR(ENODATA));

	*result_nvl = nv;
	return (0);
}
