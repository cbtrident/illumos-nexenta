/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2013 Steven Hartland. All rights reserved.
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include "ndmpd.h"
#include <libzfs.h>
#include <zlib.h>

int
ndmp_clone_snapshot(char *snapshot_name, char *clone_name)
{
	int		res = Z_OK;
	int		err;
	zfs_handle_t	*zhp;
	zfs_handle_t	*clone;
	nvlist_t	*props = NULL;
	char clone_mount_point[ZFS_MAX_DATASET_NAME_LEN];

	if ((zhp = zfs_open(zlibh, snapshot_name, ZFS_TYPE_SNAPSHOT)) == NULL) {
		syslog(LOG_ERR, "Could not open snapshot [%s]\n", snapshot_name);
		return (-1);
	}
	syslog(LOG_DEBUG, "Clone [%s]\n", snapshot_name);

	(void) snprintf(clone_mount_point, ZFS_MAX_DATASET_NAME_LEN, "/%s", clone_name);

	if ((nvlist_alloc(&props, NV_UNIQUE_NAME, 0) != 0) ||
	    (nvlist_add_string(props, zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
	    clone_mount_point) != 0)) {
		nvlist_free(props);
		syslog(LOG_ERR, "could not create snapshot clone "
		    "%s: out of memory\n", clone_name);
		return (-1);
	}

	err = zfs_clone(zhp, clone_name, props);
	zfs_close(zhp);
	nvlist_free(props);

	if (err != 0) {
		syslog(LOG_ERR,"zfs_clone error [%d]\n", err);
		return (-1);
	}

	if ((clone = zfs_open(zlibh, clone_name, ZFS_TYPE_DATASET)) == NULL) {
		syslog(LOG_ERR,"zfs_open failed on clone_name [%s]\n", clone_name);
		return (-1);
	}

	if (zfs_mount(clone, NULL, 0) != 0) {
		syslog(LOG_ERR, "could not mount ZFS clone "
			"%s\n", zfs_get_name(clone));
		res = -1;
	}
	zfs_close(clone);
	return (res);
}
