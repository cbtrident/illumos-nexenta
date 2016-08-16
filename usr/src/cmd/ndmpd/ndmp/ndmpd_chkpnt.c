/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, 2015 by Delphix. All rights reserved.
 * Copyright (c) 2013 Steven Hartland. All rights reserved.
 * Copyright (c) 2016 Martin Matuska. All rights reserved.
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

typedef struct snap_param {
	char *snp_name;
	boolean_t snp_found;
} snap_param_t;

static int cleanup_fd = -1;
mutex_t clean_fd_mutex = DEFAULTMUTEX;

/*
 * ndmp_create_snapshot
 *
 * This function will parse the path to get the real volume name.
 * It will then create a snapshot based on volume and job name.
 * This function should be called before the NDMP backup is started.
 *
 * Parameters:
 *   vol_name (input) - name of the volume
 *
 * Returns:
 *   0: on success
 *   -1: otherwise
 */
int
ndmp_create_snapshot(char *vol_name, char *jname)
{
	char vol[ZFS_MAX_DATASET_NAME_LEN];

	if (vol_name == 0 ||
	    get_zfsvolname(vol, sizeof (vol), vol_name) == -1)
		return (0);

	return (snapshot_create(vol, jname, B_FALSE, B_FALSE));
}

/*
 * ndmp_remove_snapshot
 *
 * This function will parse the path to get the real volume name.
 * It will then remove the snapshot for that volume and job name.
 * This function should be called after NDMP backup is finished.
 *
 * Parameters:
 *   vol_name (input) - name of the volume
 *
 * Returns:
 *   0: on success
 *   -1: otherwise
 */
int
ndmp_remove_snapshot(ndmp_bkup_size_arg_t *sarg)
{
	char vol[ZFS_MAX_DATASET_NAME_LEN];

	if (sarg->bs_path == NULL ||
	    get_zfsvolname(vol, sizeof (vol), sarg->bs_path) == -1)
		return (0);

	return (snapshot_destroy(vol, sarg->bs_jname, B_FALSE, B_FALSE, NULL));
}

/*
 * Put a hold on snapshot
 */
int
snapshot_hold(char *volname, char *snapname, char *jname, boolean_t recursive)
{
	zfs_handle_t *zhp;
	char *p;

	if ((zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == 0) {
		syslog(LOG_ERR, "Cannot open volume %s.", volname);
		return (-1);
	}

	if (cleanup_fd == -1 && (cleanup_fd = open(ZFS_DEV,
	    O_RDWR|O_EXCL)) < 0) {
		syslog(LOG_ERR, "Cannot open dev %d", errno);
		zfs_close(zhp);
		return (-1);
	}

	p = strchr(snapname, '@') + 1;
	if (zfs_hold(zhp, p, jname, recursive, cleanup_fd) != 0) {
		syslog(LOG_ERR, "Cannot hold snapshot %s", p);
		zfs_close(zhp);
		return (-1);
	}
	zfs_close(zhp);
	return (0);
}

int
snapshot_release(char *volname, char *snapname, char *jname,
    boolean_t recursive)
{
	zfs_handle_t *zhp;
	char *p;
	int rv = 0;

	if ((zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == 0) {
		syslog(LOG_ERR, "Cannot open volume %s", volname);
		return (-1);
	}

	p = strchr(snapname, '@') + 1;
	if (zfs_release(zhp, p, jname, recursive) != 0) {
		syslog(LOG_DEBUG, "Cannot release snapshot %s", p);
		rv = -1;
	}
	if (cleanup_fd != -1) {
		(void) close(cleanup_fd);
		cleanup_fd = -1;
	}
	zfs_close(zhp);
	return (rv);
}

/*
 * Create a snapshot on the volume
 */
int
snapshot_create(char *volname, char *jname,
	boolean_t recursive, boolean_t hold)
{
	char snapname[ZFS_MAX_DATASET_NAME_LEN] = {'\0'};
	char clonename[ZFS_MAX_DATASET_NAME_LEN] = {'\0'};
	char zpoolname[ZFS_MAX_DATASET_NAME_LEN] = {'\0'};
	char *slash;
	int rv;

	if (!volname || !*volname)
		return (-1);

	(void) strlcpy(zpoolname, volname, ZFS_MAX_DATASET_NAME_LEN);
	slash = strchr(zpoolname, '/');
	if (slash != 0) {
		*slash = '\0';
	} else {
		(void) strlcpy(zpoolname, volname, ZFS_MAX_DATASET_NAME_LEN);
	}

	(void) snprintf(snapname, ZFS_MAX_DATASET_NAME_LEN, "%s@%s", volname, jname);
	(void) snprintf(clonename, ZFS_MAX_DATASET_NAME_LEN, "%s/%s", zpoolname, jname);

	(void) mutex_lock(&zlib_mtx);
	if ((rv = zfs_snapshot(zlibh, snapname, recursive, NULL)) == -1) {
		if (errno == EEXIST) {
			(void) mutex_unlock(&zlib_mtx);
			return (0);
		}
		syslog(LOG_ERR,
		    "snapshot_create: %s failed (err=%d): %s",
		    snapname, errno, libzfs_error_description(zlibh));
		(void) mutex_unlock(&zlib_mtx);
		return (rv);
	}
	if (ndmp_clone_snapshot(snapname, clonename) != 0) {
		syslog(LOG_ERR,
		    "snapshot_create: %s clone failed (err=%d): %s",
		    snapname, errno, libzfs_error_description(zlibh));
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}
	if (hold && snapshot_hold(volname, snapname, jname, recursive) != 0) {
		syslog(LOG_DEBUG,
		    "snapshot_create: %s hold failed (err=%d): %s",
		    snapname, errno, libzfs_error_description(zlibh));
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	(void) mutex_unlock(&zlib_mtx);
	return (0);
}

/*
 * Remove and release the backup snapshot
 */
int
snapshot_destroy(char *volname, char *jname, boolean_t recursive,
    boolean_t hold, int *zfs_err)
{
	char snapname[ZFS_MAX_DATASET_NAME_LEN] = {'\0'};
	char clonename[ZFS_MAX_DATASET_NAME_LEN] = {'\0'};
	char zpoolname[ZFS_MAX_DATASET_NAME_LEN] = {'\0'};
	char clone_mount_point[ZFS_MAX_DATASET_NAME_LEN] = {'\0'};
	char *slash;
	zfs_handle_t *vol_zhp;
	zfs_handle_t *cln_zhp;
	int err;

	if (!volname || !*volname)
		return (-1);

	(void) strlcpy(zpoolname, volname, ZFS_MAX_DATASET_NAME_LEN);
	slash = strchr(zpoolname, '/');
	if (slash != 0) {
		*slash = 0;
	} else {
		(void) strlcpy(zpoolname, volname, ZFS_MAX_DATASET_NAME_LEN);
	}

	if (zfs_err)
		*zfs_err = 0;

	(void) snprintf(snapname, ZFS_MAX_DATASET_NAME_LEN, "%s@%s", volname, jname);
	(void) snprintf(clonename, ZFS_MAX_DATASET_NAME_LEN, "%s/%s", zpoolname, jname);
	(void) snprintf(clone_mount_point, ZFS_MAX_DATASET_NAME_LEN, "/%s", clonename);

	syslog(LOG_DEBUG, "Destroy [%s]", snapname);

	/*
	 * Destroy using this sequence
	 * zfs promote <pool>/<jname>  (clonename) - this is what was traversed
	 * zfs promote <pool>/<volume> (volname) - this is the original backup
	 * zfs destroy <pool>/<jname>
	 * zfs destroy <pool>/<volume>@<jname>
	 */
	(void) mutex_lock(&zlib_mtx);

	if (hold &&
	    snapshot_release(volname, snapname, jname, recursive) != 0) {
		syslog(LOG_DEBUG,
		    "snapshot_destroy: %s release failed (err=%d): %s",
		    clonename, errno, libzfs_error_description(zlibh));
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	/*
	 * Open the clone to get descriptor
	 */
	if ((cln_zhp = zfs_open(zlibh, clonename,
			ZFS_TYPE_VOLUME | ZFS_TYPE_FILESYSTEM)) == NULL) {
		syslog(LOG_ERR, "snapshot_destroy: open %s failed", clonename);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	/*
	 * Open the mounted clone to get descriptor for unmount
	 */
	if ((vol_zhp = zfs_open(zlibh, volname,
			ZFS_TYPE_VOLUME | ZFS_TYPE_FILESYSTEM)) == NULL) {
		syslog(LOG_ERR, "snapshot_destroy: open %s failed [while trying "
			"to promote]", volname);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	/*
	 * This unmounts the clone which was just traversed for backup
	 */
	if ((err = zfs_unmount(cln_zhp, NULL, 0)) != 0) {
		syslog(LOG_INFO, "failed to unmount [%s]", clonename);
	}

	/*
	 * This destroys the snapshot
	 */
	err = zfs_destroy(cln_zhp, B_TRUE);
	if (err) {
		syslog(LOG_ERR, "%s (destroy: %s): %d; %s; %s",
		    clonename,
		    (recursive) ? "recursive" : "non-recursive",
		    libzfs_errno(zlibh),
		    libzfs_error_action(zlibh),
		    libzfs_error_description(zlibh));

		if (zfs_err)
			*zfs_err = err;
	}

	/*
	 * This destroys the snapshot of the current backup
	 */
	err = zfs_destroy_snaps(vol_zhp, jname, B_TRUE);
	if (err) {
		syslog(LOG_ERR, "%s (destroy: %d): %d; %s; %s",
		    jname,
		    recursive,
		    libzfs_errno(zlibh),
		    libzfs_error_action(zlibh),
		    libzfs_error_description(zlibh));

		if (zfs_err)
			*zfs_err = err;
	}

	zfs_close(vol_zhp);
	zfs_close(cln_zhp);
	(void) mutex_unlock(&zlib_mtx);

	if (rmdir(clone_mount_point) != 0) {
		syslog(LOG_ERR, "Failed to remove mount point [%s]", clone_mount_point);
	}

	return (0);
}
