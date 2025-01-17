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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2014, 2016 by Delphix. All rights reserved.
 * Copyright 2016 Igor Kozhukhov <ikozhukhov@gmail.com>
 * Copyright 2017 Joyent, Inc.
 * Copyright 2017 RackTop Systems.
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Routines to manage ZFS mounts.  We separate all the nasty routines that have
 * to deal with the OS.  The following functions are the main entry points --
 * they are used by mount and unmount and when changing a filesystem's
 * mountpoint.
 *
 *	zfs_is_mounted()
 *	zfs_mount()
 *	zfs_unmount()
 *	zfs_unmountall()
 *
 * This file also contains the functions used to manage sharing filesystems via
 * NFS and iSCSI:
 *
 *	zfs_is_shared()
 *	zfs_share()
 *	zfs_unshare()
 *
 *	zfs_is_shared_nfs()
 *	zfs_is_shared_smb()
 *	zfs_share_proto()
 *	zfs_shareall();
 *	zfs_unshare_nfs()
 *	zfs_unshare_smb()
 *	zfs_unshareall_nfs()
 *	zfs_unshareall_smb()
 *	zfs_unshareall()
 *	zfs_unshareall_bypath()
 *
 * The following functions are available for pool consumers, and will
 * mount/unmount and share/unshare all datasets within pool:
 *
 *	zpool_enable_datasets()
 *	zpool_enable_datasets_ex()
 *	zpool_disable_datasets()
 *	zpool_disable_datasets_ex()
 */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <zone.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <thread_pool.h>
#include <sys/statvfs.h>

#include <libzfs.h>

#include "libzfs_impl.h"

#include <libshare.h>
#include <sys/systeminfo.h>
#define	MAXISALEN	257	/* based on sysinfo(2) man page */

#define	IGNORE_NO_SUCH_PATH	B_TRUE

static int zfs_share_proto(zfs_handle_t *, zfs_share_proto_t *, boolean_t);
zfs_share_type_t zfs_is_shared_proto(zfs_handle_t *, char **,
    zfs_share_proto_t);

/*
 * The share protocols table must be in the same order as the zfs_share_proto_t
 * enum in libzfs_impl.h
 */
typedef struct {
	zfs_prop_t p_prop;
	char *p_name;
	int p_share_err;
	int p_unshare_err;
} proto_table_t;

proto_table_t proto_table[PROTO_END] = {
	{ZFS_PROP_SHARENFS, "nfs", EZFS_SHARENFSFAILED, EZFS_UNSHARENFSFAILED},
	{ZFS_PROP_SHARESMB, "smb", EZFS_SHARESMBFAILED, EZFS_UNSHARESMBFAILED},
};

zfs_share_proto_t nfs_only[] = {
	PROTO_NFS,
	PROTO_END
};

zfs_share_proto_t smb_only[] = {
	PROTO_SMB,
	PROTO_END
};
zfs_share_proto_t share_all_proto[] = {
	PROTO_NFS,
	PROTO_SMB,
	PROTO_END
};

typedef enum {
	PARENT_MOUNT_SUCCESS,
	PARENT_MOUNT_PENDING,
	PARENT_MOUNT_FAILED
} parent_mount_status_t;

/*
 * Search the sharetab for the given mountpoint and protocol, returning
 * a zfs_share_type_t value.
 */
static zfs_share_type_t
is_shared(libzfs_handle_t *hdl, const char *mountpoint, zfs_share_proto_t proto)
{
	char buf[MAXPATHLEN], *tab;
	char *ptr;

	if (hdl->libzfs_sharetab == NULL)
		return (SHARED_NOT_SHARED);

	(void) fseek(hdl->libzfs_sharetab, 0, SEEK_SET);

	while (fgets(buf, sizeof (buf), hdl->libzfs_sharetab) != NULL) {

		/* the mountpoint is the first entry on each line */
		if ((tab = strchr(buf, '\t')) == NULL)
			continue;

		*tab = '\0';
		if (strcmp(buf, mountpoint) == 0) {
			/*
			 * the protocol field is the third field
			 * skip over second field
			 */
			ptr = ++tab;
			if ((tab = strchr(ptr, '\t')) == NULL)
				continue;
			ptr = ++tab;
			if ((tab = strchr(ptr, '\t')) == NULL)
				continue;
			*tab = '\0';
			if (strcmp(ptr,
			    proto_table[proto].p_name) == 0) {
				switch (proto) {
				case PROTO_NFS:
					return (SHARED_NFS);
				case PROTO_SMB:
					return (SHARED_SMB);
				default:
					return (0);
				}
			}
		}
	}

	return (SHARED_NOT_SHARED);
}

static boolean_t
dir_is_empty_stat(const char *dirname)
{
	struct stat st;

	/*
	 * We only want to return false if the given path is a non empty
	 * directory, all other errors are handled elsewhere.
	 */
	if (stat(dirname, &st) < 0 || !S_ISDIR(st.st_mode)) {
		return (B_TRUE);
	}

	/*
	 * An empty directory will still have two entries in it, one
	 * entry for each of "." and "..".
	 */
	if (st.st_size > 2) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
dir_is_empty_readdir(const char *dirname)
{
	DIR *dirp;
	struct dirent64 *dp;
	int dirfd;

	if ((dirfd = openat(AT_FDCWD, dirname,
	    O_RDONLY | O_NDELAY | O_LARGEFILE | O_CLOEXEC, 0)) < 0) {
		return (B_TRUE);
	}

	if ((dirp = fdopendir(dirfd)) == NULL) {
		(void) close(dirfd);
		return (B_TRUE);
	}

	while ((dp = readdir64(dirp)) != NULL) {

		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		(void) closedir(dirp);
		return (B_FALSE);
	}

	(void) closedir(dirp);
	return (B_TRUE);
}

/*
 * Returns true if the specified directory is empty.  If we can't open the
 * directory at all, return true so that the mount can fail with a more
 * informative error message.
 */
static boolean_t
dir_is_empty(const char *dirname)
{
	struct statvfs64 st;

	/*
	 * If the statvfs call fails or the filesystem is not a ZFS
	 * filesystem, fall back to the slow path which uses readdir.
	 */
	if ((statvfs64(dirname, &st) != 0) ||
	    (strcmp(st.f_basetype, "zfs") != 0)) {
		return (dir_is_empty_readdir(dirname));
	}

	/*
	 * At this point, we know the provided path is on a ZFS
	 * filesystem, so we can use stat instead of readdir to
	 * determine if the directory is empty or not. We try to avoid
	 * using readdir because that requires opening "dirname"; this
	 * open file descriptor can potentially end up in a child
	 * process if there's a concurrent fork, thus preventing the
	 * zfs_mount() from otherwise succeeding (the open file
	 * descriptor inherited by the child process will cause the
	 * parent's mount to fail with EBUSY). The performance
	 * implications of replacing the open, read, and close with a
	 * single stat is nice; but is not the main motivation for the
	 * added complexity.
	 */
	return (dir_is_empty_stat(dirname));
}

/*
 * Checks to see if the mount is active.  If the filesystem is mounted, we fill
 * in 'where' with the current mountpoint, and return 1.  Otherwise, we return
 * 0.
 */
boolean_t
is_mounted(libzfs_handle_t *zfs_hdl, const char *special, char **where)
{
	struct mnttab entry;

	if (libzfs_mnttab_find(zfs_hdl, special, &entry) != 0)
		return (B_FALSE);

	if (where != NULL)
		*where = zfs_strdup(zfs_hdl, entry.mnt_mountp);

	return (B_TRUE);
}

boolean_t
zfs_is_mounted(zfs_handle_t *zhp, char **where)
{
	return (is_mounted(zhp->zfs_hdl, zfs_get_name(zhp), where));
}

/*
 * Returns true if the given dataset is mountable, false otherwise.  Returns the
 * mountpoint in 'buf'.
 */
static boolean_t
zfs_is_mountable(zfs_handle_t *zhp, char *buf, size_t buflen,
    zprop_source_t *source)
{
	char sourceloc[MAXNAMELEN];
	zprop_source_t sourcetype;

	if (!zfs_prop_valid_for_type(ZFS_PROP_MOUNTPOINT, zhp->zfs_type))
		return (B_FALSE);

	verify(zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, buf, buflen,
	    &sourcetype, sourceloc, sizeof (sourceloc), B_FALSE) == 0);

	if (strcmp(buf, ZFS_MOUNTPOINT_NONE) == 0 ||
	    strcmp(buf, ZFS_MOUNTPOINT_LEGACY) == 0)
		return (B_FALSE);

	if (zfs_prop_get_int(zhp, ZFS_PROP_CANMOUNT) == ZFS_CANMOUNT_OFF)
		return (B_FALSE);

	if (zfs_prop_get_int(zhp, ZFS_PROP_ZONED) &&
	    getzoneid() == GLOBAL_ZONEID)
		return (B_FALSE);

	if (source)
		*source = sourcetype;

	return (B_TRUE);
}

/*
 * Mount the given filesystem.
 */
int
zfs_mount(zfs_handle_t *zhp, const char *options, int flags)
{
	struct stat buf;
	char mountpoint[ZFS_MAXPROPLEN];
	char mntopts[MNT_LINE_MAX];
	libzfs_handle_t *hdl = zhp->zfs_hdl;

	if (options == NULL)
		mntopts[0] = '\0';
	else
		(void) strlcpy(mntopts, options, sizeof (mntopts));

	/*
	 * If the pool is imported read-only then all mounts must be read-only
	 */
	if (zpool_get_prop_int(zhp->zpool_hdl, ZPOOL_PROP_READONLY, NULL))
		flags |= MS_RDONLY;

	if (!zfs_is_mountable(zhp, mountpoint, sizeof (mountpoint), NULL))
		return (0);

	/* Create the directory if it doesn't already exist */
	if (lstat(mountpoint, &buf) != 0) {
		if (mkdirp(mountpoint, 0755) != 0) {
			int err = errno;
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "failed to create mountpoint - %s"),
			    strerror(err));
			(void) zfs_error_fmt(hdl, EZFS_MOUNTFAILED,
			    dgettext(TEXT_DOMAIN, "cannot mount '%s'"),
			    mountpoint);
			return (err);
		}
	}

	/*
	 * Determine if the mountpoint is empty.  If so, refuse to perform the
	 * mount.  We don't perform this check if MS_OVERLAY is specified, which
	 * would defeat the point.  We also avoid this check if 'remount' is
	 * specified.
	 */
	if ((flags & MS_OVERLAY) == 0 &&
	    strstr(mntopts, MNTOPT_REMOUNT) == NULL &&
	    !dir_is_empty(mountpoint)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "directory is not empty"));
		return (zfs_error_fmt(hdl, EZFS_MOUNTFAILED,
		    dgettext(TEXT_DOMAIN, "cannot mount '%s'"), mountpoint));
	}

	/* perform the mount */
	if (mount(zfs_get_name(zhp), mountpoint, MS_OPTIONSTR | flags,
	    MNTTYPE_ZFS, NULL, 0, mntopts, sizeof (mntopts)) != 0) {
		/*
		 * Generic errors are nasty, but there are just way too many
		 * from mount(), and they're well-understood.  We pick a few
		 * common ones to improve upon.
		 */
		if (errno == EBUSY) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "mountpoint or dataset is busy"));
		} else if (errno == EPERM) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "Insufficient privileges"));
		} else if (errno == ENOTSUP) {
			char buf[256];
			int spa_version;

			VERIFY(zfs_spa_version(zhp, &spa_version) == 0);
			(void) snprintf(buf, sizeof (buf),
			    dgettext(TEXT_DOMAIN, "Can't mount a version %lld "
			    "file system on a version %d pool. Pool must be"
			    " upgraded to mount this file system."),
			    (u_longlong_t)zfs_prop_get_int(zhp,
			    ZFS_PROP_VERSION), spa_version);
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, buf));
		} else {
			zfs_error_aux(hdl, strerror(errno));
		}
		return (zfs_error_fmt(hdl, EZFS_MOUNTFAILED,
		    dgettext(TEXT_DOMAIN, "cannot mount '%s'"),
		    zhp->zfs_name));
	}

	/* add the mounted entry into our cache */
	libzfs_mnttab_add(hdl, zfs_get_name(zhp), mountpoint,
	    mntopts);
	return (0);
}

/*
 * Unmount a single filesystem.
 */
static int
unmount_one(libzfs_handle_t *hdl, const char *mountpoint, int flags,
    boolean_t ignore_no_such_path)
{
	if (umount2(mountpoint, flags) != 0) {
		if (ignore_no_such_path && (errno == ENOENT || errno == EINVAL))
			return (0);

		zfs_error_aux(hdl, strerror(errno));
		return (zfs_error_fmt(hdl, EZFS_UMOUNTFAILED,
		    dgettext(TEXT_DOMAIN, "cannot unmount '%s'"),
		    mountpoint));
	}

	return (0);
}

/*
 * Unmount the given filesystem.
 */
int
zfs_unmount(zfs_handle_t *zhp, const char *mountpoint, int flags)
{
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	struct mnttab entry;
	char *mntpt = NULL;

	/* check to see if we need to unmount the filesystem */
	if (mountpoint != NULL || ((zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM) &&
	    libzfs_mnttab_find(hdl, zhp->zfs_name, &entry) == 0)) {
		/*
		 * mountpoint may have come from a call to
		 * getmnt/getmntany if it isn't NULL. If it is NULL,
		 * we know it comes from libzfs_mnttab_find which can
		 * then get freed later. We strdup it to play it safe.
		 */
		if (mountpoint == NULL)
			mntpt = zfs_strdup(hdl, entry.mnt_mountp);
		else
			mntpt = zfs_strdup(hdl, mountpoint);

		/*
		 * Unshare and unmount the filesystem
		 */
		if (zfs_unshare_proto(zhp, mntpt, share_all_proto) != 0) {
			free(mntpt);
			return (-1);
		}

		if (unmount_one(hdl, mntpt, flags, !IGNORE_NO_SUCH_PATH) != 0) {
			free(mntpt);
			(void) zfs_shareall(zhp);
			return (-1);
		}
		libzfs_mnttab_remove(hdl, zhp->zfs_name);
		free(mntpt);
	}

	return (0);
}

/*
 * Unmount this filesystem and any children inheriting the mountpoint property.
 * To do this, just act like we're changing the mountpoint property, but don't
 * remount the filesystems afterwards.
 */
int
zfs_unmountall(zfs_handle_t *zhp, int flags)
{
	prop_changelist_t *clp;
	int ret;

	clp = changelist_gather(zhp, ZFS_PROP_MOUNTPOINT, 0, flags);
	if (clp == NULL)
		return (-1);

	ret = changelist_prefix(clp);
	changelist_free(clp);

	return (ret);
}

boolean_t
zfs_is_shared(zfs_handle_t *zhp)
{
	zfs_share_type_t rc = 0;
	zfs_share_proto_t *curr_proto;

	if (ZFS_IS_VOLUME(zhp))
		return (B_FALSE);

	for (curr_proto = share_all_proto; *curr_proto != PROTO_END;
	    curr_proto++)
		rc |= zfs_is_shared_proto(zhp, NULL, *curr_proto);

	return (rc ? B_TRUE : B_FALSE);
}

int
zfs_share(zfs_handle_t *zhp)
{
	assert(!ZFS_IS_VOLUME(zhp));
	return (zfs_share_proto(zhp, share_all_proto, B_FALSE));
}

int
zfs_unshare(zfs_handle_t *zhp)
{
	assert(!ZFS_IS_VOLUME(zhp));
	return (zfs_unshareall(zhp));
}

/*
 * Check to see if the filesystem is currently shared.
 */
zfs_share_type_t
zfs_is_shared_proto(zfs_handle_t *zhp, char **where, zfs_share_proto_t proto)
{
	char *mountpoint;
	zfs_share_type_t rc;

	if (!zfs_is_mounted(zhp, &mountpoint))
		return (SHARED_NOT_SHARED);

	if ((rc = is_shared(zhp->zfs_hdl, mountpoint, proto))
	    != SHARED_NOT_SHARED) {
		if (where != NULL)
			*where = mountpoint;
		else
			free(mountpoint);
		return (rc);
	} else {
		free(mountpoint);
		return (SHARED_NOT_SHARED);
	}
}

boolean_t
zfs_is_shared_nfs(zfs_handle_t *zhp, char **where)
{
	return (zfs_is_shared_proto(zhp, where,
	    PROTO_NFS) != SHARED_NOT_SHARED);
}

boolean_t
zfs_is_shared_smb(zfs_handle_t *zhp, char **where)
{
	return (zfs_is_shared_proto(zhp, where,
	    PROTO_SMB) != SHARED_NOT_SHARED);
}

/*
 * Make sure things will work if libshare isn't installed by using
 * wrapper functions that check to see that the pointers to functions
 * initialized in _zfs_init_libshare() are actually present.
 */

static sa_handle_t (*_sa_init)(int);
static sa_handle_t (*_sa_init_arg)(int, void *);
static int (*_sa_service)(sa_handle_t);
static void (*_sa_fini)(sa_handle_t);
static sa_share_t (*_sa_find_share)(sa_handle_t, char *);
static int (*_sa_enable_share)(sa_share_t, char *);
static int (*_sa_disable_share)(sa_share_t, char *);
static int (*_sa_suspend_share)(sa_share_t, char *);
static int (*_sa_resume_share)(sa_share_t, char *);
static char *(*_sa_errorstr)(int);
static int (*_sa_parse_legacy_options)(sa_group_t, char *, char *);
static boolean_t (*_sa_needs_refresh)(sa_handle_t *);
static libzfs_handle_t *(*_sa_get_zfs_handle)(sa_handle_t);
static int (* _sa_get_zfs_share)(sa_handle_t, char *, zfs_handle_t *);
static void (*_sa_update_sharetab_ts)(sa_handle_t);

/*
 * _zfs_init_libshare()
 *
 * Find the libshare.so.1 entry points that we use here and save the
 * values to be used later. This is triggered by the runtime loader.
 * Make sure the correct ISA version is loaded.
 */

#pragma init(_zfs_init_libshare)
static void
_zfs_init_libshare(void)
{
	void *libshare;
	char path[MAXPATHLEN];
	char isa[MAXISALEN];

#if defined(_LP64)
	if (sysinfo(SI_ARCHITECTURE_64, isa, MAXISALEN) == -1)
		isa[0] = '\0';
#else
	isa[0] = '\0';
#endif
	(void) snprintf(path, MAXPATHLEN,
	    "/usr/lib/%s/libshare.so.1", isa);

	if ((libshare = dlopen(path, RTLD_LAZY | RTLD_GLOBAL)) != NULL) {
		_sa_init = (sa_handle_t (*)(int))dlsym(libshare, "sa_init");
		_sa_init_arg = (sa_handle_t (*)(int, void *))dlsym(libshare,
		    "sa_init_arg");
		_sa_fini = (void (*)(sa_handle_t))dlsym(libshare, "sa_fini");
		_sa_service = (int (*)(sa_handle_t))dlsym(libshare,
		    "sa_service");
		_sa_find_share = (sa_share_t (*)(sa_handle_t, char *))
		    dlsym(libshare, "sa_find_share");
		_sa_enable_share = (int (*)(sa_share_t, char *))dlsym(libshare,
		    "sa_enable_share");
		_sa_disable_share = (int (*)(sa_share_t, char *))dlsym(libshare,
		    "sa_disable_share");
		_sa_suspend_share = (int (*)(sa_share_t, char *))dlsym(libshare,
		    "sa_suspend_share");
		_sa_resume_share = (int (*)(sa_share_t, char *))dlsym(libshare,
		    "sa_resume_share");
		_sa_errorstr = (char *(*)(int))dlsym(libshare, "sa_errorstr");
		_sa_parse_legacy_options = (int (*)(sa_group_t, char *, char *))
		    dlsym(libshare, "sa_parse_legacy_options");
		_sa_needs_refresh = (boolean_t (*)(sa_handle_t *))
		    dlsym(libshare, "sa_needs_refresh");
		_sa_get_zfs_handle = (libzfs_handle_t *(*)(sa_handle_t))
		    dlsym(libshare, "sa_get_zfs_handle");
		_sa_get_zfs_share = (int (*)(sa_handle_t, char *,
		    zfs_handle_t *)) dlsym(libshare, "sa_get_zfs_share");
		_sa_update_sharetab_ts = (void (*)(sa_handle_t))
		    dlsym(libshare, "sa_update_sharetab_ts");
		if (_sa_init == NULL || _sa_init_arg == NULL ||
		    _sa_fini == NULL || _sa_find_share == NULL ||
		    _sa_enable_share == NULL || _sa_disable_share == NULL ||
		    _sa_suspend_share == NULL || _sa_resume_share == NULL ||
		    _sa_errorstr == NULL || _sa_parse_legacy_options == NULL ||
		    _sa_needs_refresh == NULL || _sa_get_zfs_handle == NULL ||
		    _sa_get_zfs_share == NULL || _sa_service == NULL ||
		    _sa_update_sharetab_ts == NULL) {
			_sa_init = NULL;
			_sa_init_arg = NULL;
			_sa_service = NULL;
			_sa_fini = NULL;
			_sa_enable_share = NULL;
			_sa_disable_share = NULL;
			_sa_suspend_share = NULL;
			_sa_resume_share = NULL;
			_sa_errorstr = NULL;
			_sa_parse_legacy_options = NULL;
			(void) dlclose(libshare);
			_sa_needs_refresh = NULL;
			_sa_get_zfs_handle = NULL;
			_sa_get_zfs_share = NULL;
			_sa_update_sharetab_ts = NULL;
		}
	}
}

/*
 * zfs_init_libshare(zhandle, service)
 *
 * Initialize the libshare API if it hasn't already been initialized.
 * In all cases it returns 0 if it succeeded and an error if not. The
 * service value is which part(s) of the API to initialize and is a
 * direct map to the libshare sa_init(service) interface.
 */
static int
zfs_init_libshare_impl(libzfs_handle_t *zhandle, int service, void *arg)
{
	/*
	 * libshare is either not installed or we're in a branded zone. The
	 * rest of the wrapper functions around the libshare calls already
	 * handle NULL function pointers, but we don't want the callers of
	 * zfs_init_libshare() to fail prematurely if libshare is not available.
	 */
	if (_sa_init == NULL)
		return (SA_OK);

	/*
	 * Attempt to refresh libshare. This is necessary if there was a cache
	 * miss for a new ZFS dataset that was just created, or if state of the
	 * sharetab file has changed since libshare was last initialized. We
	 * want to make sure so check timestamps to see if a different process
	 * has updated any of the configuration. If there was some non-ZFS
	 * change, we need to re-initialize the internal cache.
	 */
	if (_sa_needs_refresh != NULL &&
	    _sa_needs_refresh(zhandle->libzfs_sharehdl)) {
		zfs_uninit_libshare(zhandle);
		zhandle->libzfs_sharehdl = _sa_init_arg(service, arg);
	}

	if (zhandle && zhandle->libzfs_sharehdl == NULL)
		zhandle->libzfs_sharehdl = _sa_init_arg(service, arg);

	if (zhandle->libzfs_sharehdl == NULL)
		return (SA_NO_MEMORY);

	return (SA_OK);
}
int
zfs_init_libshare(libzfs_handle_t *zhandle, int service)
{
	return (zfs_init_libshare_impl(zhandle, service, NULL));
}

int
zfs_init_libshare_arg(libzfs_handle_t *zhandle, int service, void *arg)
{
	return (zfs_init_libshare_impl(zhandle, service, arg));
}


/*
 * zfs_uninit_libshare(zhandle)
 *
 * Uninitialize the libshare API if it hasn't already been
 * uninitialized. It is OK to call multiple times.
 */
void
zfs_uninit_libshare(libzfs_handle_t *zhandle)
{
	if (zhandle != NULL && zhandle->libzfs_sharehdl != NULL) {
		if (_sa_fini != NULL)
			_sa_fini(zhandle->libzfs_sharehdl);
		zhandle->libzfs_sharehdl = NULL;
	}
}

/*
 * zfs_parse_options(options, proto)
 *
 * Call the legacy parse interface to get the protocol specific
 * options using the NULL arg to indicate that this is a "parse" only.
 */
int
zfs_parse_options(char *options, zfs_share_proto_t proto)
{
	if (_sa_parse_legacy_options != NULL) {
		return (_sa_parse_legacy_options(NULL, options,
		    proto_table[proto].p_name));
	}
	return (SA_CONFIG_ERR);
}

/*
 * zfs_sa_find_share(handle, path)
 *
 * wrapper around sa_find_share to find a share path in the
 * configuration.
 */
static sa_share_t
zfs_sa_find_share(sa_handle_t handle, char *path)
{
	if (_sa_find_share != NULL)
		return (_sa_find_share(handle, path));
	return (NULL);
}

/*
 * zfs_sa_enable_share(share, proto)
 *
 * Wrapper for sa_enable_share which enables a share for a specified
 * protocol.
 */
static int
zfs_sa_enable_share(sa_share_t share, char *proto)
{
	if (_sa_enable_share != NULL)
		return (_sa_enable_share(share, proto));
	return (SA_CONFIG_ERR);
}

/*
 * zfs_sa_disable_share(share, proto)
 *
 * Wrapper for sa_enable_share which disables a share for a specified
 * protocol.
 */
static int
zfs_sa_disable_share(sa_share_t share, char *proto)
{
	if (_sa_disable_share != NULL)
		return (_sa_disable_share(share, proto));
	return (SA_CONFIG_ERR);
}

/*
 * zfs_sa_suspend_share(share, proto)
 *
 * Wrapper for sa_suspend_share which suspends a share for a specified
 * protocol.
 */
static int
zfs_sa_suspend_share(sa_share_t share, char *proto)
{
	if (_sa_suspend_share != NULL)
		return (_sa_suspend_share(share, proto));
	return (SA_CONFIG_ERR);
}

/*
 * zfs_sa_resume_share(share, proto)
 *
 * Wrapper for sa_resumeshare which resumes a share for a specified
 * protocol.
 */
static int
zfs_sa_resume_share(sa_share_t share,  char *proto)
{
	if (_sa_resume_share != NULL)
		return (_sa_resume_share(share, proto));
	return (SA_CONFIG_ERR);
}

/*
 * Share the given filesystem according to the options in the specified
 * protocol specific properties (sharenfs, sharesmb).  We rely
 * on "libshare" to the dirty work for us.
 */
static int
zfs_share_proto(zfs_handle_t *zhp, zfs_share_proto_t *proto, boolean_t resume)
{
	char mountpoint[ZFS_MAXPROPLEN];
	char shareopts[ZFS_MAXPROPLEN];
	char sourcestr[ZFS_MAXPROPLEN];
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	sa_share_t share;
	zfs_share_proto_t *curr_proto;
	zprop_source_t sourcetype;
	int service = SA_INIT_ONE_SHARE_FROM_HANDLE;
	int ret;

	if (!zfs_is_mountable(zhp, mountpoint, sizeof (mountpoint), NULL))
		return (0);

	/*
	 * Function may be called in a loop from higher up stack, with libshare
	 * initialized for multiple shares (SA_INIT_SHARE_API_SELECTIVE), or
	 * for all shares (SA_INIT_SHARE_API).
	 * zfs_init_libshare_arg will refresh the handle's cache if necessary.
	 * In this case we do not want to switch to per share initialization.
	 * Specify SA_INIT_SHARE_API to do full refresh, if refresh required.
	 */
	if ((hdl->libzfs_sharehdl != NULL) && (_sa_service != NULL)) {
		int prev_service = _sa_service(hdl->libzfs_sharehdl);
		if ((prev_service == SA_INIT_SHARE_API_SELECTIVE) ||
		    (prev_service == SA_INIT_SHARE_API)) {
			service = SA_INIT_SHARE_API;
		}
	}

	for (curr_proto = proto; *curr_proto != PROTO_END; curr_proto++) {
		/*
		 * Return success if there are no share options.
		 */
		if (zfs_prop_get(zhp, proto_table[*curr_proto].p_prop,
		    shareopts, sizeof (shareopts), &sourcetype, sourcestr,
		    ZFS_MAXPROPLEN, B_FALSE) != 0 ||
		    strcmp(shareopts, "off") == 0)
			continue;
		ret = zfs_init_libshare_arg(hdl, service, zhp);
		if (ret != SA_OK) {
			(void) zfs_error_fmt(hdl, EZFS_SHARENFSFAILED,
			    dgettext(TEXT_DOMAIN, "cannot share '%s': %s"),
			    zfs_get_name(zhp), _sa_errorstr != NULL ?
			    _sa_errorstr(ret) : "");
			return (-1);
		}

		share = zfs_sa_find_share(hdl->libzfs_sharehdl, mountpoint);
		if (share == NULL) {
			/*
			 * This may be a new file system that was just
			 * created so isn't in the internal cache.
			 * Rather than reloading the entire configuration,
			 * we can add just this one share to the cache.
			 */
			if ((_sa_get_zfs_share == NULL) ||
			    (_sa_get_zfs_share(hdl->libzfs_sharehdl, "zfs", zhp)
			    != SA_OK)) {
				(void) zfs_error_fmt(hdl,
				    proto_table[*curr_proto].p_share_err,
				    dgettext(TEXT_DOMAIN, "cannot share '%s'"),
				    zfs_get_name(zhp));
				return (-1);
			}
			share = zfs_sa_find_share(hdl->libzfs_sharehdl,
			    mountpoint);
		}
		if (share != NULL) {
			int err;
			if (resume) {
				err = zfs_sa_resume_share(share,
				    proto_table[*curr_proto].p_name);
			} else {
				err = zfs_sa_enable_share(share,
				    proto_table[*curr_proto].p_name);
			}
			if (err != SA_OK) {
				(void) zfs_error_fmt(hdl,
				    proto_table[*curr_proto].p_share_err,
				    dgettext(TEXT_DOMAIN, "cannot share '%s'"),
				    zfs_get_name(zhp));
				return (-1);
			}
		} else {
			(void) zfs_error_fmt(hdl,
			    proto_table[*curr_proto].p_share_err,
			    dgettext(TEXT_DOMAIN, "cannot share '%s'"),
			    zfs_get_name(zhp));
			return (-1);
		}

	}
	return (0);
}


int
zfs_share_nfs(zfs_handle_t *zhp)
{
	return (zfs_share_proto(zhp, nfs_only, B_FALSE));
}

int
zfs_share_smb(zfs_handle_t *zhp)
{
	return (zfs_share_proto(zhp, smb_only, B_FALSE));
}

int
zfs_shareall(zfs_handle_t *zhp)
{
	return (zfs_share_proto(zhp, share_all_proto, B_FALSE));
}

static int
zfs_share_resume(zfs_handle_t *zhp)
{
	return (zfs_share_proto(zhp, share_all_proto, B_TRUE));
}

/*
 * Unshare a filesystem by mountpoint.
 */
static int
unshare_one(libzfs_handle_t *hdl, const char *name, const char *mountpoint,
    zfs_share_proto_t proto, boolean_t suspend, boolean_t ignore_no_such_path)
{
	sa_share_t share;
	int err;
	char *mntpt;
	int service = SA_INIT_ONE_SHARE_FROM_NAME;

	/*
	 * Mountpoint could get trashed if libshare calls getmntany
	 * which it does during API initialization, so strdup the
	 * value.
	 */
	mntpt = zfs_strdup(hdl, mountpoint);

	/*
	 * Function may be called in a loop from higher up stack, with libshare
	 * initialized for multiple shares (SA_INIT_SHARE_API_SELECTIVE), or
	 * for all shares (SA_INIT_SHARE_API).
	 * zfs_init_libshare_arg will refresh the handle's cache if necessary.
	 * In this case we do not want to switch to per share initialization.
	 * Specify SA_INIT_SHARE_API to do full refresh, if refresh required.
	 */
	if ((hdl->libzfs_sharehdl != NULL) && (_sa_service != NULL)) {
		int prev_service = _sa_service(hdl->libzfs_sharehdl);
		if ((prev_service == SA_INIT_SHARE_API_SELECTIVE) ||
		    (prev_service == SA_INIT_SHARE_API)) {
			service = SA_INIT_SHARE_API;
		}
	}

	err = zfs_init_libshare_arg(hdl, service, (void *)name);
	if (err != SA_OK) {
		free(mntpt);	/* don't need the copy anymore */
		return (zfs_error_fmt(hdl, proto_table[proto].p_unshare_err,
		    dgettext(TEXT_DOMAIN, "cannot unshare '%s': %s"),
		    name, _sa_errorstr(err)));
	}

	share = zfs_sa_find_share(hdl->libzfs_sharehdl, mntpt);
	free(mntpt);	/* don't need the copy anymore */

	if (share != NULL) {
		if (suspend) {
			err = zfs_sa_suspend_share(share,
			    proto_table[proto].p_name);
		} else {
			err = zfs_sa_disable_share(share,
			    proto_table[proto].p_name);
		}
		if (err != SA_OK) {
			if (err == SA_NO_SUCH_PATH && ignore_no_such_path)
				return (0);

			return (zfs_error_fmt(hdl,
			    proto_table[proto].p_unshare_err,
			    dgettext(TEXT_DOMAIN, "cannot unshare '%s': %s"),
			    name, _sa_errorstr(err)));
		}
	} else if (!ignore_no_such_path) {
		return (zfs_error_fmt(hdl, proto_table[proto].p_unshare_err,
		    dgettext(TEXT_DOMAIN, "cannot unshare '%s': not found"),
		    name));
	}
	return (0);
}

/*
 * Unshare the given filesystem.
 */
int
zfs_unshare_proto(zfs_handle_t *zhp, const char *mountpoint,
    zfs_share_proto_t *proto)
{
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	struct mnttab entry;
	char *mntpt = NULL;

	/* check to see if need to unmount the filesystem */
	rewind(zhp->zfs_hdl->libzfs_mnttab);
	if (mountpoint != NULL)
		mountpoint = mntpt = zfs_strdup(hdl, mountpoint);

	if (mountpoint != NULL || ((zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM) &&
	    libzfs_mnttab_find(hdl, zfs_get_name(zhp), &entry) == 0)) {
		zfs_share_proto_t *curr_proto;

		if (mountpoint == NULL)
			mntpt = zfs_strdup(zhp->zfs_hdl, entry.mnt_mountp);

		for (curr_proto = proto; *curr_proto != PROTO_END;
		    curr_proto++) {

			if (is_shared(hdl, mntpt, *curr_proto) &&
			    unshare_one(hdl, zhp->zfs_name, mntpt, *curr_proto,
			    B_FALSE, !IGNORE_NO_SUCH_PATH) != 0) {
				if (mntpt != NULL)
					free(mntpt);
				return (-1);
			}
		}
	}
	if (mntpt != NULL)
		free(mntpt);

	return (0);
}

int
zfs_unshare_nfs(zfs_handle_t *zhp, const char *mountpoint)
{
	return (zfs_unshare_proto(zhp, mountpoint, nfs_only));
}

int
zfs_unshare_smb(zfs_handle_t *zhp, const char *mountpoint)
{
	return (zfs_unshare_proto(zhp, mountpoint, smb_only));
}

/*
 * Same as zfs_unmountall(), but for NFS and SMB unshares.
 */
int
zfs_unshareall_proto(zfs_handle_t *zhp, zfs_share_proto_t *proto)
{
	prop_changelist_t *clp;
	int ret;

	clp = changelist_gather(zhp, ZFS_PROP_SHARENFS, 0, 0);
	if (clp == NULL)
		return (-1);

	ret = changelist_unshare(clp, proto);
	changelist_free(clp);

	return (ret);
}

int
zfs_unshareall_nfs(zfs_handle_t *zhp)
{
	return (zfs_unshareall_proto(zhp, nfs_only));
}

int
zfs_unshareall_smb(zfs_handle_t *zhp)
{
	return (zfs_unshareall_proto(zhp, smb_only));
}

int
zfs_unshareall(zfs_handle_t *zhp)
{
	return (zfs_unshareall_proto(zhp, share_all_proto));
}

int
zfs_unshareall_bypath(zfs_handle_t *zhp, const char *mountpoint)
{
	return (zfs_unshare_proto(zhp, mountpoint, share_all_proto));
}

static int
zfs_share_suspend(libzfs_handle_t *hdl, const char *name, char *mountpoint,
    zfs_share_proto_t proto)
{
	return (unshare_one(hdl, name, mountpoint, proto, B_TRUE,
	    IGNORE_NO_SUCH_PATH));
}

/*
 * Remove the mountpoint associated with the current dataset, if necessary.
 * We only remove the underlying directory if:
 *
 *	- The mountpoint is not 'none' or 'legacy'
 *	- The mountpoint is non-empty
 *	- The mountpoint is the default or inherited
 *	- The 'zoned' property is set, or we're in a local zone
 *
 * Any other directories we leave alone.
 */
void
remove_mountpoint(zfs_handle_t *zhp)
{
	char mountpoint[ZFS_MAXPROPLEN];
	zprop_source_t source;

	if (!zfs_is_mountable(zhp, mountpoint, sizeof (mountpoint),
	    &source))
		return;

	if (source == ZPROP_SRC_DEFAULT ||
	    source == ZPROP_SRC_INHERITED) {
		/*
		 * Try to remove the directory, silently ignoring any errors.
		 * The filesystem may have since been removed or moved around,
		 * and this error isn't really useful to the administrator in
		 * any way.
		 */
		(void) rmdir(mountpoint);
	}
}

void
libzfs_add_handle(get_all_cb_t *cbp, zfs_handle_t *zhp)
{
	if (cbp->cb_alloc == cbp->cb_used) {
		size_t newsz;
		void *ptr;

		newsz = cbp->cb_alloc ? cbp->cb_alloc * 2 : 64;
		ptr = zfs_realloc(zhp->zfs_hdl,
		    cbp->cb_handles, cbp->cb_alloc * sizeof (void *),
		    newsz * sizeof (void *));
		cbp->cb_handles = ptr;
		cbp->cb_alloc = newsz;
	}
	cbp->cb_handles[cbp->cb_used++] = zhp;
}

static int
mount_cb(zfs_handle_t *zhp, void *data)
{
	get_all_cb_t *cbp = data;

	if (!(zfs_get_type(zhp) & ZFS_TYPE_FILESYSTEM)) {
		zfs_close(zhp);
		return (0);
	}

	if (zfs_prop_get_int(zhp, ZFS_PROP_CANMOUNT) == ZFS_CANMOUNT_NOAUTO) {
		zfs_close(zhp);
		return (0);
	}

	/*
	 * If this filesystem is inconsistent and has a receive resume
	 * token, we can not mount it.
	 */
	if (zfs_prop_get_int(zhp, ZFS_PROP_INCONSISTENT) &&
	    zfs_prop_get(zhp, ZFS_PROP_RECEIVE_RESUME_TOKEN,
	    NULL, 0, NULL, NULL, 0, B_TRUE) == 0) {
		zfs_close(zhp);
		return (0);
	}

	libzfs_add_handle(cbp, zhp);
	if (zfs_iter_fs(zhp, mount_cb, cbp) != 0) {
		zfs_close(zhp);
		return (-1);
	}
	return (0);
}

int
libzfs_dataset_cmp(const void *a, const void *b)
{
	zfs_handle_t **za = (zfs_handle_t **)a;
	zfs_handle_t **zb = (zfs_handle_t **)b;
	char mounta[MAXPATHLEN];
	char mountb[MAXPATHLEN];
	boolean_t gota, gotb;

	if ((gota = (zfs_get_type(*za) == ZFS_TYPE_FILESYSTEM)) != 0)
		verify(zfs_prop_get(*za, ZFS_PROP_MOUNTPOINT, mounta,
		    sizeof (mounta), NULL, NULL, 0, B_FALSE) == 0);
	if ((gotb = (zfs_get_type(*zb) == ZFS_TYPE_FILESYSTEM)) != 0)
		verify(zfs_prop_get(*zb, ZFS_PROP_MOUNTPOINT, mountb,
		    sizeof (mountb), NULL, NULL, 0, B_FALSE) == 0);

	if (gota && gotb)
		return (strcmp(mounta, mountb));

	if (gota)
		return (-1);
	if (gotb)
		return (1);

	return (strcmp(zfs_get_name(a), zfs_get_name(b)));
}

static int
mountpoint_compare(const void *a, const void *b)
{
	const char *mounta = *((char **)a);
	const char *mountb = *((char **)b);

	return (strcmp(mountb, mounta));
}

typedef enum {
	TASK_TO_PROCESS,
	TASK_IN_PROCESSING,
	TASK_DONE,
	TASK_MAX
} task_state_t;

typedef struct mount_task {
	const char	*mp;
	zfs_handle_t	*zh;
	task_state_t	state;
	boolean_t	error;
} mount_task_t;

typedef struct mount_task_q {
	pthread_mutex_t	q_lock;
	pthread_cond_t	q_cv;
	libzfs_handle_t	*hdl;
	const char	*mntopts;
	int		q_error;
	int		q_length;
	int		n_tasks; /* # TASK_TO_PROCESS */
	int		flags;
	mount_task_t	task[1];
} mount_task_q_t;

static int
mount_task_q_init(int argc, zfs_handle_t **handles, const char *mntopts,
    int flags, mount_task_q_t **task)
{
	mount_task_q_t *task_q;
	char mntpnt[MAXPATHLEN];
	int i, error;
	size_t task_q_size;

	*task = NULL;
	/* nothing to do ? should not be here */
	if (argc <= 0)
		return (EINVAL);

	/* allocate and init task_q */
	task_q_size = sizeof (mount_task_q_t) +
	    (argc - 1) * sizeof (mount_task_t);
	task_q = calloc(task_q_size, 1);
	if (task_q == NULL)
		return (ENOMEM);

	if ((error = pthread_mutex_init(&task_q->q_lock, NULL)) != 0) {
		free(task_q);
		return (error);
	}
	if ((error = pthread_cond_init(&task_q->q_cv, NULL)) != 0) {
		pthread_mutex_destroy(&task_q->q_lock);
		free(task_q);
		return (error);
	}
	task_q->q_length = argc;
	task_q->n_tasks = argc;
	task_q->flags = flags;
	task_q->mntopts = mntopts;

	for (i = 0; i < argc; ++i) {
		task_q->task[i].zh = handles[i];
		task_q->task[i].state = TASK_TO_PROCESS;
		task_q->task[i].error = B_TRUE;
		task_q->q_error = 0;
		verify(zfs_prop_get(handles[i], ZFS_PROP_MOUNTPOINT, mntpnt,
		    sizeof (mntpnt), NULL, NULL, 0, B_FALSE) == 0);
		task_q->task[i].mp = zfs_strdup(handles[i]->zfs_hdl, mntpnt);
	}

	*task = task_q;
	return (0);
}

static int
umount_task_q_init(int argc, const char **argv, int flags,
    libzfs_handle_t *hdl, mount_task_q_t **task)
{
	mount_task_q_t *task_q;
	int i, error;
	size_t task_q_size;

	*task = NULL;
	/* nothing to do ? should not be here */
	if (argc <= 0)
		return (EINVAL);

	/* allocate and init task_q */
	task_q_size = sizeof (mount_task_q_t) +
	    (argc - 1) * sizeof (mount_task_t);
	task_q = calloc(task_q_size, 1);
	if (task_q == NULL)
		return (ENOMEM);

	if ((error = pthread_mutex_init(&task_q->q_lock, NULL)) != 0) {
		free(task_q);
		return (error);
	}
	task_q->hdl = hdl;
	task_q->q_length = argc;
	task_q->n_tasks = argc;
	task_q->flags = flags;

	/* we are not going to change the strings, so no need to strdup */
	for (i = 0; i < argc; ++i) {
		task_q->task[i].mp = argv[i];
		task_q->task[i].state = TASK_TO_PROCESS;
		task_q->q_error = 0;
	}

	*task = task_q;
	return (0);
}

static void
mount_task_q_fini(mount_task_q_t *task_q)
{
	int i;

	assert(task_q != NULL);

	/* for mount task[i].mp was zfs_strdup'd. */
	for (i = 0; i < task_q->q_length; ++i)
		free((char *)task_q->task[i].mp);

	(void) pthread_cond_destroy(&task_q->q_cv);
	(void) pthread_mutex_destroy(&task_q->q_lock);
	free(task_q);
}

static void
umount_task_q_fini(mount_task_q_t *task_q)
{
	assert(task_q != NULL);
	(void) pthread_cond_destroy(&task_q->q_cv);
	(void) pthread_mutex_destroy(&task_q->q_lock);
	free(task_q);
}

static int
is_child_of(const char *s1, const char *s2)
{
	for (; *s1 && *s2 && (*s1 == *s2); ++s1, ++s2)
		;
	return (!*s2 && (*s1 == '/'));
}

static boolean_t
task_completed(int ind, mount_task_q_t *task_q)
{
	return (task_q->task[ind].state == TASK_DONE);
}

static boolean_t
task_to_process(int ind, mount_task_q_t *task_q)
{
	return (task_q->task[ind].state == TASK_TO_PROCESS);
}

static boolean_t
task_in_processing(int ind, mount_task_q_t *task_q)
{
	return (task_q->task[ind].state == TASK_IN_PROCESSING);
}

static void
task_next_stage(int ind, mount_task_q_t *task_q)
{
	/* our state machine is a pipeline */
	task_q->task[ind].state++;
	assert(task_q->task[ind].state < TASK_MAX);
}

static boolean_t
task_state_valid(int ind, mount_task_q_t *task_q)
{
	/* our state machine is a pipeline */
	return (task_q->task[ind].state < TASK_MAX);
}

static boolean_t
child_umount_pending(int ind, mount_task_q_t *task_q)
{
	int i;
	for (i = ind-1; i >= 0; --i) {
		assert(task_state_valid(i, task_q));
		if ((task_q->task[i].state != TASK_DONE) &&
		    is_child_of(task_q->task[i].mp, task_q->task[ind].mp))
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Identify if there is a parent mount PENDING or FAILED.
 */
static parent_mount_status_t
parent_mount_status(int ind, mount_task_q_t *task_q)
{
	int i;
	mount_task_t *ptask;
	const char *mp = task_q->task[ind].mp;

	for (i = ind-1; i >= 0; --i) {
		assert(task_state_valid(i, task_q));
		ptask = &(task_q->task[i]);

		if (ptask->state != TASK_DONE) {
			if (is_child_of(mp, ptask->mp)) {
				return (PARENT_MOUNT_PENDING);
			}
		} else if (ptask->error != 0) {
			if (is_child_of(mp, ptask->mp)) {
				return (PARENT_MOUNT_FAILED);
			}
		}
	}

	return (PARENT_MOUNT_SUCCESS);
}

/*
 * For serial mount, identify if there is a parent mount FAILED.
 */
static parent_mount_status_t
parent_mount_status_serial(int ind, int *good, char *mntpnts[])
{
	int i;
	char *mp = mntpnts[ind];

	for (i = ind-1; i >= 0; --i) {
		if ((good[i] == 0) && is_child_of(mp, mntpnts[i])) {
			return (PARENT_MOUNT_FAILED);
		}
	}

	return (PARENT_MOUNT_SUCCESS);
}

static void
unmounter(void *arg)
{
	mount_task_q_t *task_q = (mount_task_q_t *)arg;
	int error = 0, done = 0;

	assert(task_q != NULL);
	if (task_q == NULL)
		return;

	while (!error && !done) {
		mount_task_t *task;
		int i, t, umount_err, flags, q_error;

		if ((error = pthread_mutex_lock(&task_q->q_lock)) != 0)
			break; /* Out of while() loop */

		if (task_q->q_error != 0 || task_q->n_tasks == 0) {
			(void) pthread_mutex_unlock(&task_q->q_lock);
			break; /* Out of while() loop */
		}

		/* Find task ready for processing */
		for (i = 0, task = NULL, t = -1; i < task_q->q_length; ++i) {
			if (task_q->q_error != 0) {
				/* Fatal error, stop processing */
				done = 1;
				break; /* Out of for() loop */
			}

			if (task_completed(i, task_q))
				continue; /* for() loop */

			if (task_to_process(i, task_q)) {
				/*
				 * Cannot umount if some children are still
				 * mounted; come back later
				 */
				if ((child_umount_pending(i, task_q)))
					continue; /* for() loop */
				/* Should be OK to unmount now */
				task_next_stage(i, task_q);
				task = &task_q->task[i];
				t = i;
				task_q->n_tasks--;
				break; /* Out of for() loop */
			}

			/* Otherwise, the task is already in processing */
			assert(task_in_processing(i, task_q));
		}

		flags = task_q->flags;

		error = pthread_mutex_unlock(&task_q->q_lock);

		if (done || (task == NULL) || error || task_q->q_error != 0)
			break; /* Out of while() loop */

		umount_err = umount2(task->mp, flags);
		q_error = errno;

		/*
		 * It is possible someone has destroyed this dataset and
		 * this case needs to be ignored
		 */
		if (umount_err != 0 &&
		    (q_error == ENOENT || q_error == EINVAL)) {
			umount_err = 0;
			q_error = 0;
		}

		if ((error = pthread_mutex_lock(&task_q->q_lock)) != 0)
			break; /* Out of while() loop */

		/* done processing */
		assert(t >= 0 && t < task_q->q_length);
		task_next_stage(t, task_q);
		assert(task_completed(t, task_q));

		task->error = (umount_err != 0);

		if (umount_err) {
			zfs_error_aux(task_q->hdl, strerror(q_error));
			(void) zfs_error_fmt(task_q->hdl, EZFS_UMOUNTFAILED,
			    dgettext(TEXT_DOMAIN, "cannot unmount '%s'"),
			    task->mp);

			/*
			 * umount2() failed, cannot be busy because of mounted
			 * children - we have checked above, so it is fatal
			 */
			assert(child_umount_pending(t, task_q) == B_FALSE);
			if (task_q->q_error == 0)
				task_q->q_error = q_error;
			done = 1;
		}

		if ((error = pthread_mutex_unlock(&task_q->q_lock)) != 0)
			break; /* Out of while() loop */
	}
}

static void
mounter(void *arg)
{
	mount_task_q_t *task_q = (mount_task_q_t *)arg;
	int error = 0, done = 0;
	parent_mount_status_t parent_status;
	struct timespec timeout = {1, 0};

	assert(task_q != NULL);
	if (task_q == NULL)
		return;

	while (!error && !done) {
		mount_task_t *task;
		int i, t, flags;
		const char *mntopts;

		if ((error = pthread_mutex_lock(&task_q->q_lock)) != 0)
			break; /* Out of while() loop */

		if (task_q->n_tasks == 0) {
			(void) pthread_mutex_unlock(&task_q->q_lock);
			break; /* Out of while() loop */
		}

		/* Find task ready for processing */
		for (i = 0, task = NULL, t = -1; i < task_q->q_length; ++i) {
			if (task_completed(i, task_q))
				continue; /* for() loop */

			if (task_to_process(i, task_q)) {
				/*
				 * Cannot mount if some parents are not
				 * mounted yet; come back later
				 */
				parent_status = parent_mount_status(i, task_q);
				if (parent_status == PARENT_MOUNT_PENDING)
					continue; /* for() loop */

				/* Should be OK to mount now */
				task_next_stage(i, task_q);
				task = &task_q->task[i];
				t = i;
				task_q->n_tasks--;
				break; /* Out of for() loop */
			}

			/* Otherwise, the task is already in processing */
			assert(task_in_processing(i, task_q));
		}

		flags = task_q->flags;
		mntopts = task_q->mntopts;

		if (done || error) {
			(void) pthread_mutex_unlock(&task_q->q_lock);
			break; /* Out of while() loop */
		}

		if (task == NULL) {
			if (task_q->n_tasks == 0) {
				(void) pthread_mutex_unlock(&task_q->q_lock);
				break; /* Out of while() loop */
			}

			/*
			 * Didn't find a task to process but there are still
			 * unprocessed tasks. They must be waiting for parent
			 * mount to complete. Wait.
			 * Use timed wait in case broadcast never happens due
			 * to a thread breaking out of loop on a lock error.
			 */
			(void) pthread_cond_reltimedwait_np(&task_q->q_cv,
			    &task_q->q_lock, &timeout);
			(void) pthread_mutex_unlock(&task_q->q_lock);
			continue; /* while() loop */
		}

		if ((error = pthread_mutex_unlock(&task_q->q_lock)) != 0)
			break; /* Out of while() loop */

		/* do not attempt to mount if the parent mount failed */
		if (parent_status == PARENT_MOUNT_FAILED) {
			task->error = B_TRUE;
		} else {
			error = zfs_mount(task->zh, mntopts, flags);
			task->error = (error != 0);
			if ((error != 0) && (error != EROFS) &&
			    (task_q->q_error == 0)) {
				task_q->q_error = error;
			}
		}

		if ((error = pthread_mutex_lock(&task_q->q_lock)) != 0)
			break; /* Out of while() loop */

		/* done processing */
		assert(t >= 0 && t < task_q->q_length);
		task_next_stage(t, task_q);
		assert(task_completed(t, task_q));

		/* wake any waiters */
		(void) pthread_cond_broadcast(&task_q->q_cv);

		if ((error = pthread_mutex_unlock(&task_q->q_lock)) != 0)
			break; /* Out of while() loop */
	}
}

#define	THREADS_HARD_LIMIT	128
int parallel_unmount(libzfs_handle_t *hdl, int argc, const char **argv,
    int flags, int n_threads)
{
	mount_task_q_t *task_queue = NULL;
	int		i, error;
	tpool_t		*t;

	if (argc == 0)
		return (0);

	if ((error = umount_task_q_init(argc, argv, flags, hdl, &task_queue))
	    != 0) {
		assert(task_queue == NULL);
		return (error);
	}

	if (n_threads > argc)
		n_threads = argc;

	if (n_threads > THREADS_HARD_LIMIT)
		n_threads = THREADS_HARD_LIMIT;

	t = tpool_create(1, n_threads, 0, NULL);

	for (i = 0; i < n_threads; ++i)
		(void) tpool_dispatch(t, unmounter, task_queue);

	tpool_wait(t);
	tpool_destroy(t);

	error = task_queue->q_error;
	umount_task_q_fini(task_queue);

	return (error);
}

int parallel_mount(get_all_cb_t *cb, int *good, const char *mntopts,
    int flags, int n_threads)
{
	int		i, error = 0;
	mount_task_q_t	*task_queue = NULL;
	tpool_t		*t;

	if (cb->cb_used == 0)
		return (0);

	if (n_threads > cb->cb_used)
		n_threads = cb->cb_used;

	if ((error = mount_task_q_init(cb->cb_used, cb->cb_handles,
	    mntopts, flags, &task_queue)) != 0) {
		assert(task_queue == NULL);
		return (error);
	}

	t = tpool_create(1, n_threads, 0, NULL);

	for (i = 0; i < n_threads; ++i)
		(void) tpool_dispatch(t, mounter, task_queue);

	tpool_wait(t);
	for (i = 0; i < cb->cb_used; ++i) {
		good[i] = task_queue->task[i].error ? 0 : 1;
	}
	tpool_destroy(t);

	error = task_queue->q_error;
	mount_task_q_fini(task_queue);

	return (error);
}

/*
 * Handling EROFS from a failed zfs_mount:
 * If a dataset fails to mount because its mount point cannot be created due to
 * it being on a readonly filesystem we do NOT fail zpool_enable_datasets_ex.
 * We treat the mount as a failure in that we do not try to share the dataset
 * nor try to mount any child mounts on it. We chose to not fail this function
 * so that a "zpool import" does not fail as a result of this situation.
 * The primary reason for doing this is to support HPR, where it is possible
 * for a dataset to be in this state for a finite period of time. We do not
 * want to cause a failover to abort as a result of this.
 */
int
zpool_enable_datasets_ex(zpool_handle_t *zhp, const char *mntopts, int flags,
    int n_threads)
{
	get_all_cb_t cb = { 0 };
	libzfs_handle_t *hdl = zhp->zpool_hdl;
	zfs_handle_t *zfsp;
	int i, ret = -1;
	int *good = NULL;
	sa_init_selective_arg_t sharearg;
	int error = 0;

	/*
	 * Gather all non-snap datasets within the pool.
	 */
	if ((zfsp = zfs_open(hdl, zhp->zpool_name, ZFS_TYPE_DATASET)) == NULL)
		goto out;

	libzfs_add_handle(&cb, zfsp);
	if (zfs_iter_fs(zfsp, mount_cb, &cb) != 0)
		goto out;
	/*
	 * Sort the datasets by mountpoint.
	 */
	qsort(cb.cb_handles, cb.cb_used, sizeof (void *),
	    libzfs_dataset_cmp);

	/*
	 * And mount all the datasets, keeping track of which ones
	 * succeeded or failed.
	 */
	if ((good = zfs_alloc(zhp->zpool_hdl,
	    cb.cb_used * sizeof (int))) == NULL)
		goto out;

	ret = 0;
	if (n_threads < 2) {
		char mntpnt[MAXPATHLEN];
		char **mntpnts;
		if ((mntpnts = zfs_alloc(zhp->zpool_hdl,
		    cb.cb_used * sizeof (char *))) == NULL) {
			free(good);
			goto out;
		}

		for (i = 0; i < cb.cb_used; i++) {
			verify(zfs_prop_get(cb.cb_handles[i],
			    ZFS_PROP_MOUNTPOINT, mntpnt, sizeof (mntpnt),
			    NULL, NULL, 0, B_FALSE) == 0);
			mntpnts[i] =
			    zfs_strdup(cb.cb_handles[i]->zfs_hdl, mntpnt);

			/* do not attempt to mount if the parent mount failed */
			if (parent_mount_status_serial(i, good, mntpnts)
			    == PARENT_MOUNT_SUCCESS) {
				error =
				    zfs_mount(cb.cb_handles[i], mntopts, flags);
				if (error == 0) {
					good[i] = 1;
				} else if (error != EROFS) {
					ret = -1;
				}
			} else {
				ret = -1;
			}
		}
		for (i = 0; i < cb.cb_used; i++)
			free(mntpnts[i]);
		free(mntpnts);
	} else {
		ret = parallel_mount(&cb, good, mntopts, flags, n_threads);
	}

	/*
	 * Initilialize libshare SA_INIT_SHARE_API_SELECTIVE here
	 * to avoid unneccesary load/unload of the libshare API
	 * per shared dataset downstream.
	 */
	sharearg.zhandle_arr = cb.cb_handles;
	sharearg.zhandle_len = cb.cb_used;
	if (zfs_init_libshare_arg(hdl, SA_INIT_SHARE_API_SELECTIVE, &sharearg)
	    != 0) {
		ret = -1;
		free(good);
		goto out;
	}

	/*
	 * Then share all the ones that need to be shared. This needs
	 * to be a separate pass in order to avoid excessive reloading
	 * of the configuration. Good should never be NULL since
	 * zfs_alloc is supposed to exit if memory isn't available.
	 */
	for (i = 0; i < cb.cb_used; i++) {
		if (good[i] && zfs_share_resume(cb.cb_handles[i]) != 0)
			ret = -1;
	}

	free(good);

out:
	for (i = 0; i < cb.cb_used; i++)
		zfs_close(cb.cb_handles[i]);
	free(cb.cb_handles);

	return (ret);
}

int
zpool_disable_datasets_ex(zpool_handle_t *zhp, boolean_t force, int n_threads)
{
	int used, alloc;
	struct mnttab entry;
	size_t namelen;
	char **mountpoints = NULL;
	zfs_handle_t **datasets = NULL;
	libzfs_handle_t *hdl = zhp->zpool_hdl;
	int i;
	int ret = -1;
	int flags = (force ? MS_FORCE : 0);
	sa_init_selective_arg_t sharearg;

	namelen = strlen(zhp->zpool_name);

	rewind(hdl->libzfs_mnttab);
	used = alloc = 0;
	while (getmntent(hdl->libzfs_mnttab, &entry) == 0) {
		/*
		 * Ignore non-ZFS entries.
		 */
		if (entry.mnt_fstype == NULL ||
		    strcmp(entry.mnt_fstype, MNTTYPE_ZFS) != 0)
			continue;

		/*
		 * Ignore filesystems not within this pool.
		 */
		if (entry.mnt_mountp == NULL ||
		    strncmp(entry.mnt_special, zhp->zpool_name, namelen) != 0 ||
		    (entry.mnt_special[namelen] != '/' &&
		    entry.mnt_special[namelen] != '\0'))
			continue;

		/*
		 * At this point we've found a filesystem within our pool.  Add
		 * it to our growing list.
		 */
		if (used == alloc) {
			if (alloc == 0) {
				if ((mountpoints = zfs_alloc(hdl,
				    8 * sizeof (void *))) == NULL)
					goto out;

				if ((datasets = zfs_alloc(hdl,
				    8 * sizeof (void *))) == NULL)
					goto out;

				alloc = 8;
			} else {
				void *ptr;

				if ((ptr = zfs_realloc(hdl, mountpoints,
				    alloc * sizeof (void *),
				    alloc * 2 * sizeof (void *))) == NULL)
					goto out;
				mountpoints = ptr;

				if ((ptr = zfs_realloc(hdl, datasets,
				    alloc * sizeof (void *),
				    alloc * 2 * sizeof (void *))) == NULL)
					goto out;
				datasets = ptr;

				alloc *= 2;
			}
		}

		if ((mountpoints[used] = zfs_strdup(hdl,
		    entry.mnt_mountp)) == NULL)
			goto out;

		/*
		 * This is allowed to fail, in case there is some I/O error.  It
		 * is only used to determine if we need to remove the underlying
		 * mountpoint, so failure is not fatal.
		 */
		datasets[used] = make_dataset_handle(hdl, entry.mnt_special);

		used++;
	}

	/*
	 * At this point, we have the entire list of filesystems, so sort it by
	 * mountpoint.
	 */
	sharearg.zhandle_arr = datasets;
	sharearg.zhandle_len = used;
	if (zfs_init_libshare_arg(hdl, SA_INIT_SHARE_API_SELECTIVE, &sharearg)
	    != 0) {
		goto out;
	}

	qsort(mountpoints, used, sizeof (char *), mountpoint_compare);

	/*
	 * Walk through and first unshare everything.
	 */
	for (i = 0; i < used; i++) {
		zfs_share_proto_t *curr_proto;
		for (curr_proto = share_all_proto; *curr_proto != PROTO_END;
		    curr_proto++) {
			if (is_shared(hdl, mountpoints[i], *curr_proto) &&
			    zfs_share_suspend(hdl,
			    mountpoints[i], mountpoints[i],
			    *curr_proto) != 0)
				goto out;
		}
	}

	/*
	 * Now unmount everything, removing the underlying directories as
	 * appropriate.
	 */
	if (n_threads < 2) {
		for (i = 0; i < used; i++) {
			if (unmount_one(hdl, mountpoints[i], flags,
			    IGNORE_NO_SUCH_PATH) != 0) {
				goto out;
			}
		}
	} else {
		if (parallel_unmount(hdl, used, (const char **)mountpoints,
		    flags, n_threads) != 0)
			goto out;
	}
	for (i = 0; i < used; i++) {
		if (datasets[i])
			remove_mountpoint(datasets[i]);
	}
	ret = 0;
out:
	for (i = 0; i < used; i++) {
		if (datasets[i])
			zfs_close(datasets[i]);
		free(mountpoints[i]);
	}
	free(datasets);
	free(mountpoints);

	return (ret);
}

/*
 * Mount and share all datasets within the given pool.  This assumes that no
 * datasets within the pool are currently mounted.  Because users can create
 * complicated nested hierarchies of mountpoints, we first gather all the
 * datasets and mountpoints within the pool, and sort them by mountpoint.  Once
 * we have the list of all filesystems, we iterate over them in order and mount
 * and/or share each one.
 */
#pragma weak zpool_mount_datasets = zpool_enable_datasets
int
zpool_enable_datasets(zpool_handle_t *zhp, const char *mntopts, int flags)
{
	return (zpool_enable_datasets_ex(zhp, mntopts, flags, 1));
}

/* alias for 2002/240 */
#pragma weak zpool_unmount_datasets = zpool_disable_datasets
/*
 * Unshare and unmount all datasets within the given pool.  We don't want to
 * rely on traversing the DSL to discover the filesystems within the pool,
 * because this may be expensive (if not all of them are mounted), and can fail
 * arbitrarily (on I/O error, for example).  Instead, we walk /etc/mnttab and
 * gather all the filesystems that are currently mounted.
 */
int
zpool_disable_datasets(zpool_handle_t *zhp, boolean_t force)
{
	return (zpool_disable_datasets_ex(zhp, force, 1));
}
