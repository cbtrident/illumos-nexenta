#! /usr/bin/ksh -p
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2017 Nexenta Systems, Inc. All rights reserved.
#

. $STF_SUITE/tests/functional/wbc/wbc.cfg
. $STF_SUITE/tests/functional/wbc/wbc.kshlib

#
# DESCRIPTION:
#	Special vdev cannot be removed from pool with enabled meta
#	properties or active wbc feature flag. Error message should
#	be more descriptive and precise.
#
# STRATEGY:
#	1. Create pool with mirrored special device.
#	2. Try to remove redundant device from special vdev.
#	3. Verify that 'zpool remove' fails and issue valid error message.
#	4. Create child filesystem.
#	5. Enable wbc for given filesystem.
#	6. Write random data into given filesystem.
#	7. Try to remove mirrored special device.
#	8. Verify that 'zpool remove' fails and issue valid error message.
#	9. Destroy given filesystem.
#	10. Enable meta properties to store pool metadata on special device.
#	11. Create child filesystem.
#	12. Write random data into given filesystem
#	13, Try to remove mirrored special device.
#	14. Verify that 'zpool remove' fails and issue valid error message.
#

typeset cfs="$TESTPOOL/fs.$$"
typeset err="/tmp/err.$$"
typeset disk="$SSD_DISK2"
typeset vdev="mirror-1"
typeset -A msg

msg[ENOTSUP]="cannot remove $disk: operation not supported on this type of pool"
msg[EBUSY]="cannot remove $vdev: wbc feature flag is active"
msg[EEXIST]="cannot remove $vdev: special device contains metadata"

function random_data
{
	typeset dst=$1
	typeset dir=$(get_prop mountpoint $dst)
	typeset bs=$(get_random_recordsize)
	typeset count=$(( RANDOM % 16 + 1 ))

	if [[ -z "$dir" ]]; then
		log_fail "unable to get mountpoint for '$dst'"
	fi

	log_must eval "dd if=/dev/urandom of=$dir/file.$$ bs=$bs count=$count"
}

verify_runnable "global"
log_assert "Verify that 'zpool remove' fails and issue valid error message."
log_onexit cleanup
log_must create_pool_special $TESTPOOL "none" "raidz" "mirror"
log_mustnot eval "zpool remove $TESTPOOL $disk 2>$err"
log_must grep "^${msg[ENOTSUP]}$" $err
log_must zfs create $cfs
log_must set_wbc_mode $cfs "on"
random_data $cfs
log_mustnot eval "zpool remove $TESTPOOL "$vdev" 2>$err"
log_must grep "^${msg[EBUSY]}$" $err
log_must zfs destroy -Rf $cfs
log_must zfs create $cfs
log_must zpool set meta_placement=on $TESTPOOL
log_must zpool set zfs_meta_to_metadev=on $TESTPOOL
random_data $cfs
log_mustnot eval "zpool remove $TESTPOOL "$vdev" 2>$err"
log_must grep "^${msg[EEXIST]}$" $err
log_must rm -f $err
log_must destroy_pool $TESTPOOL
log_pass "'zpool remove' fails as expected with valid error message."
