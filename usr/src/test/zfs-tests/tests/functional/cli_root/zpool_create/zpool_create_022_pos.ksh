#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zfs_create/zfs_create_common.kshlib

#
# DESCRIPTION:
# 'zpool create -O property=value pool' can successfully create a pool
# with multiple filesystem properties set.
#
# STRATEGY:
# 1. Create a storage pool with multiple -O options
# 2. Verify the pool created successfully
# 3. Verify the properties are correctly set
#

verify_runnable "global"

function cleanup
{
	datasetexists $TESTPOOL && log_must destroy_pool_no_force $TESTPOOL
}

log_onexit cleanup

log_assert "'zpool create -O property=value pool' can successfully create a pool \
		with multiple filesystem properties set."

set -A RW_FS_PROP "quota=512M" \
		  "reservation=512M" \
		  "recordsize=64K" \
		  "mountpoint=/tmp/mnt$$" \
		  "checksum=fletcher2" \
		  "compression=lzjb" \
		  "atime=off" \
		  "devices=off" \
		  "exec=off" \
		  "setuid=off" \
		  "readonly=on" \
		  "snapdir=visible" \
		  "aclmode=discard" \
		  "aclinherit=discard" \
		  "canmount=off" \
		  "sharenfs=on"

typeset -i i=0
typeset opts=""

while (( $i < ${#RW_FS_PROP[*]} )); do
	opts="$opts -O ${RW_FS_PROP[$i]}"
	(( i = i + 1 ))
done

log_must zpool create $opts -f $TESTPOOL $DISKS
datasetexists $TESTPOOL || log_fail "zpool create $TESTPOOL fail."

i=0
while (( $i < ${#RW_FS_PROP[*]} )); do
	propertycheck $TESTPOOL ${RW_FS_PROP[i]} || \
			log_fail "${RW_FS_PROP[i]} is failed to set."
	(( i = i + 1 ))
done

log_pass "'zpool create -O property=value pool' can successfully create a pool \
		with multiple filesystem properties set."

