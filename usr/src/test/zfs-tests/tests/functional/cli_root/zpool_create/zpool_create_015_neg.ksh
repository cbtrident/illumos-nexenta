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
. $STF_SUITE/tests/functional/cli_root/zpool_create/zpool_create.shlib

#
#
# DESCRIPTION:
# 'zpool create' will fail with zfs vol device in swap
#
#
# STRATEGY:
# 1. Create a zpool
# 2. Create a zfs vol on zpool
# 3. Add this zfs vol device to swap
# 4. Try to create a new pool with devices in swap
# 5. Verify the creation is failed.
#

verify_runnable "global"

function cleanup
{
	# cleanup zfs pool and dataset
	if datasetexists $vol_name; then
		swap -l | grep /dev/zvol/dsk/$vol_name > /dev/null 2>&1
		if [[ $? -eq 0 ]]; then
			swap -d /dev/zvol/dsk/${vol_name}
		fi
	fi

	for pool in $TESTPOOL1 $TESTPOOL; do
		if poolexists $pool; then
			destroy_pool $pool
		fi
	done
}

unset NOINUSE_CHECK
if [[ -n $DISK ]]; then
        disk=$DISK
else
        disk=$DISK0
fi

typeset pool_dev=${disk}s${SLICE0}
typeset vol_name=$TESTPOOL/$TESTVOL

log_assert "'zpool create' should fail with zfs vol device in swap."
log_onexit cleanup

#
# use zfs vol device in swap to create pool which should fail.
#
create_pool $TESTPOOL $pool_dev
log_must zfs create -V 100m $vol_name
log_must swap -a /dev/zvol/dsk/$vol_name
for opt in "-n" "" "-f"; do
	log_mustnot zpool create $opt $TESTPOOL1 /dev/zvol/dsk/${vol_name}
done

# cleanup
log_must swap -d /dev/zvol/dsk/${vol_name}
log_must zfs destroy $vol_name
log_must destroy_pool_no_force $TESTPOOL

log_pass "'zpool create' passed as expected with inapplicable scenario."
