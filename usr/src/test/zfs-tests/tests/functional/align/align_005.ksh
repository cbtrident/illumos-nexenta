#! /usr/bin/ksh
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
# Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/align/align.kshlib

#
# DESCRIPTION:
#
# 'align' property is used to set leaf vdev ashift on add, attach, replace
#
# STRATEGY:
# 1. Create a pool
# 2. Attach a device and check that new vdev's ashift is set correctly
# 3. Replace a device and check that new vdev's ashift is set correctly
# 4. Add a device and check that new vdev's ashift is set correctly
#

function cleanup
{
	poolexists testpool && destroy_pool testpool
	rm -f $filevdev1
	rm -f $filevdev2
}

log_onexit cleanup

#
# S1, S2: two devices which are compatible for mirroring.
#
function do_test
{
	dev1=$1
	dev2=$2

	# create pool and check pool and device ashift
	log_must zpool create -o align=$align testpool $dev1
	log_must check_pool_ashift testpool $expected_ashift
	log_must check_vdev_ashift $dev1 $expected_ashift

	# attach second device and check its ashift
	log_must zpool attach testpool $dev1 $dev2
	log_must check_vdev_ashift $dev2 $expected_ashift
	log_must wait_for_resilver testpool
	log_must zpool detach testpool $dev2

	# replace first device with second device and check its ashift
	zpool replace testpool $dev1 $dev2
	log_must check_vdev_ashift $dev2 $expected_ashift
	log_must wait_for_resilver testpool

	# add second device and check its ashift
	log_must zpool add testpool $dev1
	log_must check_vdev_ashift $dev1 $expected_ashift

	log_must destroy_pool testpool
	return 0
}

log_assert "'align' property is used to set vdev ashift on add, attach, replace"
typeset align=16K
typeset expected_ashift=14
typeset filevdev1=/var/tmp/filevdev1
typeset filevdev2=/var/tmp/filevdev2
typeset disk1=$(echo $DISKS | awk '{print $1}')
typeset disk2=$(echo $DISKS | awk '{print $2}')
log_must mkfile 64M $filevdev1
log_must mkfile 64M $filevdev2

log_must do_test $filevdev1 $filevdev2
log_must do_test $disk1 $disk2

rm -f $filevdev1
rm -f $filevdev2
log_pass "'align' property is used to set vdev ashift on add, attach, replace"
