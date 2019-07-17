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
# 'align' property is used to set pool and leaf vdev ashift
#
# STRATEGY:
# 1. Create a pool
# 2. Verify that the align property is used to set pool minimum ashift
# 3. Verify that leaf vdev's ashift >= pool minimum
#

function cleanup
{
	poolexists testpool && destroy_pool testpool
	rm -f $filevdev
}

log_onexit cleanup

log_assert "'align' property is used to set pool and leaf vdev ashift"

typeset disk=$(echo $DISKS | awk '{print $1}')

filevdev=/var/tmp/filevdev.txt
log_must mkfile 128M $filevdev
typeset align=64K
typeset expected_ashift=16

for dev in $disk $filevdev
do
	log_must zpool create -o align=$align testpool $dev

	log_must check_pool_ashift testpool $expected_ashift
	log_must check_vdev_ashift $dev $expected_ashift

	log_must zpool destroy testpool
done

rm -f $filevdev

log_pass "'align' property is used to set pool and leaf vdev ashift"
