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
# if 'align' property is not specified zfs_default_ashift is used to set
# pool and leaf vdev ashift
#
# STRATEGY:
# 1. Create a pool, without specifying align property
# 2. Verify that the zfs_default_ashift is used to set pool minimum ashift
# 3. Verify that leaf vdev's ashift >= pool minimum
# 4. Verify that changing zfs_default_ashift does not affect existing pool
#

function cleanup
{
	poolexists testpool && destroy_pool testpool
	rm -f $filevdev
	mdb -kwe "zfs_default_ashift/W $zfs_default_ashift"
}

log_onexit cleanup

log_assert "if 'align' not specified zfs_default_ashift used to set ashift"

typeset disk=$(echo $DISKS | awk '{print $1}')
typeset filevdev=/var/tmp/filevdev.txt
typeset zfs_default_ashift=0x$(mdb -ke "zfs_default_ashift /X" \
    | awk 'NR==2{print $NF}')
typeset expected_ashift=$(($zfs_default_ashift))

log_must mkfile 128M $filevdev

for dev in $disk $filevdev
do
	log_must zpool create testpool $dev
	log_must check_pool_ashift testpool $expected_ashift
	log_must check_vdev_ashift $dev $expected_ashift

	log_must mdb -kwe "zfs_default_ashift/W 9"
	log_must check_pool_ashift testpool $expected_ashift
	log_must check_vdev_ashift $dev $expected_ashift

	log_must mdb -kwe "zfs_default_ashift/W $zfs_default_ashift"
	log_must zpool destroy testpool
done

rm -f $filevdev

log_pass "if 'align' not specified zfs_default_ashift used to set ashift"
