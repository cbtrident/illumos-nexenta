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
# use of zfs_default_ashift constrained to valid values: 0, 9-20
#
# STRATEGY:
# 1. Create a pool, without specifying align property
# 2. Verify that if zfs_default_ashift is ZERO,
#    pool minimum ashift is set to ZERO
# 3. Verify that if zfs_default_ashift is < MIN_ASHIFT,
#    pool minimum ashift is set to MIN_ASHIFT
# 4. Verify that if zfs_default_ashift is > MAX_ASHIFT,
#    pool minimum ashift is set to MAX_ASHIFT
#

function cleanup
{
	poolexists testpool && destroy_pool testpool
	rm -f $filevdev
	mdb -kwe "zfs_default_ashift/W $zfs_default_ashift"
}

log_onexit cleanup

log_assert "use of zfs_default_ashift constrained to valid values: 0, 9-20"

# MIN_ASHIFT & MAX_ASHIFT should correspond to SPA_ASHIFT_MIN & SPA_ASHIFT_MAX
typeset MIN_ASHIFT=9
typeset MAX_ASHIFT=20
typeset zfs_default_ashift=0x$(mdb -ke "zfs_default_ashift /X" \
    | awk 'NR==2{print $NF}')

function constrain_ashift
{
	if [[ $1 == 0 ]]; then
		echo 0
	elif [[ $1 -le $MIN_ASHIFT ]]; then
		echo $MIN_ASHIFT
	elif [[ $1 -ge $MAX_ASHIFT ]]; then
   		echo $MAX_ASHIFT
	else
		echo $1
	fi
	return 0
}

filevdev=/var/tmp/filevdev.txt
log_must mkfile 128M $filevdev

for val in 0 $MIN_ASHIFT $((MIN_ASHIFT-1)) $MAX_ASHIFT $((MAX_ASHIFT+1))
do
	typeset test_ashift=$(echo "obase=16; $val" |bc)
	typeset expected_ashift=$(constrain_ashift $val)

	log_must mdb -kwe "zfs_default_ashift/W $test_ashift"
	log_must zpool create testpool $filevdev
	log_must check_pool_ashift testpool $expected_ashift
	log_must destroy_pool testpool
done

rm -f $filevdev
mdb -kwe "zfs_default_ashift/W $zfs_default_ashift"
log_pass "use of zfs_default_ashift constrained to valid values: 0, 9-20"
