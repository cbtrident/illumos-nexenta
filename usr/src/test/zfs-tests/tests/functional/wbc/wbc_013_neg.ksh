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
# Copyright 2016 Nexenta Systems, Inc. All rights reserved.
#

. $STF_SUITE/tests/functional/wbc/wbc.cfg
. $STF_SUITE/tests/functional/wbc/wbc.kshlib

#
# DESCRIPTION:
#	Do not allow to add special to the old-version pools (<= 28)
#
# STRATEGY:
#	1. Create pool with version 28 and try to add a special vdev to it
#	2. Try to create pool with version 28 and special vdev
#

verify_runnable "global"
log_assert "Special vdev cannot be added to the old-version pools"
log_onexit cleanup

for special_type in "stripe" "mirror" ; do
	log_must $ZPOOL create -f -o version=28 $TESTPOOL $HDD_DISKS

	if [[ $special_type == "stripe" ]] ; then
		log_mustnot $ZPOOL add -f $TESTPOOL special $SSD_DISKS
	else
		log_mustnot $ZPOOL add -f $TESTPOOL special $special_type $SSD_DISKS
	fi
	
	log_must display_status $TESTPOOL
	log_must $SYNC
	log_must $ZPOOL scrub $TESTPOOL
	while is_pool_scrubbing $TESTPOOL ; do
		$SLEEP 1
	done

	log_must check_pool_errors $TESTPOOL
	log_must destroy_pool $TESTPOOL
done

for special_type in "stripe" "mirror" ; do
	if [[ $special_type == "stripe" ]] ; then
		special_type=""
	fi

	log_mustnot $ZPOOL create -f -o version=28 $TESTPOOL $HDD_DISKS special $special_type $SSD_DISKS
	
	log_must display_status $TESTPOOL
	log_must $SYNC
	log_must $ZPOOL scrub $TESTPOOL
	while is_pool_scrubbing $TESTPOOL ; do
		$SLEEP 1
	done

	log_must check_pool_errors $TESTPOOL
	log_must destroy_pool $TESTPOOL
done

log_pass "Special vdev cannot be added to the old-version pools"
