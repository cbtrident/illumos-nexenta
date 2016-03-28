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
#	Attaching special vdev succeeds
#
# STRATEGY:
#	1. Create pool without separated special devices
#	2. Display pool status
#	3. Add special device
#	4. Display pool status
#	5. Try to attach new special device
#	6. Display pool status
#	7. Scrub pool and check status
#

verify_runnable "global"
log_assert "Attaching special vdev succeeds."
log_onexit cleanup
for wbc_mode in "on" "off" ; do
	log_must create_pool $TESTPOOL $pool_type
	log_must display_status $TESTPOOL
	log_must $ZPOOL add -f $TESTPOOL special $SSD_DISK1
	log_must set_wbc_mode $TESTPOOL $wbc_mode
	log_must display_status $TESTPOOL
	log_must $ZPOOL attach $TESTPOOL $SSD_DISK1 $SSD_DISK2
	log_must display_status $TESTPOOL
	while is_pool_resilvering $TESTPOOL ; do
		$SLEEP 1
	done
	log_must $ZPOOL scrub $TESTPOOL
	while is_pool_scrubbing $TESTPOOL ; do
		$SLEEP 1
	done
	log_must check_pool_errors $TESTPOOL
	log_must destroy_pool $TESTPOOL
done
log_pass "Attaching special vdev succeeds."
