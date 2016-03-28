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
#	Remove special vdev succeeds
#
# STRATEGY:
#	1. Create pool
#	2. Display pool status, check 'enablespecial' and 'feature@meta_devices'
#	3. Add special vdev
#	2. Display pool status, check 'enablespecial' and 'feature@meta_devices'
#	3. Remove special vdev
#	4. Display pool status, check 'enablespecial' and 'feature@meta_devices'
#	5. Scrub pool and check status
#

function check_props_without_special
{
	RESULT=$(get_pool_prop "enablespecial" $TESTPOOL)
	if [[ $RESULT != "off" ]]
	then
		log_fail "Property 'enablespecial' must be 'off'"
	fi

	RESULT=$(get_pool_prop "feature@meta_devices" $TESTPOOL)
	if [[ $RESULT != "enabled" ]]
	then
		log_fail "Feature flag 'meta_devices' must be 'enabled'"
	fi
}

function check_props_with_special
{
	RESULT=$(get_pool_prop "enablespecial" $TESTPOOL)
	if [[ $RESULT != "on" ]]
	then
		log_fail "Property 'enablespecial' must be 'on'"
	fi

	RESULT=$(get_pool_prop "feature@meta_devices" $TESTPOOL)
	if [[ $RESULT != "active" ]]
	then
		log_fail "Feature flag 'meta_devices' must be 'active'"
	fi
}

verify_runnable "global"
log_assert "Removing special vdev succeeds."
log_onexit cleanup
log_must create_pool $TESTPOOL
log_must display_status $TESTPOOL
log_must check_props_without_special
log_must $ZPOOL add -f $TESTPOOL special $SSD_DISK1
log_must display_status $TESTPOOL
log_must check_props_with_special
log_must $ZPOOL remove $TESTPOOL $SSD_DISK1
log_must display_status $TESTPOOL
log_must check_props_without_special
log_must $ZPOOL scrub $TESTPOOL
while is_pool_scrubbing $TESTPOOL ; do
	$SLEEP 1
done
log_must check_pool_errors $TESTPOOL
log_must destroy_pool $TESTPOOL
log_pass "Removing special vdev succeeds."
