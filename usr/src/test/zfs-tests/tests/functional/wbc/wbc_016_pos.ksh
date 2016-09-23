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
#	Removing writecached datasets should decrement feature@wbc refcounter
#
# STRATEGY:
#	1. Create pool with separated special devices and disabled write back cache
#	2. Display pool status
#	3. Create a filesystem
#	4. Check that "feature@wbc" is "enabled".
#	5. Enable write back cache for the created filesystem
#	6. Check that "feature@wbc" is "active"
#	7. Display pool status
#	8. Scrub pool and check status
#	9. Destroy the created filesystem
#	11. Check that "feature@wbc" is "enabled".
#

function check_feature_wbc_enabled
{
	log_must eval "$ZPOOL get feature@wbc $TESTPOOL > /tmp/value.$$"
	$GREP "enabled" /tmp/value.$$ > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		log_fail "feature@wbc is not 'enabled'"
	fi
}

function check_feature_wbc_active
{
	log_must eval "$ZPOOL get feature@wbc $TESTPOOL > /tmp/value.$$"
	$GREP "active" /tmp/value.$$ > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		log_fail "feature@wbc is not 'active'"
	fi
}

verify_runnable "global"
log_assert "Enabling WBC succeeds."
log_onexit cleanup
log_must create_pool_special $TESTPOOL "none"
log_must display_status $TESTPOOL

log_must $ZFS create $TESTPOOL/wbc
datasetexists $TESTPOOL/wbc || \
	log_fail "zfs create $TESTPOOL/wbc fail."

check_feature_wbc_enabled
log_must enable_wbc $TESTPOOL/wbc
check_feature_wbc_active

log_must display_status $TESTPOOL
log_must $SYNC
log_must $ZPOOL scrub $TESTPOOL
while is_pool_scrubbing $TESTPOOL ; do
	$SLEEP 1
done
log_must check_pool_errors $TESTPOOL

log_must $ZFS destroy -rR $TESTPOOL/wbc
datasetnonexists $TESTPOOL/wbc || \
	log_fail "zfs destroy -rR $TESTPOOL/wbc fail."

check_feature_wbc_enabled

log_must display_status $TESTPOOL
log_must $SYNC
log_must $ZPOOL scrub $TESTPOOL
while is_pool_scrubbing $TESTPOOL ; do
	$SLEEP 1
done
log_must check_pool_errors $TESTPOOL

log_must destroy_pool $TESTPOOL
log_pass "Enabling WBC succeeds."
