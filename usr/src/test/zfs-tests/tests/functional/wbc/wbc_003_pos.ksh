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
#	Disabling write back cache succeeds
#
# STRATEGY:
#	1. Create pool with separated special devices and enabled write back cache
#	2. Display pool status
#	3. Disable write back cache
#	4. Display pool status
#	5. Scrub pool and check status
#

verify_runnable "global"
log_assert "Disabling WBC succeeds."
log_onexit cleanup
log_must create_pool_special $TESTPOOL "on"
log_must display_status $TESTPOOL
log_must disable_wbc $TESTPOOL
log_must display_status $TESTPOOL
log_must $SYNC
log_must $ZPOOL scrub $TESTPOOL
while is_pool_scrubbing $TESTPOOL ; do
	$SLEEP 1
done
log_must check_pool_errors $TESTPOOL
log_must destroy_pool $TESTPOOL
log_pass "Disabling WBC succeeds."
