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
#	Enabling write back cache succeeds
#
# STRATEGY:
#	1. Create pool with separated special devices and disabled write back
#	   cache
#	2. Display pool status
#	3. Enable write back cache
#	4. Display pool status
#	5. Scrub pool and check status
#

verify_runnable "global"
log_assert "Enabling WBC succeeds."
log_onexit cleanup
log_must create_pool_special $TESTPOOL "none"
log_must display_status $TESTPOOL
log_must enable_wbc $TESTPOOL
log_must display_status $TESTPOOL
log_must sync
log_must zpool scrub $TESTPOOL
while is_pool_scrubbing $TESTPOOL ; do
	sleep 1
done
log_must check_pool_errors $TESTPOOL
log_must destroy_pool $TESTPOOL
log_pass "Enabling WBC succeeds."
