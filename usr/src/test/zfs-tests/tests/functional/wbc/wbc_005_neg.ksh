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
#	Write back cache can not be deactivated for child dataset
#
# STRATEGY:
#	1. Create pool with separated special devices and enabled write back cache
#	2. Display pool status
#	3. Create child dataset
#	4. Try to disable write back cache for child dataset
#

verify_runnable "global"
log_assert "Write back cache can not be deactivated for child dataset."
log_onexit cleanup
log_must create_pool_special $TESTPOOL "on"
log_must display_status $TESTPOOL
log_must create_dataset $TESTPOOL/child_dataset
log_mustnot disable_wbc $TESTPOOL/child_dataset
log_pass "Write back cache can not be deactivated for child dataset."
