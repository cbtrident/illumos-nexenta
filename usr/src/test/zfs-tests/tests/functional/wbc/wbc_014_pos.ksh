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
#	Setting sync_to_special to valid value should succeed.
#
# STRATEGY:
#	1. Create pool with special devices.
#	2. Setting different valid sync_to_special property.
#	3. Check the return value and make sure it is 0.
#

verify_runnable "global"
log_assert "Setting sync_to_special to valid value should succeed."
log_onexit cleanup
log_must create_pool_special $TESTPOOL
log_must display_status $TESTPOOL

for sync_to_special in "disabled" "standard" "balanced" "always"; do
	log_must set_pool_prop "sync_to_special" $sync_to_special $TESTPOOL
done

log_pass "Setting a valid sync_to_special property on a pool succeeds."
