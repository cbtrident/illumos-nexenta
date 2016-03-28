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
#	Write back cache can not be deactivated during the creation of the pool
#
# STRATEGY:
#	1. Try to create pool with wbc_mode=off
#	2. Creating pool must fail
#

verify_runnable "global"
log_assert "Write back cache can not be deactivated during the creation of the pool."
log_onexit cleanup
for pool_type in "stripe" "mirror" ; do
	for special_type in "stripe" "mirror" ; do
		log_mustnot create_pool_special $TESTPOOL "off" $pool_type $special_type
	done
done
log_pass "Write back cache can not be deactivated during the creation of the pool."
