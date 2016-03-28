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
#	A raidz special can not be added to existing pool
#
# STRATEGY:
#	1. Create pool without separated special devices
#	2. Try to add a raidz special to this pool
#	3. Verify failed to add
#

verify_runnable "global"
log_assert "A raidz special can not be added to existing pool."
log_onexit cleanup
for pool_type in "stripe" "mirror" ; do
	for special_type in "raidz" "raidz2" "raidz3" ; do
		log_must create_pool $TESTPOOL $pool_type
		log_mustnot $ZPOOL add $TESTPOOL special $special_type $SSD_DISKS
		log_must destroy_pool $TESTPOOL
	done
done
log_pass "A raidz special can not be added to existing pool."
