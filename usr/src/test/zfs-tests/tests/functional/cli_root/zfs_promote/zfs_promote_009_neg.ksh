#! /usr/bin/sh
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
# Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
#


. $STF_SUITE/tests/functional/cli_root/zfs_promote/zfs_promote.cfg
. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#	'zfs promote' should fail for a partially received clone.
#
# STRATEGY:
#	1. Create a tree of datasets with one clone
#	2. Execute 'zfs send' for the tree so that the clone will be partly received
#	3. Promote the clone filesystem
#	4. Verify the promote operation fails because the clone is not fully received
#

verify_runnable "both"

function cleanup
{
	datasetexists $TESTPOOL/a && log_must zfs destroy -r $TESTPOOL/a
	datasetexists $TESTPOOL/b && log_must zfs destroy -r $TESTPOOL/b
}

log_assert "'zfs promote' should fail for a partially received clone."
log_onexit cleanup

log_must zfs create $TESTPOOL/a
log_must zfs create $TESTPOOL/b
log_must zfs set quota=20M $TESTPOOL/b
log_must zfs create $TESTPOOL/a/o1
log_must zfs snapshot $TESTPOOL/a/o1@o1
log_must zfs snapshot -r $TESTPOOL/a@snap1
log_must zfs send -R $TESTPOOL/a@snap1 | zfs recv -u $TESTPOOL/b/a
log_must zfs clone $TESTPOOL/a/o1@o1 $TESTPOOL/a/c1
log_must mkfile 50M /$TESTPOOL/a/c1/$TESTFILE1
log_must zfs snapshot -r $TESTPOOL/a@snap2
log_mustnot zfs send -R -i $TESTPOOL/a@snap1 $TESTPOOL/a@snap2 | zfs recv -us $TESTPOOL/b/a

log_mustnot zfs promote $TESTPOOL/b/a/c1

log_pass "'zfs promote' fails for a partially received clone as expected"
