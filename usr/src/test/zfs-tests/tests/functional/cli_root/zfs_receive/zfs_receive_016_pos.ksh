#! /usr/bin/ksh
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
# Copyright 2016 Nexenta Systems, Inc.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#	Verifying 'zfs receive <cloned_dataset>' works.
#
# STRATEGY:
#	1. Create source filesystem 'src'.
#	2. Source filesystem: take the recursive snapshot 'snap1'.
#	3. Source filesystem: send initial recursive replication stream
#	   from the snapshot 'snap1'.
#	4. Destination filesystem: receive initial replication stream from the
#	   source snapshot 'snap1'.
#	5. Source filesystem: take the recursive snapshot 'snap2'.
#	6. Source filesystem: send incremental recursive replication stream
#	   from snapshot 'snap1' to snapshot 'snap2'.
#	7. Destination filesystem: receive incremental replication stream.
#	8. Destination filesystem: create a clone 'clone' of the snapshot
#	   'snap1'.
#	9. Destination filesystem: promote cloned filesystem.
#	10. Source filesystem: take the recursive snapshot 'snap3'.
#	11. Source filesystem: send incremental recursive replication stream
#	    from snapshot 'snap2' to snapshot 'snap3'.
#	12. Destination filesystem: receive incremental replication stream.
#	13. Destination filesystem: verify the receiving results.
#

verify_runnable "both"

typeset streamfile=/var/tmp/streamfile.$$
typeset dataset=$TESTPOOL/$TESTFS

function cleanup
{
	log_must rm $streamfile
	log_must zfs destroy -rf $dataset/src
	log_must zfs destroy -rf $dataset/clone
	log_must zfs destroy -rf $dataset/dst
}

log_assert "Verifying 'zfs receive <cloned_dataset>' works."
log_onexit cleanup

log_must zfs create $dataset/src
log_must zfs snapshot -r $dataset/src@snap1
log_must zfs send -R $dataset/src@snap1 > $streamfile
log_must zfs receive $dataset/dst < $streamfile
log_must zfs snapshot -r $dataset/src@snap2
log_must zfs send -R -I $dataset/src@snap1 $dataset/src@snap2 > $streamfile
log_must zfs receive $dataset/dst < $streamfile
log_must zfs clone $dataset/dst@snap1 $dataset/clone
log_must zfs promote $dataset/clone
log_must zfs snapshot -r $dataset/src@snap3
log_must zfs send -R -I $dataset/src@snap2 $dataset/src@snap3 > $streamfile
log_must zfs receive $dataset/dst < $streamfile

log_pass "Verifying 'zfs receive <cloned_dataset>' works."
