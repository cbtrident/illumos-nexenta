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
#	'zfs recv -F' destroy snapshots and file systems that do not
#	exist on the sending side.
#
# STRATEGY:
#	1. Create source filesystem.
#	2. Source filesystem: create child filesystems 'fs1', 'fs2'
#	   and take the recursive snapshot 'snap1'.
#	3. Source filesystem: send initial recursive replication stream
#	   from snapshot 'snap1'.
#	4. Destination filesystem: receive initial replication stream from
#	   source snapshot 'snap1'.
#	5. Source filesystem: take recursive snapshot 'snap2'.
#	6. Source filesystem: send incremental recursive replication stream
#	   from snapshot 'snap1' to snapshot 'snap2'.
#	7. Destination filesystem: receive incremental replication stream.
#	8. Destination filesystem: make sure that child filesystems 'fs1' and
#	   'fs2' and their recursive snapshots 'snap1' and 'snap2' are exists.
#	9. Source filesystem: create child filesystem 'fs3' and take recursive
#	   snapshot 'snap3'.
#	10. Source filesystem: recursively destroy snapshot 'snap1'.
#	11. Source filesystem: recursively destroy filesystem 'fs1'.
#	12. Source filesystem: send incremental recursive replication stream
#	    from snapshot 'snap2' to snapshot 'snap3'.
#	13. Destination filesystem: force receive (-F) incremental replication
#	    stream.
#	14. Destination filesystem: make sure that only child filesystems
#	    'fs2', 'fs3' and recursive snapshots 'snap2' and 'snap3' are exists.
#

verify_runnable "both"

typeset streamfile=/var/tmp/streamfile.$$
typeset dataset=$TESTPOOL/$TESTFS

function cleanup
{
	log_must rm $streamfile
	log_must zfs destroy -rf $dataset/src
	log_must zfs destroy -rf $dataset/dst
}


log_assert "'zfs receive -F' destroy snapshots and file systems that do not " \
	"exist on the sending side."
log_onexit cleanup

log_must zfs create $dataset/src
log_must zfs create $dataset/src/fs1
log_must zfs create $dataset/src/fs2
log_must zfs snapshot -r $dataset/src@snap1
log_must zfs send -R $dataset/src@snap1 > $streamfile
log_must zfs receive $dataset/dst < $streamfile

log_must zfs snapshot -r $dataset/src@snap2
log_must zfs send -R -I $dataset/src@snap1 $dataset/src@snap2 > $streamfile
log_must zfs receive $dataset/dst < $streamfile
log_must zfs list $dataset/dst/fs1@snap1
log_must zfs list $dataset/dst/fs1@snap2
log_must zfs list $dataset/dst/fs2@snap1
log_must zfs list $dataset/dst/fs2@snap2

log_must zfs create $dataset/src/fs3
log_must zfs snapshot -r $dataset/src@snap3
log_must zfs destroy -r $dataset/src@snap1
log_must zfs destroy -r $dataset/src/fs1
log_must zfs send -R -I $dataset/src@snap2 $dataset/src@snap3 > $streamfile
log_must zfs receive -F $dataset/dst < $streamfile
log_must zfs list $dataset/dst/fs2@snap2
log_must zfs list $dataset/dst/fs2@snap3
log_must zfs list $dataset/dst/fs3@snap3
log_mustnot zfs list $dataset/dst/fs1
log_mustnot zfs list $dataset/dst/fs2@snap1

log_pass "Verifying 'zfs receive -F' succeeds."
