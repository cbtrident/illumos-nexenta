#!/bin/ksh -p
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

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#       Verifying 'zfs receive -x <property>' works.
#
# STRATEGY:
#	1. Create source filesystem 'src'.
#	2. Source filesystem: change the default value for the compression
#          property.
#       3. Source filesystem: take the recursive snapshot 'snap1'.
#	4. Source filesystem: send initial recursive replication stream
#	   from the snapshot 'snap1'.
#	5. Destination filesystem: receive initial replication stream from the
#	   source snapshot 'snap1', excluding compression property.
#	8. Destination filesystem: verify that the compression properties has
#          a default value.
#

verify_runnable "both"

typeset streamfile=/var/tmp/streamfile.$$
typeset dataset=$TESTPOOL/$TESTFS
typeset prop_name=compression
typeset prop_value=on
typeset prop_source=default

function cleanup
{
	log_must $RM $streamfile
	log_must $ZFS destroy -rf $dataset/src
	log_must $ZFS destroy -rf $dataset/dst
}

log_assert "Verifying 'zfs receive -x <property>' works."
log_onexit cleanup

log_must $ZFS create $dataset/src
log_must $ZFS set $prop_name=$prop_value $dataset/src
log_must $ZFS snapshot -r $dataset/src@snap1
log_must $ZFS send -R $dataset/src@snap1 > $streamfile
log_must $ZFS receive -x $prop_name $dataset/dst < $streamfile

typeset src_value=$($ZFS get -H -o source $prop_name $dataset/dst)
if [[ "$src_value" != "$prop_source" ]] ; then
	log_fail "The '$dataset/dst' '$prop_name' source '$src_value' " \
	         "not equal to the expected value '$prop_source'"
fi

log_pass "Verifying 'zfs receive -x <property>' works."
