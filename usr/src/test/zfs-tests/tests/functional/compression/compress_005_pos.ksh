#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/compression/compress.cfg

#
# DESCRIPTION:
# Create two files of exactly the same size. Both with enabled
# compression, but the first one with enabled smart-compressiom
# the second one without.
# Ensure the size of both files are the same.
#
# STRATEGY:
# Use "zfs set" to turn on compression. After that use "zfs set"
# to turn on smartcompression and create files before
# and after the second set call. Check the size of files.
#

verify_runnable "both"

log_assert "Ensure that smart compression correctly handles all-zero data"

log_note "Ensure compression is on"
log_must zfs set compression=on $TESTPOOL/$TESTFS

log_note "Ensure smartcompression is off"
log_must zfs set smartcompression=off $TESTPOOL/$TESTFS

log_note "Writing the first file..."
log_must dd if=/dev/zero of=$TESTDIR/$TESTFILE0 bs=1M count=100

log_note "Enable smartcompression"
log_must zfs set smartcompression=on $TESTPOOL/$TESTFS

log_note "Writing the second file..."
log_must dd if=/dev/zero of=$TESTDIR/$TESTFILE1 bs=1M count=100

sleep 60

FILE0_BLKS=`du -k $TESTDIR/$TESTFILE0 | awk '{ print $1}'`
FILE1_BLKS=`du -k $TESTDIR/$TESTFILE1 | awk '{ print $1}'`

if [[ $FILE0_BLKS -ne $FILE1_BLKS ]]; then
	log_fail "The size $TESTFILE0 is not equal the size of $TESTFILE1" \
			"($FILE0_BLKS != $FILE1_BLKS)"
fi

log_pass "The sizes of $TESTFILE0 and $TESTFILE1 are equal ($FILE0_BLKS == $FILE1_BLKS)"
