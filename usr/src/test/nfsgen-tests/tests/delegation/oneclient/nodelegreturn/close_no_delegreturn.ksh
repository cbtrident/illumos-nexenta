#! /usr/bin/ksh -p
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# open a file RDONLY, get read delegation
# then close the file, verify the delegation is not returned

. ${STF_SUITE}/include/nfsgen.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

NAME=$(basename $0)
typeset prog=$STF_SUITE/bin/file_operator

[[ :$_NFS_STF_DEBUG: = *:${NAME}:* \
	|| :${_NFS_STF_DEBUG}: = *:all:* ]] && set -x

function cleanup {
	retcode=$1
	rm -f $MNTDIR/testfile.$$ $STF_TMPDIR/file_operator.outR.$$
	exit $retcode
}

# create test file
RUN_CHECK create_file_nodeleg $MNTDIR/testfile.$$ || cleanup $STF_UNRESOLVED

# save current close op and delegreturn op statistic
prev_close=$(save_rfsreqcntv4 close) || cleanup $STF_UNRESOLVED
prev_delegreturn=$(save_rfsreqcntv4 delegreturn) || cleanup $STF_UNRESOLVED

# read a test file over NFS, check delegation type
$prog -R -c -d -o 0 -B "1 1 -1" $MNTDIR/testfile.$$ \
        > $STF_TMPDIR/file_operator.outR.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/file_operator.outR.$$ \
        | nawk -F\= '{print $2'})

if [[ $deleg_type -ne $RD ]]; then
	print -u2 "unexpected delegation type($deleg_type) when reading file"
        cat $STF_TMPDIR/file_operator.outR.$$
	cleanup $STF_FAIL
fi

# check close op and delegreturn op statistic
RUN_CHECK check_rfsreqcntv4_larger close $prev_close || cleanup $STF_FAIL
RUN_CHECK check_rfsreqcntv4_equal delegreturn $prev_delegreturn \
    || cleanup $STF_FAIL

# clean up 
cleanup $STF_PASS
