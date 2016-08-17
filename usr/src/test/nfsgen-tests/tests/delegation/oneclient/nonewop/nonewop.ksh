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

# the file is designed for "no OTW operation" tests. It is called
# in the following way:
#
#    nonewop <testfile> <cmd1> <deleg_type1> <cmd2> <deleg_type2>
#
# the script will first create $testfile, and then execute $cmd1
# to get expected $deleg_type1, and then execute $cmd2 to get
# expected $deleg_type2. It verifies $cmd2 won't cause new OPEN
# or CLOSE operations.

. ${STF_SUITE}/include/nfsgen.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

NAME=$(basename $0)

[[ :$_NFS_STF_DEBUG: = *:${NAME}:* \
	|| :${_NFS_STF_DEBUG}: = *:all:* ]] && set -x

function cleanup {
	retcode=$1
	rm -f $testfile $STF_TMPDIR/local.out.*
	exit $retcode
}

testfile=$1
cmd1=$2
dtype1=$3
cmd2=$4
dtype2=$5

# create test file
RUN_CHECK create_file_nodeleg $testfile || cleanup $STF_UNRESOLVED

# run command 1, check delegation type
eval $cmd1 > $STF_TMPDIR/local.out.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/local.out.$$ \
        | nawk -F\= '{print $2'})
if [[ $deleg_type -ne $dtype1 ]]; then
	print -u2 "unexpected delegation type($deleg_type)"
	cat $STF_TMPDIR/local.out.$$
	cleanup $STF_FAIL
fi

# save current open and close statistic
prev_open=$(save_rfsreqcntv4 open) || cleanup $STF_UNRESOLVED
prev_close=$(save_rfsreqcntv4 close) || cleanup $STF_UNRESOLVED

# run command 2, check delegation type
i=0
while ((i < 6)); do
	eval $cmd2 > $STF_TMPDIR/local.out.$$ 2>&1
	deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/local.out.$$ \
    	    | nawk -F\= '{print $2'})
	if [[ $deleg_type -ne $dtype2 ]]; then
        	print -u2 "unexpected delegation type($deleg_type)" 
		cat $STF_TMPDIR/local.out.$$
        	cleanup $STF_FAIL
	fi
	i=$((i + 1))
done

# check open and close op statistic
RUN_CHECK check_rfsreqcntv4_equal open $prev_open || cleanup $STF_FAIL
RUN_CHECK check_rfsreqcntv4_equal close $prev_close || cleanup $STF_FAIL

# clean up 
cleanup $STF_PASS
