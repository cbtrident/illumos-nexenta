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

# the file is designed for "no delegationreturn" tests on multi-clients
# setup. It it called in the following way:
#
#    nodelegreturn <testfile> <local_cmd> <deleg_type> <remote_cmd>
#
# the script will first create $testfile, and then execute $local_cmd
# to get the expected delegation type, and then execute $remote_cmd
# and verify delegation isn't returned.

. ${STF_SUITE}/include/nfsgen.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

NAME=$(basename $0)
[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
	|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

function cleanup {
	retcode=$1
	rm -f $local_testfile $STF_TMPDIR/local.*
	exit $retcode
}

local_testfile=$1
local_cmd=$2
dtype=$3
remote_cmd=$4

# create test file
RUN_CHECK create_file_nodeleg $local_testfile || cleanup $STF_UNRESOLVED

# execute command 1, check delegation type
eval $local_cmd > $STF_TMPDIR/local.out.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/local.out.$$ \
        | nawk -F\= '{print $2'})
if [[ $deleg_type -ne $dtype ]]; then
	print -u2 "unexpected deleg type($deleg_type) after running $local_cmd"
	cat $STF_TMPDIR/local.out.$$
	cleanup $STF_FAIL
fi

# save current delegreturn op statistic
prev_delegreturn=$(save_rfsreqcntv4 delegreturn) || cleanup $STF_UNRESOLVED

# execute command 2 on 2nd client
RSH root $CLIENT2 "$remote_cmd"
if (( $? != 0 )); then
	printf -u2 "failed to execute \"$remoted_cmd\" on $CLIENT2"
	cleanup $STF_FAIL
fi

# check delegreturn op statistic
RUN_CHECK check_rfsreqcntv4_equal delegreturn $prev_delegreturn \
    || cleanup $STF_FAIL

# clean up 
cleanup $STF_PASS
