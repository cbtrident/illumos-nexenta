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

# the file is designed for "no claim_deleg_cur" tests. It is
# called in the following way: 
# 
#   nodelegclaim <testfile> <cmd1> <deleg_type1> <cmd2> <deleg_type2> \
#       <remote_cmd>
#
# the script will first create $testfile, and then execute $cmd1
# and verify the expected delegation type, and then execute $cmd2 and
# verify the expected delegation type. Then it runs a remote command 
# on client B and verifies it triger delegation callback. Then it checks
# there is no claim_deleg_cur. 

. ${STF_SUITE}/include/nfsgen.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

NAME=$(basename $0)
[[ :$_NFS_STF_DEBUG: = *:${NAME}:* \
	|| :${_NFS_STF_DEBUG}: = *:all:* ]] && set -x

function cleanup {
	retcode=$1
	pkill file_operator
	rm -f $testfile $STF_TMPDIR/$NAME.cmd.*
	exit $retcode
}

testfile=$1
cmd1=$2
dtype1=$3
cmd2=$4
dtype2=$5
remote_cmd=$6
typeset pid

# create test file
RUN_CHECK create_file_nodeleg $testfile || cleanup $STF_UNRESOLVED

# run command 1, check delegation type
eval $cmd1 > $STF_TMPDIR/$NAME.cmd.1.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/$NAME.cmd.1.$$ \
        | nawk -F\= '{print $2'})
if [[ $deleg_type -ne $dtype1 ]]; then
	print -u2 "unexpected delegation type($deleg_type) when reading file"
	cat $STF_TMPDIR/$NAME.cmd.1.$$
	cleanup $STF_FAIL
fi

# save current open and close statistic
prev_claim=$(save_nfs4callback claim_cur) || cleanup $STF_UNRESOLVED

# run command 2, check delegation type
eval $cmd2 > $STF_TMPDIR/$NAME.cmd.2.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/$NAME.cmd.2.$$ \
        | nawk -F\= '{print $2'})
if [[ $deleg_type -ne $dtype2 ]]; then
        print -u2 "unexpected delegation type($deleg_type) when reading file"
	cat $STF_TMPDIR/$NAME.cmd.2.$$
        cleanup $STF_FAIL
fi

# save current delegreturn op statistic
prev_delegreturn=$(save_rfsreqcntv4 delegreturn) || cleanup $STF_UNRESOLVED

# execute command 2 on 2nd client
RSH root $CLIENT2 "$remote_cmd" > $STF_TMPDIR/$NAME.cmd.3.$$ 2>&1
if (( $? != 0 )); then
	printf -u2 "failed to execute \"$remoted_cmd\" on $CLIENT2"
	cat $STF_TMPDIR/$NAME.cmd.3.$$
	cleanup $STF_FAIL
fi


# check delegreturn op statistic
RUN_CHECK check_rfsreqcntv4_larger delegreturn $prev_delegreturn \
    || cleanup $STF_FAIL

# check open and close op statistic
RUN_CHECK check_nfs4callback_equal claim_cur $prev_claim || cleanup $STF_FAIL

# clean up 
cleanup $STF_PASS
