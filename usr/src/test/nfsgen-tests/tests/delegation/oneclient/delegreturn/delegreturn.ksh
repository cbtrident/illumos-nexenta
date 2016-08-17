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

# the file is designed to test delegation return. It it called
# in the following way:
#
#    delegreturn <testfile> <cmd1> <deleg_type> <cmd2>
#
# the script will first create $testfile, and then execute $cmd1
# to get the expected delegation type, and then execute $cmd2 and
# check if delegation is returned.

. ${STF_SUITE}/include/nfsgen.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
	|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

function Cleanup {
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
		|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

	retcode=$1
	mount -p | grep $SERVER | grep $SHRDIR >/dev/null
	if [[ $? != 0 && -n $realMNT ]]; then
		RUN_CHECK mount -o $MNTOPT $SERVER:$SHRDIR $realMNT || \
	    	    echo "Warning: re-mount <$SERVER:$SHRDIR $realMNT> failed"
	fi

	cleanup $retcode "" "$testfile $STF_TMPDIR/*.err.$$, $STF_TMPDIR/local.*"
}

testfile=$1
cmd1=$2
dtype=$3
cmd2=$4
run_directly=$5

[[ -n $run_directly ]] || run_directly=1

# save the realMNT info if any
echo "$cmd2" | grep "umount" > /dev/null 2>&1
(( $? == 0 )) && realMNT=$(echo $cmd2 | awk '{print $NF}')

# create test file
if [[ $testfile != NOT_NEEDED ]]; then
	RUN_CHECK create_file_nodeleg $testfile || Cleanup $STF_UNRESOLVED
fi

# run command 1, check delegation type
if (( $run_directly == 1 )); then
	eval $cmd1
	deleg_type=$?
else
	eval $cmd1 > $STF_TMPDIR/local.out.$$ 2>&1
	deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/local.out.$$ \
       		| nawk -F\= '{print $2'})
fi
if [[ $deleg_type -ne $dtype ]]; then
	print -u2 "unexpected delegation type($deleg_type)" 
	(( $run_directly != 1 )) && cat $STF_TMPDIR/local.out.$$
	Cleanup $STF_FAIL
fi

# save current delegreturn op statistic
prev_delegreturn=$(save_rfsreqcntv4 delegreturn) || Cleanup $STF_UNRESOLVED

# run command 2
RUN_CHECK $cmd2 || Cleanup $STF_UNRESOLVED 

# check delegreturn op statistic
RUN_CHECK check_rfsreqcntv4_larger delegreturn $prev_delegreturn \
    || Cleanup $STF_FAIL

# Clean up 
Cleanup $STF_PASS
