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

# the file is designed for "get delegation" tests on multi-clients
# setup. It it called in the following way:
#
#    getdeleg <testfile> <remote_cmd> <local_cmd> <deleg_type>
#
# the script will first create $testfile, and execute $remote_cmd,
# and then execute $local_cmd and verify the expected delegation
# is granted.

. ${STF_SUITE}/include/nfsgen.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

NAME=$(basename $0)
[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
	|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

local_testfile=$1
remote_cmd=$2
local_cmd=$3
dtype=$4
run_remote_on_backgd=$5
typeset pid

function cleanup {
	retcode=$1
	RSH root $CLIENT2 "pkill file_operator"
	rm -f $local_testfile $STF_TMPDIR/local.out.$$ $STF_TMPDIR/$NAME.*
	exit $retcode
}

remote_cmdname=$(echo $remote_cmd | cut -d\  -f1)
remote_cmdname=$(basename $remote_cmdname)

# create test file
RUN_CHECK create_file_nodeleg $local_testfile || cleanup $STF_UNRESOLVED

if (( $run_remote_on_backgd == 1 )); then 
	RSH root $CLIENT2 "$remote_cmd > $SRV_TMPDIR/$NAME.remote_cmd.$$" \
		> $STF_TMPDIR/$NAME.err.$$ 2>&1 &
	pid=$!
	
	# make sure the remote_cmd is ready
	wait_now 100 "RSH root $CLIENT2 grep I_am_ready $SRV_TMPDIR/$NAME.remote_cmd.$$" \
		> /dev/null 2>&1
	if (( $? != 0 )); then
		echo "remote_command failed to be ready within 100 seconds"
		cat $STF_TMPDIR/$NAME.err.$$
		cleanup $STF_FAIL
	fi
else
	RSH root $CLIENT2 "$remote_cmd" 
	if (( $? != 0 )); then
		printf -u2 "failed to execute \"$remoted_cmd\" on $CLIENT2"
		cleanup $STF_FAIL
	fi
fi

# run local comand, verify the expected delegation is granted 
eval $local_cmd > $STF_TMPDIR/local.out.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/local.out.$$ \
        | nawk -F\= '{print $2'})
if [[ $deleg_type -ne $dtype ]]; then
	print -u2 "unexpected delegation type($deleg_type)" 
	cat $STF_TMPDIR/local.out.$$
	cleanup $STF_FAIL
fi

# clean up 
cleanup $STF_PASS
