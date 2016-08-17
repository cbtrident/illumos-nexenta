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

. $STF_SUITE/tests/acl/acl_common.kshlib

#################################################################################
#
# __stc_assertion_start
#
# ID: acl_chmod_rwx_pos001
#
# DESCRIPTION:
#	chmod A{+|-|=} have the correct behaviour to the ACL list. 	
#
# STRATEGY:
#	1. loop check root and non-root users
#	2. chmod file or dir with specified options
#	3. get ACE after behaviours of chmod
#	4. compare specified ACE and excpect ACE
#
# TESTABILITY: explicit
#
# TEST_AUTOMATION_LEVEL: automated
#
# __stc_assertion_end
#
################################################################################

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& set -x

echo "ASSERTION: chmod A{+|-|=} have the correct behaviour to the ACL list."

typeset -i trival_count=6 head=0 mid end
((mid = RANDOM % $trival_count))
((end = trival_count - 1))

opts="+ - ="
nums="$head $mid $end"
set -A file_ACEs \
	"user:$ACL_STAFF1:read_data:allow" \
	"user:$ACL_STAFF2:write_data:allow" \
	"user:$ACL_OTHER1:execute:allow"
set -A dir_ACEs \
	"user:$ACL_STAFF1:list_directory/read_data:allow" \
	"user:$ACL_STAFF2:add_file/write_data:allow" \
	"user:$ACL_OTHER1:execute:allow"

function test_chmod_ACE_list #$opt $num $ace-spec $node
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset opt=A$2$1
	typeset -i num=$2
	typeset ace=$3
	typeset node=$4
	typeset -i expect_count=0

	# Get expect ACE count
	case $opt in
		A[0-9]*+) (( expect_count = trival_count + 1 )) ;;
		A[0-9]*-) (( expect_count = trival_count - 1 )) ;;
		A[0-9]*=) (( expect_count = trival_count )) ;;
		*) echo "Error option: '$opt'" && cleanup $STF_FAIL ;;
	esac

	# Invoke chmod A[number]{+|-|=}<acl-specification> file|dir
	if [[ $opt == A[0-9]*+ || $opt == A[0-9]*= ]]; then
		RUN_CHECK usr_exec $CHMOD "$opt$ace" "$node" \
			|| cleanup $STF_FAIL
	else
		RUN_CHECK usr_exec $CHMOD "$opt" "$node" \
			|| cleanup $STF_FAIL
	fi

	# Get the current ACE count and specified ACE
	typeset cur_ace cur_count
	eval "cur_ace=$(get_ACE $node $num)" || cleanup $STF_FAIL
	eval "cur_count=$(count_ACE $node)" || cleanup $STF_FAIL

	# Compare with expected results
	if [[ $opt == A[0-9]*+ || $opt == A[0-9]*= ]]; then
		if [[ "$num:$ace" != "$cur_ace" ]]; then
			echo "FAIL: $CHMOD $opt$ace $node"
			cleanup $STF_FAIL
		fi
	fi
	if [[ "$expect_count" != "$cur_count" ]]; then
		echo "FAIL: '$expect_count' != '$cur_count'"
		cleanup $STF_FAIL
	fi
}

for user in root $ACL_STAFF1 $ACL_OTHER1; do
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	for opt in $opts; do
		for num in $nums; do
			for ace in $file_ACEs; do
				# ls -l $TESTDIR
				RUN_CHECK usr_exec $TOUCH $testfile \
					|| cleanup $STF_FAIL
				test_chmod_ACE_list $opt $num $ace $testfile
				RUN_CHECK $RM -f $testfile || cleanup $STF_FAIL
			done
			for ace in $dir_ACEs; do
				# ls -l $TESTDIR
				RUN_CHECK usr_exec $MKDIR -p $testdir \
					|| cleanup $STF_FAIL
				test_chmod_ACE_list $opt $num $ace $testdir
				RUN_CHECK $RM -rf $testdir || cleanup $STF_FAIL
			done
		done
	done
done	

# chmod A{+|-|=} behave to the ACL list passed.
cleanup $STF_PASS
