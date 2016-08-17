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
# ID: acl_chmod_neg001
#
# DESCRIPTION:
# 	Verify  1) Illegal options to chmod should fail.
#		2) Delete all the ACE will lead to fail.
#		3) Add ACE exceed 1024 will cause to fail.
#
# STRATEGY:
#	1. Loop root and non-root users
#	2. Verify all kinds of illegal option will lead to chmod failed.
#	3. Verify 'chmod A0-' will fail when try to delete all the ACE.
#	4. Verify 'chmod A+' will succeed when the ACE number exceed 1024.
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

echo "ASSERTION: Verify illegal operating to ACL, it will fail."

function err_opts #node
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset A_opts="+A@ -A#- +A% =A^ =A# =A@ +A#\ asd \
			A+@ A-#- A+% A=^ A=# A=@ A+#"
	
	# Illegal option to chmod should fail
	for A in ${A_opts[@]}; do
		RUN_CHECKNEG usr_exec $CHMOD ${A}owner@:read_data:allow $node \
			|| cleanup $STF_FAIL
		RUN_CHECKNEG usr_exec $CHMOD A+ asd owner@:execute:deny $node \
			|| cleanup $STF_FAIL
	done

	typeset type_opts="everyone groups owner user@ users"
	for tp in ${type_opts[@]}; do
		RUN_CHECKNEG usr_exec $CHMOD A+$tp:read_data:deny $node \
			|| cleanup $STF_FAIL
	done

	return 0
}

function del_all_ACE #node
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1
	typeset -i cnt

	eval "cnt=$(count_ACE $node)" || cleanup $STF_FAIL
	while (( cnt > 0 )); do
		if (( cnt == 1 )); then
			RUN_CHECKNEG $CHMOD A0- $node \
				|| cleanup $STF_FAIL
		else
			RUN_CHECK $CHMOD A0- $node \
				|| cleanup $STF_FAIL
		fi

		(( cnt -= 1 ))
	done

	return 0
}

function exceed_max_ACE #node
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1
	typeset -i max=1024
	typeset -i cnt

	eval "cnt=$(count_ACE $node)" || cleanup $STF_FAIL

	# One more ACE exceed the max limitation.
	(( max = max - cnt + 1 ))
	while (( max > 0 )); do
		if (( max == 1 )); then
			RUN_CHECKNEG $CHMOD A+owner@:read_data:allow $node \
				|| cleanup $STF_FAIL
		else
			$CHMOD A+owner@:read_data:allow $node
			if (($? != 0)); then
				((cnt = 1024 - max))
				echo "Add No.$cnt ACL item failed."
				cleanup $STF_FAIL
			fi
		fi

		(( max -= 1 ))
	done

	return 0
}

typeset node
typeset func_name="err_opts del_all_ACE exceed_max_ACE"

for usr in "root" "$ACL_STAFF1"; do
	RUN_CHECK set_cur_usr $usr || cleanup $STF_FAIL
	
	for node in $testfile $testdir; do
		RUN_CHECK usr_exec $TOUCH $testfile || cleanup $STF_FAIL
		RUN_CHECK usr_exec $MKDIR $testdir || cleanup $STF_FAIL

		for func in $func_name; do
			eval "$func $node" || cleanup $STF_FAIL
		done

		RUN_CHECK usr_exec $RM -rf $testfile $testdir \
			|| cleanup $STF_FAIL
	done
done

# Verify illegal operating to ACL passed.
cleanup $STF_PASS
