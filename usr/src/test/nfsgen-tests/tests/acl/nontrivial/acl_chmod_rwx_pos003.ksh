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
# ID: acl_chmod_rwx_pos003
#
# DESCRIPTION:
#	Verify that the read_data/write_data/execute permission for 
#	owner/group/everyone are correct.
#
# STRATEGY:
#	1. Loop root and non-root user.
#	2. Separated verify type@:access:allow|deny to file and directory
#	3. To super user, read and write deny was override.
#	4. According to ACE list and override rule, expect that 
#	   read/write/execute file or directory succeed or fail.
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

#	owner@		group_users		other_users
set -A users \
	"root" 		"$ACL_ADMIN" 	"$ACL_OTHER1" \
	"$ACL_STAFF1" "$ACL_STAFF2" 	"$ACL_OTHER1"

# In order to test execute permission, read_data was need firstly.
set -A a_access "read_data" "write_data" "read_data/execute"
set -A a_flag "owner@" "group@" "everyone@"

echo "ASSERTION: Verify that the read_data/write_data/execute permission for" \
	"owner/group/everyone are correct."

if [[ -n $ZONE_PATH ]]; then
        echo "\n\tThe test runs in TX configuration, we don't verify"
        echo "\texecute permission on a directory as a regular user.\n"
fi

function logname #node acl_spec user
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1
	typeset acl_spec=$2
	typeset user=$3

	# To super user, read and write deny permission was override.
	if [[ $acl_spec == *:allow ]] || \
		[[ $user == root && -d $node ]] || \
		[[ $user == root && $acl_spec != *"execute"* ]]
	then
		print "RUN_CHECK"
	elif [[ $acl_spec == *:deny ]]; then
		print "RUN_CHECKNEG"
	fi
}

function check_chmod_results #node acl_spec g_usr o_usr
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1
	typeset acl_spec=$2
	typeset g_usr=$3
	typeset o_usr=$4
	typeset log

	# In the following condition, rwx_node() calls 'find' to verify
	# execute permission. But 'find' can not get current working
	# directory in TX env if the user is a regular user, which has
	# has no permission to access zone path.
	if [[ $g_usr != root ]] && [[ -n $ZONE_PATH ]] \
	    && [[ -d $node ]] && [[ $acl_spec == *execute* ]]; then
		return
	fi 
	if [[ $acl_spec == "owner@:"* || $acl_spec == "everyone@:"* ]]; then
		log=$(logname $node $acl_spec $ACL_CUR_USER)
		$log rwx_node $ACL_CUR_USER $node $acl_spec \
			> $STF_TMPDIR/$NAME.$$ 2>&1 \
			|| cleanup $STF_FAIL $STF_TMPDIR/$NAME.$$
	fi
	if [[ $acl_spec == "group@:"* || $acl_spec == "everyone@:"* ]]; then
		log=$(logname $node $acl_spec $g_usr)
		$log rwx_node $g_usr $node $acl_spec \
			> $STF_TMPDIR/$NAME.$$ 2>&1 \
			|| cleanup $STF_FAIL $STF_TMPDIR/$NAME.$$
	fi
	if [[ $acl_spec == "everyone@"* ]]; then
		log=$(logname $node $acl_spec $o_usr)
		$log rwx_node $o_usr $node $acl_spec \
			> $STF_TMPDIR/$NAME.$$ 2>&1 \
			|| cleanup $STF_FAIL $STF_TMPDIR/$NAME.$$
	fi
}

function test_chmod_basic_access #node group_user other_user
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1
	typeset g_usr=$2
	typeset o_usr=$3
	typeset flg access acl_spec

	for flg in ${a_flag[@]}; do
		for access in ${a_access[@]}; do
			for tp in allow deny; do
				acl_spec="$flg:$access:$tp"
				RUN_CHECK usr_exec $CHMOD A+$acl_spec $node \
					|| cleanup $STF_FAIL
				check_chmod_results \
					$node $acl_spec $g_usr $o_usr
				RUN_CHECK usr_exec $CHMOD A0- $node \
					|| cleanup $STF_FAIL
			done
		done	
	done
}

typeset -i i=0
while (( i < ${#users[@]} )); do
	RUN_CHECK set_cur_usr ${users[i]} || cleanup $STF_FAIL

	RUN_CHECK usr_exec $TOUCH $testfile || cleanup $STF_FAIL
	test_chmod_basic_access $testfile ${users[((i+1))]} ${users[((i+2))]}
	RUN_CHECK usr_exec $MKDIR $testdir || cleanup $STF_FAIL
	test_chmod_basic_access $testdir ${users[((i+1))]} ${users[((i+2))]}

	RUN_CHECK usr_exec $RM -rf $testfile $testdir || cleanup $STF_FAIL

	(( i += 3 ))
done

# Verify that the read_data/write_data/execute permission for
# owner/group/everyone passed.
cleanup $STF_PASS
