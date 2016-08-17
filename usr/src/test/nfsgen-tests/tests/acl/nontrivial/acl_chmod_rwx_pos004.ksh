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
# ID: acl_chmod_rwx_pos004
#
# DESCRIPTION:
#	Verify that explicit ACL setting to specified user or group will
#	override existed access rule.
#
# STRATEGY:
#	1. Loop root and non-root user.
#	2. Loop the specified access one by one.
#	3. Loop verify explicit ACL set to specified user and group.
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

function check_access #log user node access rflag
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset log=$1
	typeset user=$2
	typeset node=$3
	typeset access=$4
	typeset rflag=$5

	if [[ $rflag == "allow" && $access == execute ]]; then
		rwx_node $user $node $access > $STF_TMPDIR/$NAME.$$ 2>&1
		#
		# When everyone@ were deny, this file can't execute.
		# So,'cannot execute' means user has the permission to
		# execute, just the file can't be execute.
		#
		if [[ $ACL_ERR_STR != *"cannot execute"* ]]; then
			echo "FAIL: rwx_node $user $node $access"
			cleanup $STF_FAIL $STF_TMPDIR/$NAME.$$
		fi
	else
		$log rwx_node $user $node $access \
			> $STF_TMPDIR/$NAME.$$ 2>&1 \
			|| cleanup $STF_FAIL $STF_TMPDIR/$NAME.$$
	fi
}

function verify_explicit_ACL_rule #node access flag
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	set -A a_access "read_data" "write_data" "execute"
	typeset node=$1
	typeset access=$2
	typeset flg=$3 
	typeset log rlog rflag

	# Get the expect log check
	if [[ $flg == allow ]]; then
		log=RUN_CHECKNEG
		rlog=RUN_CHECK
		rflag=deny
	else
		log=RUN_CHECK
		rlog=RUN_CHECKNEG
		rflag=allow
	fi

	# rwx_node() calls 'find' to verify execute permission on a directory,
	# in TX env, a regular user has no permission to access zone path.
	# in the case, skip.
	if [[ -n $ZONE_PATH ]] && [[ $access == *execute* ]] && [[ -d $node ]]; then
		return
	fi

	RUN_CHECK usr_exec $CHMOD A+everyone@:$access:$flg $node \
		|| cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A+user:$ACL_OTHER1:$access:$rflag $node \
		|| cleanup $STF_FAIL
	check_access $log $ACL_OTHER1 $node $access $rflag || cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A0- $node || cleanup $STF_FAIL

	RUN_CHECK usr_exec \
		$CHMOD A+group:$ACL_OTHER_GROUP:$access:$rflag $node \
		|| cleanup $STF_FAIL
	check_access $log $ACL_OTHER1 $node $access $rflag || cleanup $STF_FAIL
	check_access $log $ACL_OTHER2 $node $access $rflag || cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A0- $node || cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A0- $node || cleanup $STF_FAIL

	RUN_CHECK usr_exec \
		$CHMOD A+group:$ACL_OTHER_GROUP:$access:$flg $node \
		|| cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A+user:$ACL_OTHER1:$access:$rflag $node \
		|| cleanup $STF_FAIL
	$log rwx_node $ACL_OTHER1 $node $access \
		> $STF_TMPDIR/$NAME.$$ 2>&1 \
		|| cleanup $STF_FAIL $STF_TMPDIR/$NAME.$$
	$rlog rwx_node $ACL_OTHER2 $node $access \
		> $STF_TMPDIR/$NAME.$$ 2>&1 \
		|| cleanup $STF_FAIL $STF_TMPDIR/$NAME.$$
	RUN_CHECK usr_exec $CHMOD A0- $node || cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A0- $node || cleanup $STF_FAIL
}

echo "ASSERTION: Verify that explicit ACL setting to specified user or group will" \
	"override existed access rule."

if [[ -n $ZONE_PATH ]]; then 
	echo "\n\tThe test runs in TX configuration, we don't verify" 
	echo "\texecute permission on a directory.\n"
fi

set -A a_access "read_data" "write_data" "execute"
set -A a_flag "allow" "deny"
typeset node

for user in root $ACL_STAFF1; do
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	RUN_CHECK usr_exec $TOUCH $testfile || cleanup $STF_FAIL
	RUN_CHECK usr_exec $MKDIR $testdir || cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD 755 $testfile $testdir || cleanup $STF_FAIL

	for node in $testfile $testdir; do
		for access in ${a_access[@]}; do
			for flg in ${a_flag[@]}; do
				verify_explicit_ACL_rule $node $access $flg
			done
		done
	done

	RUN_CHECK usr_exec $RM -rf $testfile $testdir || cleanup $STF_FAIL
done

# Explicit ACL setting to specified user or group will override 
# existed access rule passed.
cleanup $STF_PASS
