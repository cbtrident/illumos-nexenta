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
# ID: acl_chmod_rwacl_pos001
#
# DESCRIPTION:
#	Verify assigned read_acl/write_acl to owner@/group@/everyone@,
#	specificied user and group. File have the correct access permission.
#
# STRATEGY:
#	1. Separatedly verify file and directory was assigned read_acl/write_acl
#	   by root and non-root user.
#	2. Verify owner always can read and write acl, even deny.
#	3. Verify group access permission, when group was assigned 
#	   read_acl/write_acl.
#	4. Verify access permission, after everyone was assigned read_acl/write.
#	5. Verify everyone@ was deny except specificied user, this user can read
#	   and write acl.
#	6. Verify the group was deny except specified user, this user can read
#	   and write acl
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

function case_cleanup
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	[[ $1 != $STF_PASS ]] && [[ -f $STF_TMPDIR/$NAME.$$ ]] \
		&& cat $STF_TMPDIR/$NAME.$$
	rm -rf $STF_TMPDIR/$NAME.$$.*

	# restore the mount option and enable attribute cache
	cd $CWD
	RUN_CHECK do_remount 
	[[ -n $1 ]] && cleanup $1 || return 0
}

echo "ASSERTION: Verify chmod A[number]{+|-|=} read_acl/write_acl have correct " \
	"behaviour to access permission."

function read_ACL #<node> <user1> <user2> ... 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1
	typeset user
	typeset -i ret

	shift
	for user in $@; do
		RUN_CHECK chgusr_exec $user $LS -vd $node \
			> $STF_TMPDIR/$NAME.$$ 2>&1
		ret=$?
		(( ret != 0 )) && return $ret

		shift
	done

	return 0
}

function write_ACL #<node> <user1> <user2> ... 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1
	typeset user
	typeset -i ret before_cnt after_cnt

	shift
	for user in "$@"; do
		before_cnt=$(count_ACE $node)
		ret=$?; 
		(( ret != 0 )) && return $ret

		RUN_CHECK chgusr_exec $user $CHMOD A0+owner@:read_data:allow $node
		ret=$?
		(( ret != 0 )) && return $ret

		after_cnt=$(count_ACE $node)
		ret=$?
		(( ret != 0 )) && return $ret

		RUN_CHECK chgusr_exec $user $CHMOD A0- $node
		ret=$?
		(( ret != 0 )) && return $ret
		
		if (( after_cnt - before_cnt != 1 )); then
			return 1
		fi

		shift
	done

	return 0
}

function check_owner #<node>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1

	for acc in allow deny; do
		RUN_CHECK usr_exec \
			$CHMOD A0+owner@:read_acl/write_acl:$acc $node \
			|| case_cleanup $STF_FAIL
		RUN_CHECK read_ACL $node $ACL_CUR_USER \
			|| case_cleanup $STF_FAIL
		RUN_CHECK write_ACL $node $ACL_CUR_USER \
			|| case_cleanup $STF_FAIL
		RUN_CHECK usr_exec $CHMOD A0- $node || case_cleanup $STF_FAIL
	done
}

function check_group #<node>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1

	typeset grp_usr=""
	if [[ $ACL_CUR_USER == root ]]; then
		grp_usr=$ACL_ADMIN
	elif [[ $ACL_CUR_USER == $ACL_STAFF1 ]]; then
		grp_usr=$ACL_STAFF2
	fi
		
	RUN_CHECK usr_exec $CHMOD A0+group@:read_acl/write_acl:allow $node \
		|| case_cleanup $STF_FAIL
	RUN_CHECK read_ACL $node $grp_usr || case_cleanup $STF_FAIL
	RUN_CHECK write_ACL $node $grp_usr || case_cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A0- $node || case_cleanup $STF_FAIL

	RUN_CHECK usr_exec $CHMOD A0+group@:read_acl/write_acl:deny $node \
		|| case_cleanup $STF_FAIL
	RUN_CHECKNEG read_ACL $node $grp_usr || case_cleanup $STF_FAIL
	RUN_CHECKNEG write_ACL $node $grp_usr || case_cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A0- $node || case_cleanup $STF_FAIL
}

function check_everyone #<node>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1

	typeset flag
	for flag in allow deny; do
		if [[ $flag == allow ]]; then
			log=RUN_CHECK
		else
			log=RUN_CHECKNEG
		fi

		RUN_CHECK usr_exec \
			$CHMOD A0+everyone@:read_acl/write_acl:$flag $node \
			|| case_cleanup $STF_FAIL

		eval $log read_ACL $node $ACL_OTHER1 $ACL_OTHER2 \
			|| case_cleanup $STF_FAIL
		eval $log write_ACL $node $ACL_OTHER1 $ACL_OTHER2 \
			|| case_cleanup $STF_FAIL

		RUN_CHECK usr_exec $CHMOD A0- $node || case_cleanup $STF_FAIL
	done
}

function check_spec_user #<node>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1

	RUN_CHECK usr_exec $CHMOD A0+everyone@:read_acl/write_acl:deny $node \
		|| case_cleanup $STF_FAIL
	RUN_CHECK usr_exec \
		$CHMOD A0+user:$ACL_OTHER1:read_acl/write_acl:allow $node \
		|| case_cleanup $STF_FAIL

	# The specified user can read and write acl
	RUN_CHECK read_ACL $node $ACL_OTHER1 || case_cleanup $STF_FAIL
	RUN_CHECK write_ACL $node $ACL_OTHER1 || case_cleanup $STF_FAIL

	# All the other user can't read and write acl
	RUN_CHECKNEG \
		read_ACL $node $ACL_ADMIN $ACL_STAFF2 $ACL_OTHER2 \
		|| case_cleanup $STF_FAIL
	RUN_CHECKNEG \
		write_ACL $node $ACL_ADMIN $ACL_STAFF2 $ACL_OTHER2 \
		|| case_cleanup $STF_FAIL

	RUN_CHECK usr_exec $CHMOD A0- $node || case_cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A0- $node || case_cleanup $STF_FAIL
}

function check_spec_group #<node>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1

	RUN_CHECK usr_exec $CHMOD A0+everyone@:read_acl/write_acl:deny $node \
		|| case_cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD \
		A0+group:$ACL_OTHER_GROUP:read_acl/write_acl:allow $node \
		|| case_cleanup $STF_FAIL
	
	# The specified group can read and write acl
	RUN_CHECK read_ACL $node $ACL_OTHER1 $ACL_OTHER2 \
		|| case_cleanup $STF_FAIL
	RUN_CHECK write_ACL $node $ACL_OTHER1 $ACL_OTHER2 \
		|| case_cleanup $STF_FAIL

	# All the other user can't read and write acl
	RUN_CHECKNEG read_ACL $node $ACL_ADMIN $ACL_STAFF2 \
		|| case_cleanup $STF_FAIL
	RUN_CHECKNEG write_ACL $node $ACL_ADMIN $ACL_STAFF2 \
		|| case_cleanup $STF_FAIL
}

function check_user_in_group #<node>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1

	RUN_CHECK usr_exec $CHMOD \
		A0+group:$ACL_OTHER_GROUP:read_acl/write_acl:deny $node \
		|| case_cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD \
		A0+user:$ACL_OTHER1:read_acl/write_acl:allow $node \
		|| case_cleanup $STF_FAIL
	RUN_CHECK read_ACL $node $ACL_OTHER1 || case_cleanup $STF_FAIL
	RUN_CHECK write_ACL $node $ACL_OTHER1 || case_cleanup $STF_FAIL
	RUN_CHECKNEG read_ACL $node $ACL_OTHER2 || case_cleanup $STF_FAIL
	RUN_CHECKNEG write_ACL $node $ACL_OTHER2 || case_cleanup $STF_FAIL

	RUN_CHECK usr_exec $CHMOD A0- $node || case_cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A0- $node || case_cleanup $STF_FAIL
}

# This case needs to disable the attribute cache.
cd /
RUN_CHECK do_remount noac || case_cleanup $STF_FAIL

# use relative path, TX doesn't allow a regular user access zone path.
cd $MNTDIR
set -A func_name check_owner \
		check_group \
		check_everyone \
		check_spec_user \
		check_spec_group \
		check_user_in_group

for user in root $ACL_STAFF1; do
	RUN_CHECK set_cur_usr $user || case_cleanup $STF_FAIL

	RUN_CHECK usr_exec $TOUCH $testfile || case_cleanup $STF_FAIL
	RUN_CHECK usr_exec $MKDIR $testdir || case_cleanup $STF_FAIL

	typeset func node
	for func in ${func_name[@]}; do
		for node in $testfile $testdir; do
			eval $func \$node
		done
	done

	RUN_CHECK usr_exec $RM -rf $testfile $testdir || case_cleanup $STF_FAIL
done

# Verify chmod A[number]{+|-|=} read_data/write_data passed.
case_cleanup $STF_PASS
