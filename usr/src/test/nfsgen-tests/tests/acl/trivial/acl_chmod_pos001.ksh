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
# ID: acl_chmod_001_pos
#
# DESCRIPTION:
#	Verify chmod permission settings on files and directories, as both root
#	and non-root users.
#
# STRATEGY:
#	1. Loop root and $ACL_STAFF1 as root and non-root users.
#	2. Create test file and directory in exported filesystem.
#	3. Execute 'chmod' with specified options.
#	4. Check 'ls -l' output and compare with expect results.
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

# 	"init_map" "options" "expect_map"
set -A argv \
	"000" "a+rw"	"rw-rw-rw-" 	"000" "a+rwx"	"rwxrwxrwx" \
	"000" "u+xr"	"r-x------"	"000" "gu-xw"	"---------" \
	"644" "a-r"	"-w-------"	"644" "augo-x"	"rw-r--r--" \
	"644" "=x"	"--x--x--x"	"644" "u-rw"	"---r--r--" \
	"644" "uo+x"	"rwxr--r-x"	"644" "ga-wr"	"---------" \
	"777" "augo+x"	"rwxrwxrwx"	"777" "go-xr"	"rwx-w--w-" \
	"777" "o-wx"	"rwxrwxr--" 	"777" "ou-rx"	"-w-rwx-w-" \
	"777" "a+rwx"	"rwxrwxrwx"	"777" "u=rw"	"rw-rwxrwx" \
	"000" "123"	"--x-w--wx"	"000" "412"	"r----x-w-" \
	"231" "562"	"r-xrw--w-"	"712" "000"	"---------" \
	"777" "121"	"--x-w---x"	"123" "775"	"rwxrwxr-x"

echo "ASSERTION: Verify chmod permission settings on files and directories"

#
# Verify file or directory have correct map after chmod 
#
# $1 file or directory
#
function test_chmod_mapping #<file-dir>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1
	typeset -i i=0

	while (( i < ${#argv[@]} )); do
		usr_exec $CHMOD ${argv[i]} $node
		if (($? != 0)); then
			echo "usr_exec $CHMOD ${argv[i]} $node"
			return 1
		fi

		usr_exec $CHMOD ${argv[((i + 1))]} $node
		if (($? != 0)); then
			echo "usr_exec $CHMOD ${argv[((i + 1))]} $node"
			return 1
		fi

		typeset mode
		eval "mode=$(get_mode ${node})"

		if [[ $mode != "-${argv[((i + 2))]}"* && \
			$mode != "d${argv[((i + 2))]}"* ]]
		then
			echo "FAIL: '${argv[i]}' '${argv[((i + 1))]}' \
				'${argv[((i + 2))]}'"
			cleanup $STF_FAIL
		fi

		(( i += 3 ))
	done

	return 0
}

for user in root $ACL_STAFF1; do
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	# Test file
	RUN_CHECK usr_exec $TOUCH $testfile || cleanup $STF_FAIL
	RUN_CHECK test_chmod_mapping $testfile || cleanup $STF_FAIL

	RUN_CHECK $CHMOD A+user:$ACL_STAFF2:write_acl:allow $testfile \
		|| cleanup $STF_FAIL
	RUN_CHECK set_cur_usr $ACL_STAFF2 || cleanup $STF_FAIL

	# Test directory
	RUN_CHECK usr_exec $MKDIR $testdir || cleanup $STF_FAIL
	RUN_CHECK test_chmod_mapping $testdir || cleanup $STF_FAIL

	# Grant privileges of write_acl and retest the chmod commands.

	RUN_CHECK usr_exec $CHMOD A+user:$ACL_STAFF2:write_acl:allow $testfile \
		|| cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD A+user:$ACL_STAFF2:write_acl:allow $testdir \
		|| cleanup $STF_FAIL
	
	RUN_CHECK set_cur_usr $ACL_STAFF2 || cleanup $STF_FAIL
	RUN_CHECK test_chmod_mapping $testfile || cleanup $STF_FAIL
	RUN_CHECK test_chmod_mapping $testdir || cleanup $STF_FAIL

	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	RUN_CHECK usr_exec $RM $testfile || cleanup $STF_FAIL
	RUN_CHECK usr_exec $RM -rf $testdir || cleanup $STF_FAIL
done

cleanup $STF_PASS
