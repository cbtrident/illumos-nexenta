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

################################################################################
#
# __stc_assertion_start
#
# ID: acl_mv_pos001
#
# DESCRIPTION:
# Verify that '/usr/bin/mv' supports NFSv4 ACL
#
# STRATEGY:
# 1. Create file and  directory in nfs filesystem
# 2. Set special ACE to the file and directory
# 3. Copy the file/directory to another directory
# 4. Verify that the ACL of file/directroy is not changed
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

	(( ${#cwd} != 0 )) && cd $cwd
	(( ${#mask} != 0 )) && RUN_CHECK $UMASK $mask
	cleanup $1
}

function testing_mv #<flag for file|dir> <file1|dir1> <file2|dir2>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset flag=$1
	set -A obj $2 $3
	typeset -i i=0
	typeset orig_acl=""
	typeset orig_mode=""
	typeset dst_acl=""
	typeset dst_mode=""

	if [[ $flag == "f" ]]; then	
	while (( i < ${#obj[*]} ))
	do	
		orig_acl="$(get_acl ${obj[i]})"	|| case_cleanup $STF_FAIL
		orig_mode="$(get_mode ${obj[i]})" || case_cleanup $STF_FAIL
		if (( i < 1 )); then
			RUN_CHECK $MV ${obj[i]} $dst_file \
				|| case_cleanup $STF_FAIL
			dst_acl=$(get_acl $dst_file) || case_cleanup $STF_FAIL
			dst_mode=$(get_mode $dst_file) || case_cleanup $STF_FAIL
		else
			RUN_CHECK $MV ${obj[i]} $TESTDIR1 || case_cleanup $STF_FAIL
			dst_acl=$(get_acl $TESTDIR1/${obj[i]}) \
				|| case_cleanup $STF_FAIL
			dst_mode=$(get_mode $TESTDIR1/${obj[i]}) \
				|| case_cleanup $STF_FAIL
		fi
			
		if [[ "$dst_mode" != "$orig_mode" ]] || \
			[[ "$dst_acl" != "$orig_acl" ]]; then
			echo "$MV fails to keep the acl for file."
			case_cleanup $STF_FAIL
		fi
			
		(( i = i + 1 ))
	done
	else
	while (( i < ${#obj[*]} ))
	do
		typeset orig_nested_acl=""
		typeset orig_nested_mode=""
		typeset dst_nested_acl=""
		typeset dst_nested_mode=""

		orig_acl=$(get_acl ${obj[i]}) || case_cleanup $STF_FAIL
		orig_mode=$(get_mode ${obj[i]}) || case_cleanup $STF_FAIL
		orig_nested_acl=$(get_acl ${obj[i]}/$nestedfile) \
			|| case_cleanup $STF_FAIL
		orig_nested_mode=$(get_mode ${obj[i]}/$nestedfile) \
			|| case_cleanup $STF_FAIL
		if (( i < 1 )); then
			RUN_CHECK $MV ${obj[i]} $dst_dir \
				|| case_cleanup $STF_FAIL
			dst_acl=$(get_acl $dst_dir) || case_cleanup $STF_FAIL
			dst_mode=$(get_mode $dst_dir) || case_cleanup $STF_FAIL
			dst_nested_acl=$(get_acl $dst_dir/$nestedfile) \
				|| case_cleanup $STF_FAIL
			dst_nested_mode=$(get_mode $dst_dir/$nestedfile) \
				|| case_cleanup $STF_FAIL
		else
			RUN_CHECK $MV ${obj[i]} $TESTDIR1 \
				|| case_cleanup $STF_FAIL
			dst_acl=$(get_acl $TESTDIR1/${obj[i]}) \
				|| case_cleanup $STF_FAIL
			dst_mode=$(get_mode $TESTDIR1/${obj[i]}) \
				|| case_cleanup $STF_FAIL
			dst_nested_acl=$(get_acl \
				$TESTDIR1/${obj[i]}/$nestedfile) \
				|| case_cleanup $STF_FAIL
			dst_nested_mode=$(get_mode \
				$TESTDIR1/${obj[i]}/$nestedfile) \
				|| case_cleanup $STF_FAIL
		fi
			
		if [[ "$orig_mode" != "$dst_mode" ]] || \
		   [[ "$orig_acl" != "$dst_acl" ]] || \
		   [[ "$dst_nested_mode" != "$orig_nested_mode" ]] || \
		   [[ "$dst_nested_acl" != "$orig_nested_acl" ]]; then	
			echo "$MV fails to recursively keep the acl for " \
				"directory." 
			case_cleanup $STF_FAIL
		fi
			
		(( i = i + 1 ))
	done
	fi
}

echo "ASSERTION: Verify that '$MV' supports NFSv4 ACLs."

spec_ace="everyone@:execute:allow" 
set -A orig_file "origfile1.$$" "origfile2.$$"
set -A orig_dir "origdir1.$$" "origdir2.$$"
nestedfile="nestedfile.$$"
dst_file=dstfile.$$
dst_dir=dstdir.$$ 
cwd=$PWD
mask=`$UMASK`
$UMASK 0022

#
# This assertion should only test 'mv' within the same filesystem
#
TESTDIR1=$MNTDIR/$TESTDIR/testdir1$$

if [[ ! -d $TESTDIR1 ]]; then
	RUN_CHECK $MKDIR -p $TESTDIR1 || case_cleanup $STF_FAIL
fi

# Create files and directories and set special ace on them for testing.
cd $TESTDIR
typeset -i i=0
while (( i < ${#orig_file[*]} ))
do
	RUN_CHECK $TOUCH ${orig_file[i]} || case_cleanup $STF_FAIL
	RUN_CHECK $CHMOD A0+$spec_ace ${orig_file[i]} || case_cleanup $STF_FAIL

	(( i = i + 1 ))
done
i=0
while (( i < ${#orig_dir[*]} ))
do
	RUN_CHECK $MKDIR ${orig_dir[i]} || case_cleanup $STF_FAIL
	RUN_CHECK $TOUCH ${orig_dir[i]}/$nestedfile || case_cleanup $STF_FAIL

	for obj in ${orig_dir[i]} ${orig_dir[i]}/$nestedfile; do
		RUN_CHECK $CHMOD A0+$spec_ace $obj || case_cleanup $STF_FAIL
	done

	(( i = i + 1 ))
done

testing_mv "f" ${orig_file[0]} ${orig_file[1]}
testing_mv "d" ${orig_dir[0]} ${orig_dir[1]}

# '$MV' succeeds to support NFSv4 ACLs.
case_cleanup $STF_PASS
