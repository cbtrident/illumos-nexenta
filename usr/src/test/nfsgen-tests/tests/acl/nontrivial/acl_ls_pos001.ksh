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
# ID: acl_ls_pos001
#
# DESCRIPTION:
# Verify that '/usr/bin/ls' command option supports NFSv4 ACL 
#
# STRATEGY:
# 1. Create file and  directory in nfs filesystem
# 2. Verify that 'ls [-dv]' can list the ACEs of ACL of 
#    file/directroy
# 3. Change the file/directory's acl
# 4. Verify that 'ls -l' can use the '+' to indicate the non-trivial
#    acl. 
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

echo "ASSERTION: Verify that '$LS' command supports NFSv4 ACLs."

file=$TESTFILE0
dir=dir.$$
cwd=$PWD
mask=`$UMASK`
spec_ace="everyone@:write_acl:allow"

$UMASK 0022

# Create file and directory in the nfs filesystem.
cd $TESTDIR
RUN_CHECK $TOUCH $file || case_cleanup $STF_FAIL
RUN_CHECK $MKDIR $dir || case_cleanup $STF_FAIL

# Verify that '$LS [-dv]' can list file/directory ACEs of its acl.

typeset -i ace_num=0
for obj in $file $dir
do
	typeset ls_str=""
	if [[ -f $obj ]]; then
		ls_str="$LS -v"
	else 
		ls_str="$LS -dv"
	fi
	
	for ace_type in "owner@" "group@" "everyone@"
	do
		RUN_CHECK $ls_str $obj | $GREP $ace_type > /dev/null 
		(( $? == 0 )) && (( ace_num += 1 )) || case_cleanup $STF_FAIL
	done

	if (( ace_num < 1 )); then
		echo "'$LS [-dv] fails to list file/directroy acls."	
		case_cleanup $STF_FAIL
	fi
done

# Verify that '$LS [-dl] [-dv]' can output '+' to indicate the acl existent.

for obj in $file $dir
do
	RUN_CHECK $CHMOD A0+$spec_ace $obj || case_cleanup $STF_FAIL

	RUN_CHECK $LS -ld -vd $obj | $GREP + > /dev/null \
		|| case_cleanup $STF_FAIL
	RUN_CHECK plus_sign_check_v $obj || case_cleanup $STF_FAIL

	RUN_CHECK $LS -ld -vd $obj | $GREP $spec_ace > /dev/null \
		|| case_cleanup $STF_FAIL
	RUN_CHECK plus_sign_check_l $obj || case_cleanup $STF_FAIL
done 

# '$LS' command succeeds to support NFSv4 ACLs.
case_cleanup $STF_PASS
