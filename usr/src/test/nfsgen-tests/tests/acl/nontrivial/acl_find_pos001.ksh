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
# ID: acl_find_pos001
#
# DESCRIPTION:
# Verify that '$FIND' command with '-ls' and '-acl' options supports NFSv4 ACL 
#
# STRATEGY:
# 1. Create 5 files and 5 directories in nfs filesystem
# 2. Select a file or directory and add a few ACEs to it 
# 3. Use $FIND -ls to check the "+" existen only with the selected file or 
#    directory
# 4. Use $FIND -acl to check only the selected file/directory in the list
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

	[[ -d $TESTDIR ]] && $RM -rf $TESTDIR/*
	(( ${#cmd} != 0 )) && cd $cwd
	(( ${#mask} != 0 )) && $UMASK $mask
	cleanup $1
}

function find_ls_acl #<opt> <obj>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset opt=$1 # -ls or -acl
	typeset obj=$2
	typeset rst_str=""

	if [[ $opt == "ls" ]]; then
		rst_str=`$FIND . -ls | $GREP "+" | $AWK '{print $11}'`
	else
		rst_str=`$FIND . -acl`
	fi

	if [[ $rst_str == "./$obj" ]]; then 
		return 0
	else
		return 1
	fi
}

echo "ASSERTION: Verify that '$FIND' command supports NFSv4 ACLs."

set -A ops " A+everyone@:read_data:allow" \
	" A+owner@:write_data:allow" 

f_base=testfile.$$ # Base file name for tested files
d_base=testdir.$$ # Base directory name for tested directory
cwd=$PWD
mask=`$UMASK`

# Create five files and directories in the nfs filesystem.
cd $TESTDIR
$UMASK 0777
typeset -i i=0
while (( i < 5 ))
do
	RUN_CHECK $TOUCH ${f_base}.$i || case_cleanup $STF_FAIL
	RUN_CHECK $MKDIR ${d_base}.$i || case_cleanup $STF_FAIL

	(( i = i + 1 ))
done

for obj in ${f_base}.3 ${d_base}.3
do
	i=0
	while (( i < ${#ops[*]} ))
	do
		RUN_CHECK $CHMOD ${ops[i]} $obj || case_cleanup $STF_FAIL

		(( i = i + 1 ))
	done

	for opt in "ls" "acl"
	do
		RUN_CHECK find_ls_acl $opt $obj || case_cleanup $STF_FAIL
	done

	# Check the file access permission according to the added ACEs
	if [[ ! -r $obj || ! -w $obj ]]; then
		echo "The added ACEs for $obj cannot be represented in " \
			"mode."
		case_cleanup $STF_FAIL
	fi
	
	# Remove the added ACEs from ACL.
	i=0
	while (( i < ${#ops[*]} ))
	do
		RUN_CHECK $CHMOD A0- $obj || case_cleanup $STF_FAIL
		(( i = i + 1 ))
	done
done

# '$FIND' command succeeds to support NFSv4 ACLs.
case_cleanup $STF_PASS
