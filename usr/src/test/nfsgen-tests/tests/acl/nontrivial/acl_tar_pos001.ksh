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
# ID: acl_tar_pos001
#
# DESCRIPTION:
# Verify that '$TAR' command with -p option supports to archive NFSv4 ACLs
#
# STRATEGY:
# 1. Create file and directory in nfs filesystem
# 2. Add new ACE in ACL of file and directory
# 3. Use $TAR to archive file and directory
# 4. Extract the archive file
# 5. Verify that the restored ACLs of file and directory identify
#    with the origional ones. 
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

echo "ASSERTION: Verify that '$TAR' command supports to archive NFSv4 ACLs."

set -A ops " A+everyone@:execute:allow" "a-x" "777"

TARFILE=tarfile.$$.tar
file=$TESTFILE0
dir=dir.$$
cwd=$PWD

# use absolute path
TESTDIR=$MNTDIR/$TESTDIR
TESTDIR1=$MNTDIR/$TESTDIR1

# Create second directory to restore the tar archive.
if [[ ! -d $TESTDIR1 ]]; then
	RUN_CHECK $MKDIR -p $TESTDIR1 || cleanup $STF_FAIL
fi

# Create a file: $file, and directory: $dir, in nfs filesystem.
cd $TESTDIR
RUN_CHECK $TOUCH $file || cleanup $STF_FAIL
RUN_CHECK $MKDIR $dir || cleanup $STF_FAIL

typeset -i i=0
while (( i < ${#ops[*]} ))
do
	# Change the ACLs of file and directory with '$CHMOD ${ops[i]}'.
	cd $TESTDIR
	for obj in $file $dir; do
		RUN_CHECK $CHMOD ${ops[i]} $obj || cleanup $STF_FAIL
	done
	# Archive the file and directory.
	RUN_CHECK $TAR cpf $TARFILE $file $dir || cleanup $STF_FAIL

	# Restore the tar archive.
	RUN_CHECK $MV $TARFILE $TESTDIR1 || cleanup $STF_FAIL
	cd $TESTDIR1
	RUN_CHECK $TAR xpf $TARFILE || cleanup $STF_FAIL

	# Verify the ACLs of restored file/directory have no changes.
	for obj in $file $dir; do
		RUN_CHECK compare_modes $TESTDIR/$obj $TESTDIR1/$obj \
			|| cleanup $STF_FAIL
		RUN_CHECK compare_acls $TESTDIR/$obj $TESTDIR1/$obj \
			|| cleanup $STF_FAIL
	done

	RUN_CHECK $RM -rf $TESTDIR1/* || cleanup $STF_FAIL

	(( i = i + 1 ))
done

# '$TAR' command succeeds to support NFSv4 ACLs.
cleanup $STF_PASS
