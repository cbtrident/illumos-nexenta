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
# ID: acl_tar_pos002
#
# DESCRIPTION:
# Verify that '$TAR' command with -p@ option supports to archive NFSv4 ACLs 
#	& xattrs
#
# STRATEGY:
# 1. Create file and directory in nfs filesystem
# 2. Add new ACE in ACL of file and directory
# 3. Create xattr of the file and directory
# 4. Use $TAR cf@ to archive file and directory
# 5. Use $TAR xf@ to extract the archive file
# 6. Verify that the restored ACLs & xttrs of file and directory identify
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

echo "ASSERTION: Verify that '$TAR' command supports to archive NFSv4 ACLs & xattrs."

set -A ops " A+everyone@:execute:allow" "a-x" "777"
MYTESTFILE=$STF_SUITE/STF.INFO

testfile=testfile.$$
testdir=testdir.$$
TARFILE=tarfile.$$.tar
cwd=$PWD

# Create second directory to restore the tar archive.
if [[ ! -d $TESTDIR1 ]]; then
	RUN_CHECK $MKDIR -p $TESTDIR1 || cleanup $STF_FAIL
fi

# Create a file: $testfile, and directory: $testdir, in nfs filesystem
# And prepare for there xattr files.

for user in root $ACL_STAFF1; do
	# Set the current user
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	# Create source object and target directroy
	cd $TESTDIR
	RUN_CHECK usr_exec $TOUCH $testfile || cleanup $STF_FAIL
	RUN_CHECK usr_exec $MKDIR $testdir || cleanup $STF_FAIL

	RUN_CHECK usr_exec $RUNAT $testfile $CP $MYTESTFILE attr.0 \
		|| cleanup $STF_FAIL
	RUN_CHECK usr_exec $RUNAT $testdir $CP $MYTESTFILE attr.0 \
		|| cleanup $STF_FAIL

	# Add the new ACE on the head.
	# Change the ACLs of file and directory with '$CHMOD ${ops[0]}'.
	RUN_CHECK usr_exec $CHMOD ${ops[0]} $testfile || cleanup $STF_FAIL
	RUN_CHECK usr_exec $CHMOD ${ops[0]} $testdir || cleanup $STF_FAIL

	# Archive the file and directory.
	RUN_CHECK $TAR cpf@ $TARFILE ${testfile#$TESTDIR/} ${testdir#$TESTDIR/} \
		|| cleanup $STF_FAIL
		
	# Restore the tar archive.
	cd $MNTDIR/$TESTDIR1
	RUN_CHECK $TAR xpf@ $MNTDIR/$TESTDIR/$TARFILE || cleanup $STF_FAIL

	cd $MNTDIR
	# Verify the ACLs of restored file/directory have no changes.
	for obj in $testfile $testdir; do
		RUN_CHECK compare_modes $TESTDIR/$obj $TESTDIR1/${obj##*/} \
			|| cleanup $STF_FAIL
		RUN_CHECK compare_acls $TESTDIR/$obj $TESTDIR1/${obj##*/} \
			|| cleanup $STF_FAIL
		RUN_CHECK compare_xattrs $TESTDIR/$obj $TESTDIR1/${obj##*/} \
			|| cleanup $STF_FAIL
	done

	RUN_CHECK $RM -rf $TESTDIR/* $TESTDIR1/* || cleanup $STF_FAIL
done
		
# '$TAR' command succeeds to support NFSv4 ACLs.
cleanup $STF_PASS
