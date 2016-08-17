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
# ID: acl_cpio_pos001
#
# DESCRIPTION:
# Verify that '$CPIO' command with -P option supports to archive ZFS ACLs
#
# STRATEGY:
# 1. Create file and directory in nfs filesystem
# 2. Add new ACE in ACL or change mode of file and directory
# 3. Use $CPIO to archive file and directory
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

echo "ASSERTION: Verify that '$CPIO' command supports to archive NFSv4 ACLs."

set -A ops "A+everyone@:execute:allow" \
	"A3+user:$ACL_OTHER1:write_data:deny" \
	"A5+group:$ACL_OTHER_GROUP:read_data:deny" \
	"A0+user:$ACL_OTHER1:write_data:deny" \
	"A1=user:$ACL_STAFF1:write_data:deny" \
	"A5=group:$ACL_STAFF_GROUP:write_data:deny"

# Create second directory to restore the cpio archive.
RUN_CHECK $MKDIR -p $TESTDIR1 || cleanup $STF_FAIL
RUN_CHECK $CHMOD 777 $TESTDIR1 || cleanup $STF_FAIL

# Define test fine and record the original directory.
CPIOFILE=cpiofile.$$
file=$TESTFILE0
dir=dir.$$
orig_dir=$PWD

typeset user
for user in root $ACL_STAFF1; do
	# Set the current user
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	typeset -i i=0
	while (( i < ${#ops[*]} )); do
		# Create file $file and directory $dir in nfs filesystem.
		cd $TESTDIR
		RUN_CHECK usr_exec $TOUCH $file || cleanup $STF_FAIL
		RUN_CHECK usr_exec $MKDIR $dir || cleanup $STF_FAIL

		# Change the ACLs of file and directory with '$CHMOD ${ops[i]}'
		for obj in $file $dir; do
			RUN_CHECK usr_exec $CHMOD ${ops[i]} $obj \
				|| cleanup $STF_FAIL
		done

		# Archive the file and directory.
		RUN_CHECK usr_exec $LS | $CPIO -ocP -O $CPIOFILE \
			> $STF_TMPDIR/cpio.$$ 2>&1 \
			|| cleanup $STF_FAIL $STF_TMPDIR/cpio.$$

		# Restore the cpio archive.
		cd $MNTDIR
		RUN_CHECK usr_exec $MV $TESTDIR/$CPIOFILE $TESTDIR1 || cleanup $STF_FAIL
		cd $TESTDIR1
		RUN_CHECK usr_exec $CAT $CPIOFILE | $CPIO -icP \
			> $STF_TMPDIR/cpio.$$ 2>&1 \
			|| cleanup $STF_FAIL $STF_TMPDIR/cpio.$$

		# Verify that the ACLs of restored file/directory have no change
		cd $MNTDIR
		for obj in $file $dir; do
			RUN_CHECK compare_modes $TESTDIR/$obj $TESTDIR1/$obj \
				|| cleanup $STF_FAIL
			RUN_CHECK compare_acls $TESTDIR/$obj $TESTDIR1/$obj \
				|| cleanup $STF_FAIL
		done

		RUN_CHECK usr_exec $RM -rf $TESTDIR/* $TESTDIR1/* \
			|| cleanup $STF_FAIL

		(( i = i + 1 ))
	done
done

# '$CPIO' command succeeds to support NFSv4 ACLs.
cleanup $STF_PASS
