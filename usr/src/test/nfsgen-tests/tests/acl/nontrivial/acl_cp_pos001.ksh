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
# ID: acl_cp_pos001
#
# DESCRIPTION:
# 	Verify that '/usr/bin/cp [-p]' supports ACL
#
# STRATEGY:
# 	1. Create file and  directory in nfs filesystem
# 	2. Set special ACE to the file and directory
# 	3. Copy the file/directory to another directory
# 	4. Verify that the ACL of file/directroy is not changed, when you are
# 	   inserting an ACL with a user: or group: entry on the top.
#	   (abstractions entry are treated special, since they represent the 
#	   traditional permission bit mapping.)
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

echo "ASSERTION: Verify that '$CP [-p]' supports ACLs."

# Create the second directory.
RUN_CHECK $MKDIR -p $TESTDIR1 || cleanup $STF_FAIL
RUN_CHECK $CHMOD 777 $TESTDIR1 || cleanup $STF_FAIL

# Define target directory.
dstdir=$TESTDIR1/dstdir.$$

for user in root $ACL_STAFF1; do
	# Set the current user
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	for obj in $testfile $testdir; do
		# Create source object and target directroy
		RUN_CHECK usr_exec $TOUCH $testfile || cleanup $STF_FAIL
		RUN_CHECK usr_exec $MKDIR $testdir $dstdir || cleanup $STF_FAIL

		# Add the new ACE on the head.
		RUN_CHECK usr_exec $CHMOD \
			A0+user:$ACL_OTHER1:read_acl:deny $obj \
			|| cleanup $STF_FAIL

		cmd_str="$CP -p"
		[[ -d $obj ]] && cmd_str="$CP -rp"
		RUN_CHECK usr_exec $cmd_str $obj $dstdir || cleanup $STF_FAIL
		RUN_CHECK usr_exec $cmd_str $obj $TESTDIR1 || cleanup $STF_FAIL

		for dir in $dstdir $TESTDIR1; do 
			RUN_CHECK compare_modes $obj $dir/${obj##*/} \
				|| cleanup $STF_FAIL
			RUN_CHECK compare_acls $obj $dir/${obj##*/} \
				|| cleanup $STF_FAIL
		done

		# Delete all the test file and directory
		RUN_CHECK usr_exec $RM -rf $TESTDIR/* $TESTDIR1/* \
			|| cleanup $STF_FAIL
	done
done

# '$CP [-p]' succeeds to support ACLs.
cleanup $STF_PASS
