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
# ID: acl_cp_pos001
#
# DESCRIPTION:
#	Verifies that cp will include file attribute when using the -@ flag
#
# STRATEGY:
#	1. In directory A, create several files and add attribute files for them
#	2. Save all files and their attribute files cksum value, then 'cp -@p' 
#	   all the files to to another directory B.
#	3. Calculate all the cksum in directory B.
#	4. Verify all the cksum are identical
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

echo "ASSERTION: Verifies that cp will include file attribute when using the -@ flag"

set -A BEFORE_FCKSUM
set -A BEFORE_ACKSUM
set -A AFTER_FCKSUM
set -A AFTER_ACKSUM

for user in root $ACL_STAFF1; do
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	RUN_CHECK create_files $TESTDIR || cleanup $STF_FAIL
	RUN_CHECK cksum_files $INI_DIR BEFORE_FCKSUM BEFORE_ACKSUM \
		|| cleanup $STF_FAIL

	initfiles=$($LS -R $INI_DIR/*)
	typeset -i i=0
	while ((i < NUM_FILE)); do
		f=$(getitem $i $initfiles)

		RUN_CHECK usr_exec $CP -@p $f $TST_DIR || cleanup $STF_FAIL

		((i += 1))
	done

	RUN_CHECK cksum_files $TST_DIR AFTER_FCKSUM AFTER_ACKSUM \
		|| cleanup $STF_FAIL
	RUN_CHECK compare_cksum BEFORE_FCKSUM AFTER_FCKSUM \
		|| cleanup $STF_FAIL
	RUN_CHECK compare_cksum BEFORE_ACKSUM AFTER_ACKSUM \
		|| cleanup $STF_FAIL

	cleanup
done

cleanup $STF_PASS
