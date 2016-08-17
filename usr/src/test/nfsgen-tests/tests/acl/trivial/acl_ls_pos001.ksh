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
# ID: acl_ls_pos001
#
# DESCRIPTION:
#	Verifies that ls displays @ in the file permissions using ls -@ 
#	for files with attribute.
#
# STRATEGY:
#	1. Create files with attribute files in directory A.
#	2. Verify 'ls -l' can display @ in file permissions.
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

echo "ASSERTION: Verifies that ls displays @ in the file permissions using ls -@ " \
	"for files with attribute."

for user in root $ACL_STAFF1; do
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	RUN_CHECK create_files $TESTDIR || cleanup $STF_FAIL

	initfiles=$($LS -R $INI_DIR/*)
	typeset -i i=0
	while (( i < NUM_FILE )); do
		f=$(getitem $i $initfiles)
		RUN_CHECK usr_exec $LS -@ $f | $AWK '{print substr($1, 11, 1)}' \
			> $STF_TMPDIR/ls.$$ || cleanup $STF_FAIL $STF_TMPDIR/ls.$$
		ls_attr=$(cat $STF_TMPDIR/ls.$$)
		if [[ $ls_attr != "@" ]]; then
			echo "ls -@ $f with attribute should success."
			cleanup $STF_FAIL
		else
			# ls -@ $f with attribute success.
			(( i += 1 ))
		fi
	done

	cleanup
done

cleanup $STF_PASS
