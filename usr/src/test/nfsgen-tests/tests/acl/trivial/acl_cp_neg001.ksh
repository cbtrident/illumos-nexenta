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
# ID: acl_cp_neg001
#
# DESCRIPTION:
#	Verifies that cp will not include file attribute when the -@ flag is not
#	present.
#
# STRATEGY:
#	1. In directory A, create several files and add attribute files for them
#	2. Implement cp to files without '-@'
#	3. Verify attribute files will not include file attribute
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

echo "ASSERTION: Verifies that cp will not include file attribute when the -@ flag "\
	"is not present."

for user in root $ACL_STAFF1; do

	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	RUN_CHECK create_files $TESTDIR || cleanup $STF_FAIL

	initfiles=$($LS -R $INI_DIR/*)
	typeset -i i=0
	while (( i < NUM_FILE )); do
		typeset f=$(getitem $i $initfiles)
		RUN_CHECK usr_exec $CP $f $TST_DIR || cleanup $STF_FAIL

		testfiles=$($LS -R $TST_DIR/*)
		tf=$(getitem $i $testfiles)
		ls_attr=$($LS -@ $tf | $AWK '{print substr($1, 11, 1)}')
		if [[ $ls_attr == "@" ]]; then
			echo "cp of attribute should fail without " \
				"-@ or -p option"
			cleanup $STF_FAIL
		fi

		(( i += 1 ))
	done

	cleanup
done

cleanup $STF_PASS
