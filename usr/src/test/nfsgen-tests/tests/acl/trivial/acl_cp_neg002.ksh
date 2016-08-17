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
# ID: acl_cp_neg002
#
# DESCRIPTION:
#	Verifies that cp will not be able to include file attribute when
#	attribute is unreadable (unless the user is root)
#
# STRATEGY:
#	1. In directory A, create several files and add attribute files for them
#	2. chmod all files'the attribute files to '000'.
#	3. Implement 'cp -@p' to files.
#	4. Verify attribute files are not existing for non-root user.
#
# TESTABILITY: explicit
#
# TEST_AUTOMATION_LEVEL: automated
#
# CODING_STATUS: COMPLETED (2006-06-01)
#
# __stc_assertion_end
#
################################################################################

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& set -x

echo "ASSERTION: Verifies that cp won't be able to include file attribute when " \
	"attribute is unreadable (except root)"

function test_unreadable_attr
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset initfiles=$($LS -R $INI_DIR/*)
	typeset -i i=0
	while (( i < NUM_FILE )); do
		typeset f=$(getitem $i $initfiles)
		typeset -i j=0
		while (( j < NUM_ATTR )); do
			# chmod all the attribute files to '000'.
			RUN_CHECK usr_exec $RUNAT $f $CHMOD 000 attribute.$j
			(( j += 1 ))
		done

		#
		# Implement 'cp -@p' to the file whose attribute files 
		# models are '000'.
		#
		RUN_CHECK usr_exec $CP -@p $f $TST_DIR > /dev/null 2>&1

		typeset testfiles=$($LS -R $TST_DIR/*)
		typeset tf=$(getitem $i $testfiles)
		RUN_CHECK usr_exec $LS -@ $tf | $AWK '{print substr($1, 11, 1)}' \
			> $STF_TMPDIR/ls.$$ || cleanup $STF_FAIL $STF_TMPDIR/ls.$$
		typeset ls_attr=$(cat $STF_TMPDIR/ls.$$)

		case $ACL_CUR_USER in
		root)
			case $ls_attr in
			@)
				# SUCCESS: root enable to cp attribute
				# when attribute files is unreadable
				break ;;
			*)
				echo "root should enable to cp attribute " \
					"when attribute files is unreadable"
				cleanup $STF_FAIL
				break ;;
			esac
			;;
		$ACL_STAFF1)
			case $ls_attr in
			@)
				echo "non-root shouldn't enable to cp " \
					"attribute when attribute files is " \
					"unreadable."
				cleanup $STF_FAIL
				break ;;
			*)
				# SUCCESS: non-root doesn't enable to
				# cp attribute when attribute files is
				# unreadable.
				break ;;
			esac
			;;
		*)
		esac


		(( i += 1 ))
	done
}

for user in root $ACL_STAFF1; do
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	RUN_CHECK create_files $TESTDIR || cleanup $STF_FAIL

	test_unreadable_attr

	cleanup
done

cleanup $STF_PASS
