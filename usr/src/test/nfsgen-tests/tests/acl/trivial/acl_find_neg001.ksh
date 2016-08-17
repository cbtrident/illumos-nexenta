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
# ID: acl_find_neg001
#
# DESCRIPTION:
#	Verifies ability to find files with attribute with -xattr flag and using
#	"-exec runat ls".
#
# STRATEGY:
#	1. In directory A, create several files and add attribute files for them
#	2. Delete all the attribute files.
#	2. Verify all the specified files can not be found with '-xattr', 
#	3. Verify all the attribute files can not be found with '-exec runat ls'
#
# TESTABILITY: explicit
#
# TEST_AUTOMATION_LEVEL: automated
#
#
# __stc_assertion_end
#
################################################################################

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& set -x

echo "ASSERTION: verifies -xattr doesn't include files without " \
		"attribute and using '-exec runat ls'"

for user in root $ACL_STAFF1; do
	# In TX env, we can't create files with xattr as a regular user
        if [[ $user != root ]] && [[ ! -z $ZONE_PATH ]]; then
                continue
        fi

	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	RUN_CHECK create_files $TESTDIR || cleanup $STF_FAIL

	initfiles=$($LS -R $INI_DIR/*)
	typeset -i i=0
	while (( i < NUM_FILE )); do
		f=$(getitem $i $initfiles)
		usr_exec $RUNAT $f $RM attribute*
		(( i += 1 ))
	done

	i=0
	while (( i < NUM_FILE )); do
		f=$(getitem $i $initfiles)
		ff=$(usr_exec $FIND $INI_DIR -type f -name ${f##*/} \
			-xattr -print)
		if [[ $ff == $f ]]; then
			echo "find not containing attribute should fail."
			cleanup $STF_FAIL
		fi

		typeset -i j=0
		while (( j < NUM_ATTR )); do
			fa=$(usr_exec $FIND $INI_DIR -type f -name ${f##*/} \
				-xattr -exec $RUNAT {} $LS attribute.$j \\\;)
			if [[ $fa == attribute.$j ]]; then
				echo "find file attribute should fail."
				cleanup $STF_FAIL
			fi
			(( j += 1 ))
		done
		# Failed to find $f and its attribute file as expected.

		(( i += 1 ))
	done
	
	cleanup
done

cleanup $STF_PASS
