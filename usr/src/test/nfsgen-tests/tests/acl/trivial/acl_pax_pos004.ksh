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
# ID: acl_pax_pos004
#
# DESCRIPTION:
#	Verify files include attribute in pax archive and restore with pax
#	should succeed.
#
# STRATEGY:
#	1. Create several files which contains contribute files in directory A.
#	2. Enter into directory A and record all files cksum.
#	3. pax all the files to directory B.
#	4. Then pax the pax file to directory C.
#	5. Record all the files cksum in derectory C.
#	6. Verify the two records should be identical.
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

echo "ASSERTION: Verify files include attribute in pax archive and restore with pax " \
	"should succeed."

set -A BEFORE_FCKSUM
set -A BEFORE_ACKSUM
set -A AFTER_FCKSUM
set -A AFTER_ACKSUM

for user in root $ACL_STAFF1; do
	# In TX env, we can't create files with xattr as a regular user
        if [[ $user != root ]] && [[ ! -z $ZONE_PATH ]]; then
                continue
        fi

	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	RUN_CHECK create_files $TESTDIR || cleanup $STF_FAIL

	#
	# Enter into initial directory and record all files cksum,
	# then pax all the files to $TMP_DIR/files.pax.
	#
	paxout=$TMP_DIR/files.pax
	cd $INI_DIR
	RUN_CHECK cksum_files $MNTDIR/$INI_DIR BEFORE_FCKSUM BEFORE_ACKSUM \
		|| cleanup $STF_FAIL
	RUN_CHECK usr_exec $PAX -w -@ -f $MNTDIR/$paxout * > /dev/null \
		|| cleanup $STF_FAIL

	#
	# Enter into test directory and pax $TMP_DIR/files.pax to current
	# directory. Record all directory information and compare with initial
	# directory record.
	#
	cd $MNTDIR/$TST_DIR
	RUN_CHECK usr_exec $PAX -r -@ -f $MNTDIR/$paxout > /dev/null \
		|| cleanup $STF_FAIL
	RUN_CHECK cksum_files $MNTDIR/$TST_DIR AFTER_FCKSUM AFTER_ACKSUM \
		|| cleanup $STF_FAIL

	RUN_CHECK compare_cksum BEFORE_FCKSUM AFTER_FCKSUM || cleanup $STF_FAIL
	RUN_CHECK compare_cksum BEFORE_ACKSUM AFTER_ACKSUM || cleanup $STF_FAIL

	cd $MNTDIR
	cleanup
done

# Files pax archive and restre with pax passed.
cleanup $STF_PASS
