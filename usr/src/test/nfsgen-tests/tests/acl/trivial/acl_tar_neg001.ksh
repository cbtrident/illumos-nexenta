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
# ID: acl_tar_neg001
#
# DESCRIPTION:
#	Verifies that tar will not include files attribute when @ flag is not
#	present.
#
# STRATEGY:
#	1. Create several files with attribute files.
#	2. Enter into directory A and record all files cksum
#	3. tar all the files to directory B.
#	4. Then tar the tar file to directory C.
#	5. Record all the files cksum in derectory C.
#	6. Verify the two records should be not identical.
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

echo "ASSERTION: Verifies that tar will not include files attribute when @ flag is "\
	"not present"

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
	# Enter into initial directory and record all directory information,
	# then tar all the files to $TMP_DIR/files.tar.
	#
	tarout=$TMP_DIR/files.tar
	cd $INI_DIR
	RUN_CHECK cksum_files $MNTDIR/$INI_DIR BEFORE_FCKSUM BEFORE_ACKSUM \
		|| cleanup $STF_FAIL
	RUN_CHECK usr_exec $TAR cpf $MNTDIR/$tarout * || cleanup $STF_FAIL

	#
	# Enter into test directory and tar $TMP_DIR/files.tar to current
	# directory. Record all directory information and compare with initial
	# directory record.
	#
	cd $MNTDIR/$TST_DIR
	RUN_CHECK usr_exec $CP $MNTDIR/$tarout $MNTDIR/$TST_DIR || cleanup $STF_FAIL
	RUN_CHECK usr_exec $TAR xpf $MNTDIR/$tarout || cleanup $STF_FAIL

	testfiles=$($LS -R $MNTDIR/$TST_DIR/*)
	typeset -i i=0
	while (( i < NUM_FILE )); do
		f=$(getitem $i $testfiles)
		ls_attr=$($LS -@ $f | $AWK '{print substr($1, 11, 1)}')
		if [[ $ls_attr == "@" ]]; then
			echo "extraction of attribute successful w/ -@ flag"
			cleanup $STF_FAIL
		fi
		
		(( i += 1 ))
	done

	RUN_CHECK cksum_files $MNTDIR/$TST_DIR AFTER_FCKSUM AFTER_ACKSUM \
		|| cleanup $STF_FAIL

	RUN_CHECK compare_cksum BEFORE_FCKSUM AFTER_FCKSUM || cleanup $STF_FAIL
	# XXX: ??? the cksum of the attributes wasn't changed?
#	log_mustnot compare_cksum BEFORE_ACKSUM AFTER_ACKSUM
	RUN_CHECK compare_cksum BEFORE_ACKSUM AFTER_ACKSUM || cleanup $STF_FAIL

	cd $MNTDIR
	cleanup
done

# Verify tar without @ passed.
cleanup $STF_PASS
