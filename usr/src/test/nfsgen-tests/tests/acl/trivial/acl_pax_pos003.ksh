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
# ID: acl_pax_pos003
#
# DESCRIPTION:
#	Verify directories which include attribute in pax archive and restore
#	with cpio should succeed.
#
# STRATEGY:
#	1. Create several files in directory A.
#	2. Enter into directory A and record all directory cksum.
#	3. pax all the files to directory B.
#	4. Then cpio the pax file to directory C.
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

echo "ASSERTION: Verify include attribute in pax archive and restore with cpio " \
	"should succeed."

for user in root $ACL_STAFF1; do
	# In TX env, we can't create files with xattr as a regular user
        if [[ $user != root ]] && [[ ! -z $ZONE_PATH ]]; then
                continue
        fi

	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL

	if [[ ! -d $INI_DIR ]]; then
		RUN_CHECK usr_exec $MKDIR -m 777 -p $INI_DIR || cleanup $STF_FAIL
	fi
	RUN_CHECK usr_exec $MKTREE -b $INI_DIR -l 6 -d 2 -f 2 \
		|| cleanup $STF_FAIL

	initout=$TMP_DIR/initout.$$
	paxout=$TMP_DIR/files.cpio
	cd $INI_DIR
	RUN_CHECK record_cksum $MNTDIR/$INI_DIR $MNTDIR/$initout > /dev/null \
		|| cleanup $STF_FAIL
	RUN_CHECK usr_exec $PAX -w -x cpio -@ -f $MNTDIR/$paxout * >/dev/null \
		|| cleanup $STF_FAIL

	#
	# Enter into test directory and cpio $TMP_DIR/files.pax to current
	# directory. Record all directory information and compare with initial
	# directory record.
	#
	if [[ ! -d $MNTDIR/$TST_DIR ]]; then
		RUN_CHECK usr_exec $MKDIR -m 777 $MNTDIR/$TST_DIR || cleanup $STF_FAIL
	fi
	testout=$TMP_DIR/testout.$$
	cd $MNTDIR/$TST_DIR
	RUN_CHECK usr_exec $CPIO -ivd@ < $MNTDIR/$paxout > /dev/null \
		|| cleanup $STF_FAIL
	RUN_CHECK record_cksum $MNTDIR/$TST_DIR $MNTDIR/$testout > /dev/null \
		|| cleanup $STF_FAIL

	RUN_CHECK usr_exec $DIFF $MNTDIR/$initout $MNTDIR/$testout || cleanup $STF_FAIL
	
	cd $MNTDIR
	cleanup
done

# Directories pax archive and restore with cpio passed.
cleanup $STF_PASS
