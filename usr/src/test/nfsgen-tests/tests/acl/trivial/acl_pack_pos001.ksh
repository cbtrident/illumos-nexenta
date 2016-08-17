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
# ID: acl_pack_pos001
#
# DESCRIPTION:
#	Verifies that pack will keep file attribute intact afterthe file is
#	packed and unpacked.
#
# STRATEGY:
#	1. In directory A, create several files and add attribute files for them
#	2. Save all files and their attribute files cksum value, then pack
#	   all the files.
#	3. Move them to another directory B.
#	4. Unpack them and calculate all the files and attribute files cksum
#	5. Verify all the cksum are identical
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

echo "ASSERTION: Verifies that pack will keep file attribute intact after the file "\
	"is packed and unpacked"

set -A BEFORE_FCKSUM
set -A BEFORE_ACKSUM
set -A AFTER_FCKSUM
set -A AFTER_ACKSUM

for user in root $ACL_STAFF1; do
	RUN_CHECK set_cur_usr $user || cleanup $STF_FAIL
	RUN_CHECK create_files $TESTDIR || cleanup $STF_FAIL
	RUN_CHECK cksum_files $INI_DIR BEFORE_FCKSUM BEFORE_ACKSUM \
		|| cleanup $STF_FAIL
	RUN_CHECK "usr_exec $PACK -f $INI_DIR/* > /dev/null" \
		|| cleanup $STF_FAIL
	RUN_CHECK usr_exec $MV $INI_DIR/* $TST_DIR \
		|| cleanup $STF_FAIL
	RUN_CHECK "usr_exec $UNPACK $TST_DIR/* > /dev/null" \
		|| cleanup $STF_FAIL
	RUN_CHECK cksum_files $TST_DIR AFTER_FCKSUM AFTER_ACKSUM \
		|| cleanup $STF_FAIL

	RUN_CHECK compare_cksum BEFORE_FCKSUM AFTER_FCKSUM || cleanup $STF_FAIL
	RUN_CHECK compare_cksum BEFORE_ACKSUM AFTER_ACKSUM || cleanup $STF_FAIL

	cleanup
done

# pack/unpack test passed.
cleanup $STF_PASS
