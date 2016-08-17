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

################################################################################
#
# __stc_assertion_start
#
# ID: dir_pos002
#
# DESCRIPTION:
#   Looply create a large amount of dirs with large files until
#   no space is available, the system should be stable.
#
# STRATEGY:
#   - Looply create a large amount of dirs which include some files
#     until the error occurs.
#   - Verify the filesystem is full and system is stable
#   - Remove all dirs and files
#
# TESTABILITY: explicit
#
# TEST_AUTOMATION_LEVEL: automated
#
# __stc_assertion_end
#
################################################################################

. ${STF_SUITE}/include/nfsgen.kshlib

readonly FILE=$(whence -p ${0})
readonly NAME=$(basename $0)
readonly DIR=$(dirname $0)

export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
        || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

# Extract and print assertion information from this source script to journal
extract_assertion_info $FILE

function assert_cleanup {
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
		|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

	ret=$STF_PASS
	if [[ ! -z $1 ]]; then
		cat $1 | grep "No space left on device" > /dev/null 2>&1
		if (($? != 0)); then 
			cat $1
			ret=$STF_FAIL
		fi
	fi
	RUN_CHECK rm -rf $testdir || ret=$STF_FAIL
	cleanup $ret
}

#
# Create a large amount of directories which include some small
# files and a large files until the space is full
#
testdir=${MNTDIR}/${NAME}.`hostname`.$$
typeset -i num=0
while (($num < 10 )); do
	curdir=$testdir/$num
	RUN_CHECK mkdir -p $curdir > $STF_TMPDIR/mkdir.$$ 2>&1 \
		|| assert_cleanup $STF_TMPDIR/mkdir.$$
	RUN_CHECK create_small_files $curdir 10 > $STF_TMPDIR/sfile.$$ 2>&1 \
		|| assert_cleanup $STF_TMPDIR/sfile.$$
	RUN_CHECK mkfile 100m $curdir/file_100m > $STF_TMPDIR/lfile.$$ 2>&1 \
		|| assert_cleanup $STF_TMPDIR/lfile.$$
	num=$((num + 1))
done

assert_cleanup

