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
# ID: mv_pos001
#
# DESCRIPTION:
#   move a large amount of files between dirs with same policy
#
# STRATEGY:
#   - Create a directory including 1000 small files and 5 large files
#   - Move all files in this directory to another directory
#   - Verify all files are moved sucessfully.
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

srcdir=${MNTDIR}/${NAME}_src.`hostname`.$$
dstdir=${MNTDIR}/${NAME}_dst.`hostname`.$$

function assert_cleanup {
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
		|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

	for pid in $pids; do
		ps -p $pid > /dev/null && kill -KILL $pid
	done
	rm -rf $srcdir $dstdir
	cleanup $1
}

# move all files in one directory to another directory
function mv_files
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
		|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

	src=$1
	dst=$2

	files=`find $1  -type f -print`
	num=0
	pids=""
	for file in $files; do
		mv $file $dst 2>$STF_TMPDIR/mv.$NAME.$num.$$ \
			&& echo "PASS" > $STF_TMPDIR/mv.$NAME.$num.$$ &
		pids="$pids $!"
		((num = num + 1))
	done

	condition="(( \`cat $STF_TMPDIR/mv.$NAME.*.\$\$ | grep PASS \
		| wc -l | nawk '{print \$1}'\` == $num ))"
	wait_now 600 "$condition"
	if (( $? != 0 )); then
		nnum=$(cat $STF_TMPDIR/mv.$NAME.*.$$ | grep PASS \
			| wc -l | nawk '{print $1}')
		echo "ERROR: Only $nnum files are moved into $dst \c"
		echo "successfully, but expected $num files"
		cat $STF_TMPDIR/mv.$NAME.*.$$
		return 1
	fi

	# we also check the number of the files
	count_files $dst $num || return 1
	count_files $src 0 || return 1
	return 0
}

# Create a large amount of files in source directory.
num=1000
RUN_CHECK mkdir -p $srcdir $dstdir || exit $STF_UNINITIATED
RUN_CHECK create_small_files $srcdir $num || exit $STF_UNINITIATED
# Also create five large files in the directory.
RUN_CHECK mkfile 30m $srcdir/file_30m || exit $STF_UNINITIATED
RUN_CHECK mkfile 500m $srcdir/file_500m || exit $STF_UNINITIATED
#RUN_CHECK mkfile 1g $srcdir/file_1g || exit $STF_UNINITIATED
#RUN_CHECK mkfile 2g $srcdir/file_2g || exit $STF_UNINITIATED
#RUN_CHECK mkfile 3g $srcdir/file_3g || exit $STF_UNINITIATED

# move all files into target directory
RUN_CHECK mv_files $srcdir $dstdir && assert_cleanup $STF_PASS \
	|| assert_cleanup $STF_FAIL
