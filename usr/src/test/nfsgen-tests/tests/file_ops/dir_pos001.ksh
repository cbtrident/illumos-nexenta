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
# ID: dir_pos001
#
# DESCRIPTION:
#   looply create a large amount of dirs with small files, verify all dirs
#   are created successfully.
#
# STRATEGY:
#   - Create 30 subdirs within test directory.
#   - Recursively create subdirs under each dir. The diretory depth is 30
#     and each dir includes 10 files.
#   - Verify all operations are successful.
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

	for pid in $pids; do
		ps -p $pid > /dev/null && kill -KILL $pid
	done

	rm -rf $testdir
	cleanup $1
}

# Create 30 subdirs in parallel, then recursively create subdir whithin each dir 
# Each dir includes 10 files, and the directory depth is 30.
testdir=${MNTDIR}/${NAME}.`hostname`.$$
num=0
pids=""
while (($num < 30)); do
	curdir=$testdir/sub$num
	# create dirs and files in parallel
	(
		level=0
		while (($level < 30)); do
			RUN_CHECK mkdir -p $curdir && \
				RUN_CHECK create_small_files $curdir 10 && \
				touch $STF_TMPDIR/mkdir.$NAME.$num.$level.$$
			curdir=$curdir/$level
			level=$((level + 1))
		done
	) &
	pids="$pids $!"
	num=$((num + 1))
done

sleep 60
condition="(( \`ls $STF_TMPDIR/mkdir.$NAME.*.\$\$ \
 	| wc -l | nawk '{print \$1}'\` == 900 ))"
wait_now 1800 "$condition"
if (( $? != 0 )); then
	nnum=$(ls $STF_TMPDIR/mkdir.$NAME.*.$$ \
		| wc -l | nawk '{print $1}')
	echo "ERROR: Only $nnum directories are created sucessfully, \c"
	echo "but expected 900 directories"
	assert_cleanup $STF_FAIL
fi

assert_cleanup $STF_PASS

