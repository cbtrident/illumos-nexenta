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
# ID: dir_pos003
#
# DESCRIPTION:
#   Concurrently rename directory accross two trees. nfs should be able
#   to handle race situation.
#
# STRATEGY:
#   - Create two dirs 1/2/3/4/5 and a/b/c/d/e
#   - Looply rename directory to create race situation.
#     One process rename "a/b/c" to "1/2/3/c" and back again,
#     another process rename "1" to "a/b/c/d/e/1" and back again.
#   - The system should be stable to handle race situation.
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

	cd - && rm -rf $testdir 
	cleanup $1
}

function loop_mv {
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
		|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
	src=$1
	dst=$2

	while true; do
		mv $src $dst > /dev/null 2>&1
		mv $dst $src > /dev/null 2>&1
	done
}

testdir=${MNTDIR}/${NAME}.`hostname`.$$
RUN_CHECK mkdir -p $testdir/1/2/3/4/5 $testdir/a/b/c/d/e \
	|| assert_cleanup $STF_UNINITIATED
RUN_CHECK cd $testdir || assert_cleanup $STF_UNINITIATED

#
# Rename directory to generate race condition, we don't care
# if the rename succeeds or fails. The test just verify if
# the system is stable. 
#
loop_mv a/b/c 1/2/3/c &
pid1=$!
loop_mv a/b/c/d/e/1 1 &
pid2=$!

sleep 30
kill -9 $pid1 $pid2
assert_cleanup $STF_PASS

