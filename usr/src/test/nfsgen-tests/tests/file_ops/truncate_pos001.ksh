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
# ID: truncate_pos001
#
# DESCRIPTION:
#   Verify file truncatation within nfs
#
# STRATEGY:
#   Concurrently perform mulitiple file truncatation with different file size,
#   block size, offset.
#     1. Open a file
#     2. Write random blocks in random places, and read them back
#     3. Truncate the file
#     4. Repeat above two steps
#     5. Close the file.
#
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
	rm -rf $trunc_dir
	cleanup $1
}

a_fsize="64 268435456 2147483648" 		# 256M,2G 
a_blksize="64 256 1024"
a_count="10 100 1000"
a_offset="0 1024 268435456"

trunc_dir=${MNTDIR}/${NAME}.`hostname`.$$
RUN_CHECK mkdir -p $trunc_dir || exit $STF_UNINITIATED
num=0
pids=""
echo ""
for fsize in $a_fsize; do
    for blksize in $a_blksize; do
        for count in $a_count; do
            for offset in $a_offset; do
		file_operator -W -c -o 6 -B "$blksize 1 -1" -t $fsize -l $count \
			$trunc_dir/trunc_$num > $STF_TMPDIR/mv.$NAME.$num.$$ 2>&1 &
		pids="$pids $!"
		((num = num + 1))
            done
        done
    done
done
echo ""

condition="(( \`cat $STF_TMPDIR/mv.$NAME.*.\$\$ | grep \"completed successfully\" \
	| wc -l | nawk '{print \$1}'\` == $num ))" 
wait_now 1800 "$condition"
if (( $? != 0 )); then
	nnum=$(cat $STF_TMPDIR/mv.$NAME.*.$$ | grep "completed successfully" \
		| wc -l | nawk '{print $1}')
	echo "ERROR: Only $nnum files are truncated sucessfully, \c"
	echo "but expected $num files trucated"
	typeset -i i=0
	while ((i < num)); do
		cat $STF_TMPDIR/mv.$NAME.$i.$$ | grep "completed successfully" > /dev/null 2>&1
		if (($? != 0 )); then
			echo "Failures found in $STF_TMPDIR/mv.$NAME.$i.$$ :"
			cat $STF_TMPDIR/mv.$NAME.$i.$$
		fi
	done
	assert_cleanup $STF_FAIL
fi

assert_cleanup $STF_PASS

