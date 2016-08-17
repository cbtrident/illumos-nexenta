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

. ${STF_SUITE}/include/nfsgen.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

NAME=$(basename $0)
typeset prog=$STF_SUITE/bin/file_operator

[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
	|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

function cleanup {
	retcode=$1
	rm -f $MNTDIR/testfile.$$
	exit $retcode
}

echo "client a opens a file RDWR, get write delegation, then it modifies"
echo "the file. client b stats the file after acregmax seconds, verify"
echo "client b can get those changed attributes"

CLNT2_TESTDIR=$1

# create test file
RUN_CHECK create_file_nodeleg $MNTDIR/testfile.$$ || cleanup $STF_UNRESOLVED

# write test file over NFS, check delegation type
$prog -W -c -d -o 4 -B "32768 10 -1" $MNTDIR/testfile.$$ \
	> $STF_TMPDIR/local.out.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/local.out.$$ \
        | nawk -F\= '{print $2'})
if [[ $deleg_type -ne $WR ]]; then
	print -u2 "unexpected delegation type($deleg_type) when reading file"
	cleanup $STF_FAIL
fi

# stat the file on 2nd client
RUN_CHECK RSH root $CLIENT2 "/usr/bin/stat -c %s,%Z $CLNT2_TESTDIR/testfile.$$" \
    > $STF_TMPDIR/stat.out || cleanup $STF_UNRESOLVED

size=$(nawk -F\, '{print $1}' $STF_TMPDIR/stat.out)
mtime=$(nawk -F\, '{print $2}' $STF_TMPDIR/stat.out)

for i in 1 2 3; do
	sleep 2
	$prog -W -c -o 2 -B "10 1 -1" -d $MNTDIR/testfile.$$ \
		> $STF_TMPDIR/$NAME.append.out.$$ 2>&1
	grep "completed successfully" $STF_TMPDIR/$NAME.append.out.$$ \
		> /dev/null 2>&1
	if (( $? != 0 )); then
		echo "client a failed to append data into the file"
		rm -f $STF_TMPDIR/$NAME.append.out.$$
		cleanup $STF_FAIL
	fi

	# 60 seconds is the default upper bound (see man mount_nfs -o acregmax)
	# plus 5 more to avoid a race with kernel cached attrs updates
	ti=0
	to=65
	inc=5
	while ((ti <= to)); do
	    sleep $inc
	    ti=$((ti + inc))
	    RUN_CHECK RSH root $CLIENT2 "/usr/bin/stat -c %s,%Z $CLNT2_TESTDIR/testfile.$$" \
	      > $STF_TMPDIR/stat.out || cleanup $STF_UNRESOLVED
	    nsize=$(nawk -F\, '{print $1}' $STF_TMPDIR/stat.out)
	    (( nsize == size + 10 )) && break
	done

	if (( nsize != size + 10 )); then
		print -u2 "previous size : $size, current size: $nsize"
		print -u2 "stat result on $CLIENT: ls -l $MNTDIR/testfile.$$"
		ls -l $MNTDIR/testfile.$$ 1>&2
		cleanup $STF_FAIL
	fi

	nmtime=$(nawk -F\, '{print $2}' $STF_TMPDIR/stat.out) 
	if (( nmtime <= mtime )); then
		print -u2 "previous mtime : $mtime, current mtime: $nmtime"
		print -u2 "stat result on $CLIENT: ls -l $MNTDIR/testfile.$$"
		ls -l $MNTDIR/testfile.$$ 1>&2
		cleanup $STF_FAIL
	fi

	size=$nsize
	mtime=$nmtime
done

# clean up 
cleanup $STF_PASS
