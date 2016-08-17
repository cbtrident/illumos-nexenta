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
	rm -f $MNTDIR/testfile.$$ $STF_TMPDIR/file_operator.*.$$
	exit $retcode
}

echo "open a file RDONLY, get read delegation"
echo "then reopen the file RDWR, get write delegation"

# create test file
RUN_CHECK create_file_nodeleg $MNTDIR/testfile.$$ || cleanup $STF_UNRESOLVED

# read test file over NFS, check delegation type
$prog -R -c -d -o 0 -B "1 1 -1" $MNTDIR/testfile.$$ \
	> $STF_TMPDIR/file_operator.outR.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/file_operator.outR.$$ \
        | nawk -F\= '{print $2'})
if [[ $deleg_type -ne $RD ]]; then
	print -u2 "unexpected delegation type($deleg_type) when reading file"
	cleanup $STF_FAIL
fi

# write test file over NFS, check delegation type
$prog -W -c -d -o 4 -B "1 1 -1" $MNTDIR/testfile.$$ \
	> $STF_TMPDIR/file_operator.outW.$$ 2>&1
deleg_type=$(grep "return_delegation_type" $STF_TMPDIR/file_operator.outW.$$ \
        | nawk -F\= '{print $2'})

if [[ $deleg_type -ne $WR ]]; then
        print -u2 "unexpected delegation type($deleg_type) when writing file"
        cleanup $STF_FAIL
fi

# clean up 
cleanup $STF_PASS
