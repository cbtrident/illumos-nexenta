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

DIR=$(dirname $0)
typeset local_prog=$STF_SUITE/bin/file_operator

echo "client a opens a script file RDWR, get write delegation"
echo "client b executes it, client a returns delegation"

CLNT2_TESTDIR=$1

TESTFILE=NOT_NEEDED
typeset prog=$STF_SUITE/bin/$(uname -p)/file_operator
LOCAL_CMD="cd $MNTDIR && chgusr_exec $DTESTUSER1 $local_prog -W -c -d -o 4 \
	-B \\\"1 1 -1\\\" endless_scr.$$"

DTYPE=$WR
REMOTE_CMD="$CLNT2_TESTDIR/endless_scr.$$ -n"

RUN_CHECK RSH root $CLIENT2 \
    "\"cp $SRV_TMPDIR/delegation/bin/endless_scr $CLNT2_TESTDIR/endless_scr.$$;\
    chmod 777 $CLNT2_TESTDIR/endless_scr.$$\"" || exit $STF_UNRESOLVED

$DIR/delegreturn2 $TESTFILE "$LOCAL_CMD" $DTYPE "$REMOTE_CMD" || exit $STF_FAIL
rm -f $MNTDIR/endless_scr.$$
