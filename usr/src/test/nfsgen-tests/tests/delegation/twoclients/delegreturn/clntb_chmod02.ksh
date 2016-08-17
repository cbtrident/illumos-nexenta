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

echo "client a opens a file RDWR, get write delegation; client b"
echo "changes its file permision attributes, client a returns delegation"

CLNT2_TESTDIR=$1
# skip with client2 mounting with v4
if [[ $CLNT2_TESTDIR == $CLNT2_MNTDIRV4 ]]; then
	echo "UNSUPPORTED: this assertion is not current supported when"
	echo "\tthe second client is also an NFSv4 client."
	exit $STF_UNSUPPORTED
fi

TESTFILE=$MNTDIR/testfile.$$
LOCAL_CMD="cd $MNTDIR && chgusr_exec $DTESTUSER1 $local_prog -W -c -d -o 4 \
	-B \\\"1 1 -1\\\" testfile.$$"
DTYPE=$WR
REMOTE_CMD="chmod 777 $CLNT2_TESTDIR/testfile.$$" 

$DIR/delegreturn2 $TESTFILE "$LOCAL_CMD" $DTYPE "$REMOTE_CMD"
