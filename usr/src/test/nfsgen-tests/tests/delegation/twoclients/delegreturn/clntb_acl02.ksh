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

. ${STF_TOOLS}/include/stf.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib
typeset local_prog=$STF_SUITE/bin/file_operator

DIR=$(dirname $0)

echo "client a opens a file RDWR, get write delegation"
echo "client b changes its ACL attributes, client a returns delegation"

CLNT2_TESTDIR=$1
ISv4=$(echo $CLNT2_TESTDIR | grep "_v4")

TESTFILE=$MNTDIR/testfile.$$
LOCAL_CMD="cd $MNTDIR && chgusr_exec $DTESTUSER1 $local_prog -W -c -d -o 4 \
	-B \\\"1 1 -1\\\" testfile.$$"
DTYPE=$WR
if [[ $TestZFS == 1 ]]; then
    if [[ -n $ISv4 ]]; then 
       REMOTE_CMD="chmod A+user:root:read_data:allow $CLNT2_TESTDIR/testfile.$$"
    else
       echo "Setting ACL for NFSv3 or NFSv2 client with ZFS is not supported"
       echo "Skip this test ..."
       exit $STF_UNSUPPORTED
    fi
else
    #REMOTE_CMD="chmod A+user:root:r-- $CLNT2_TESTDIR/testfile.$$" 
    REMOTE_CMD="setfacl -m user:root:r-- $CLNT2_TESTDIR/testfile.$$"
fi

$DIR/delegreturn2 $TESTFILE "$LOCAL_CMD" $DTYPE "$REMOTE_CMD"
