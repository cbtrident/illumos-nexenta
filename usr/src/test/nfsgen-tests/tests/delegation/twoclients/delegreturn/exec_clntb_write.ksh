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
typeset remote_prog=$SRV_TMPDIR/delegation/bin/file_operator
typeset remote_chg_usr_exec=$SRV_TMPDIR/delegation/bin/chg_usr_exec

echo "client a executes a script file, GET read delegation"
echo "client b opens it RDWR, client a returns delegation"

[[ $IS_KRB5 == 1 ]] && KOPT="-k $KPASSWORD" || KOPT=""
CLNT2_TESTDIR=$1

TESTFILE=NOT_NEEDED
LOCAL_CMD="$MNTDIR/endless_scr.$$"
DTYPE=$RD
REMOTE_CMD=". $SRV_TMPDIR/delegation/bin/deleg.env && \
	cd $CLNT2_TESTDIR && $remote_chg_usr_exec $KOPT $DTESTUSER1 \
        \"$remote_prog -W -c -o 4 -B \\\"10 1 -1\\\" endless_scr.$$\""

RUN_CHECK cp -p \
${STF_SUITE}/tests/delegation/bin/get_deleg_type\
	$MNTDIR || exit $STF_UNRESOLVED

RUN_CHECK RSH root $CLIENT2 \
    "\"cp $SRV_TMPDIR/delegation/bin/endless_scr $CLNT2_TESTDIR/endless_scr.$$;\
    chmod 777 $CLNT2_TESTDIR/endless_scr.$$ \"" || exit $STF_UNRESOLVED

$DIR/delegreturn2 $TESTFILE "$LOCAL_CMD" $DTYPE "$REMOTE_CMD" 1 || exit $STF_FAIL
rm -f $MNTDIR/endless_scr.$$ $MNTDIR/get_deleg_type
