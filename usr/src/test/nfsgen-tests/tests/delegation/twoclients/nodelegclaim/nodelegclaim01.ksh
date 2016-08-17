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

. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

DIR=$(dirname $0)
typeset local_prog=$STF_SUITE/bin/file_operator
typeset remote_prog=$SRV_TMPDIR/delegation/bin/file_operator
typeset remote_chg_usr_exec=$SRV_TMPDIR/delegation/bin/chg_usr_exec

echo "client a opens a file RDONLY, get read delegation, then it reopens"
echo "the file RDONLY, then client b opens the file RDWR to cause a recall,"
echo "verify client a successfully sends delegreturn without sending"
echo "claim_deleg_cur" 

[[ $IS_KRB5 == 1 ]] && KOPT="-k $KPASSWORD" || KOPT=""
CLNT2_TESTDIR=$1

TESTFILE=$MNTDIR/testfile.$$
LCMD1="cd $MNTDIR && chgusr_exec $DTESTUSER1 $local_prog -R -c -d -o 0 \
	-B \\\"1 1 -1\\\" testfile.$$"
LCMD2="cd $MNTDIR && chgusr_exec $DTESTUSER1 $local_prog -R -c -d -o 0 \
	-B \\\"1 1 -1\\\" testfile.$$"
RCMD=". $SRV_TMPDIR/delegation/bin/deleg.env && \
	cd $CLNT2_TESTDIR && $remote_chg_usr_exec $KOPT $DTESTUSER1 \
        $remote_prog -W -c -o 4 -B \\\"1 1 -1\\\" testfile.$$"

DTYPE1=$RD
DTYPE2=$RD

$DIR/nodelegclaim $TESTFILE "$LCMD1" $DTYPE1 "$LCMD2" $DTYPE2 "$RCMD"
