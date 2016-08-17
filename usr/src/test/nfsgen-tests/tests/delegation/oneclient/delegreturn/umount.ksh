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
NAME=$(basename $0)
typeset prog=$STF_SUITE/bin/file_operator

[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
        || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

echo "open a file RDONLY, get read delegation,"
echo "then umount filesystem, check delegation is returned."

TESTFILE=$MNTDIR/testfile.$$
realMNT=$(get_realMNT $MNTDIR 2> $STF_TMPDIR/$NAME.err.$$)
(( $? != 0 )) && cleanup $STF_UNINITIATED $STF_TMPDIR/$NAME.err.$$

CWD=$(pwd)
CMD1="cd $MNTDIR && chgusr_exec $DTESTUSER1 $prog -R -c -d -o 0 \
	-B \\\"1 1 -1\\\" testfile.$$"
DTYPE=$RD
CMD2="cd $CWD && /usr/sbin/umount $realMNT"

$DIR/delegreturn $TESTFILE "$CMD1" $DTYPE "$CMD2" 0 || \
	cleanup $STF_FAIL "" $STF_TMPDIR/$NAME.err.$$

echo "open a file RDWR, get write delegation,"
echo "then umount filesystem, check delegation is returned."

CMD1="cd $MNTDIR && chgusr_exec $DTESTUSER1 $prog -W -c -d -o 2 \
	-B \\\"1 1 -1\\\" testfile.$$"

DTYPE=$WR
$DIR/delegreturn $TESTFILE "$CMD1" $DTYPE "$CMD2" 0 || \
	cleanup $STF_FAIL "" $STF_TMPDIR/$NAME.err.$$
rm -f $STF_TMPDIR/*.err.$$
