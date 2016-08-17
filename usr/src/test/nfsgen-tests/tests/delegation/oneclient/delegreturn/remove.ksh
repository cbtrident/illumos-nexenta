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
DIR=$(dirname $0)
typeset local_prog=$STF_SUITE/bin/file_operator

[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
        || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

echo "open a file RDONLY, get read delegation," 
echo "then remove it, check delegation is returned."

cd $MNTDIR
TESTFILE=testfile.$$
CMD1="chgusr_exec $DTESTUSER1 $local_prog -R -c -d -o 0 \
	-B \\\"1 1 -1\\\" testfile.$$"
DTYPE=$RD
CMD2="rm -f testfile.$$"

$DIR/delegreturn $TESTFILE "$CMD1" $DTYPE "$CMD2" 0 || return $STF_FAIL

echo "open a file RDWR, get write delegation," 
echo "then remove it, check delegation is returned."

CMD1="chgusr_exec $DTESTUSER1 $local_prog -W -c -d -o 4 \
	-B \\\"1 1 -1\\\" testfile.$$"
DTYPE=$WR
$DIR/delegreturn $TESTFILE "$CMD1" $DTYPE "$CMD2" 0 || return $STF_FAIL
