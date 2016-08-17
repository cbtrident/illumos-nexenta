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

[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
        || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

# cp executable binary to SHRDIR on server
RUN_CHECK copy_file_nodeleg \
  ${STF_SUITE}/tests/delegation/bin/endless_exe\
    $MNTDIR/endless_exe.$$ || cleanup $STF_UNRESOLVED

echo "execute a binary file, get read delegation," 
echo "then umount filesystem, check delegation is returned."

TESTFILE=NOT_NEEDED
realMNT=$(get_realMNT $MNTDIR 2> $STF_TMPDIR/$NAME.err.$$)
(( $? != 0 )) && cleanup $STF_UNRESOLVED $STF_TMPDIR/$NAME.err.$$

CMD1="$MNTDIR/endless_exe.$$ > /dev/null"
DTYPE=$RD
CMD2="/usr/sbin/umount $realMNT"

$DIR/delegreturn $TESTFILE "$CMD1" $DTYPE "$CMD2" || \
	cleanup $STF_FAIL "" "$STF_TMPDIR/$NAME.err.$$ $MNTDIR/endless_exe.$$"
rm -f $STF_TMPDIR/*.err.$$ $MNTDIR/endless_exe.$$
