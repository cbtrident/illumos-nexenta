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

[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
	|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

function cleanup {
	retcode=$1
	rm -f $MNTDIR/endless_scr.$$
	exit $retcode
}

echo "execute a script file, get read delegation"

# cp executabl script to SHRDIR
RUN_CHECK copy_file_nodeleg \
	${STF_SUITE}/tests/delegation/bin/endless_scr \
	$MNTDIR/endless_scr.$$ || exit $STF_UNRESOLVED

# run a script file over NFS, check delegation type
$MNTDIR/endless_scr.$$ > $STF_TMPDIR/endless_scr.out.$$ 2>&1
if (( $? == 9 )); then
	print -u2 "failed to run $MNTDIR/endless_scr.$$"
	cleanup $STF_FAIL $STF_TMPDIR/endless_scr.out.$$
fi
deleg_type=$(get_deleg_type $MNTDIR/endless_scr.$$)
if [[ $deleg_type -ne $RD ]]; then
	print -u2 "unexpected delegation type($deleg_type) when executing file"
	cleanup $STF_FAIL
fi

# clean up 
cleanup $STF_PASS
