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

NAME=$(basename $0)

[[ :${NFSGEN_DEBUG}: == *:${NAME}:* || :${NFSGEN_DEBUG}: == *:all:* ]] \
	&& set -x

[[ $SETUP == "none" ]] && \
	echo "$NAME: SETUP=<$SETUP> is not supported for this subdir" && \
	exit $STF_PASS

# setup MNTDIR2 for tests which need to run other process access from MNTDIR2
if [[ $MNTDIR2 != $MNTDIR ]]; then
        RUN_CHECK mkdir -p -m 0777 $MNTDIR2 || exit $STF_UNINITIATED
        RUN_CHECK mount -o $MNTOPT2 $SERVER:$SHRDIR $MNTDIR2 || exit $STF_UNINITIATED
fi

# setup on SERVER for some recovery tests
RUN_CHECK RSH root $SERVER mkdir -p -m 0777 $SRV_TMPDIR/recovery/bin \
        || exit $STF_UNINITIATED
filelist="${STF_SUITE}/lib/$SERVER_ARCH/libnfsgen.so \
        ${STF_SUITE}/bin/$SERVER_ARCH/file_operator"
if [[ $SERVER_BIN_USED == 0 ]]; then
	RUN_CHECK scp $filelist root@$SERVER:$SRV_TMPDIR/recovery/bin \
		|| exit $STF_UNINITIATED
else
	RUN_CHECK RSH root $SERVER "cp $filelist $SRV_TMPDIR/recovery/bin" \
		|| exit $STF_UNINITIATED
fi

exit $STF_PASS
