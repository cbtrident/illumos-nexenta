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
. ${STF_SUITE}/include/nfs-util.kshlib

# Turn on debug info, if requested
NAME=$(basename $0)
[[ :${NFSGEN_DEBUG}: == *:${NAME}:* \
        || :${NFSGEN_DEBUG}: == *:all:* ]] && set -x

rm -f $MNTDIR/testfile.*.tmp $STF_TMPDIR/deleg.env

if [[ -z $CLIENT2 ]] || \
    [[ $SERVER == $CLIENT2 && $SETUP == "none" ]]; then
        echo "No cleanup is needed"
        exit $STF_PASS
fi

if [[ $SERVER == $CLIENT2 ]]; then
	RUN_CHECK RSH root $CLIENT2 "rm -rf $SRV_TMPDIR/delegation" || \
		exit $STF_WARNING
else
	if [[ -z $ZONE_PATH ]]; then
		RUN_CHECK RSH root $CLIENT2 \
		    "\"umount $CLNT2_MNTDIRV4 && \
		    umount $CLNT2_MNTDIRV3 && umount $CLNT2_MNTDIRV2 && rm -fr \
		    $SRV_TMPDIR/delegation $CLNT2_MNTDIRV4 $CLNT2_MNTDIRV3 $CLNT2_MNTDIRV2\"" || \
			exit $STF_FAIL
	else
		RUN_CHECK RSH root $CLIENT2 \
		    "\"umount $CLNT2_MNTDIRV4 && \
		    umount $CLNT2_MNTDIRV3 && rm -fr \
		    $SRV_TMPDIR/delegation $CLNT2_MNTDIRV4 $CLNT2_MNTDIRV3\"" || \
			exit $STF_FAIL
	fi
fi

exit $STF_PASS
