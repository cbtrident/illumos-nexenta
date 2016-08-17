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

. $STF_SUITE/tests/acl/acl_common.kshlib

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

if [[ $SETUP == nfsv4 && ${TestZFS} != 1 ]]; then
	echo "Exported filesystem on server side is not ZFS, ACL tests won't run"
	exit $STF_UNSUPPORTED
fi

RUN_CHECK $CD $MNTDIR || exit $STF_PASS
RUN_CHECK $MKDIR -p $TESTDIR || exit $STF_PASS
RUN_CHECK $CHMOD 777 $TESTDIR || exit $STF_PASS

exit $STF_PASS
