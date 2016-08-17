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

. ${STF_SUITE}/include/nfs-util.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

NAME=$(basename $0)

# Turn on debug info, if requested
[[ :${NFSGEN_DEBUG}: == *:${NAME}:* \
        || :${NFSGEN_DEBUG}: == *:all:* ]] && set -x

[[ $SETUP == "none" ]] && exit 0

# Make sure server delegation is enabled
server_delegation=$(RUN_CHECK RSH root $SERVER \
    "sharectl get nfs | grep server_delegation | cut -d= -f2")
if [[ $server_delegation != on ]]; then
	RUN_CHECK RSH root $SERVER \
	    "sharectl set -p server_delegation=on nfs" || exit 1
	touch $STF_TMPDIR/.SERVER_DELEGATION_OFF
fi
