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

DIR=$(dirname $0)
NAME=$(basename $0)

. ${STF_SUITE}/include/nfsgen.kshlib

# Turn on debug info, if requested
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

# Umount it
RUN_CHECK umount $MNTDIR

# Call server script to do cleanup SHRDIR
RUN_CHECK RSH root $SERVER "$SRV_TMPDIR/$SETUP/srv_setup -c"

# Remove temp dir on server
RUN_CHECK RSH root $SERVER "rm -rf $SRV_TMPDIR/$SETUP"

exit $STF_PASS
