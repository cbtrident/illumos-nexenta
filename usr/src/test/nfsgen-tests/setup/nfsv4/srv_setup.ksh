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

Usage="Usage: $NAME -s | -c \n
		-s: to setup the server\n
		-c: to cleanup the server\n
"
if (( $# < 1 )); then
	echo $Usage
	exit 99
fi

# Include common STC utility functions
. ${DIR}/srv_env.vars
. ${DIR}/nfs-util.kshlib

# Turn on debug info, if requested
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

getopts sc opt
case $opt in
s)
	RUN_CHECK mkdir -p $SHRDIR || exit 1

	# Check fs type on the server
	RUN_CHECK get_fstype $SHRDIR || exit 1 

	# share it
	RUN_CHECK sharemgr_share $SHRGRP $SHRDIR $SHROPT || exit 1

	RUN_CHECK chmod 777 $SHRDIR || exit 1
	;;
c)
	RUN_CHECK sharemgr_unshare $SHRGRP $SHRDIR || exit 1
	RUN_CHECK rm -rf $SHRDIR || exit 1
	;;
\?) 
	echo $Usage
	exit 99
	;;
esac

exit 0
