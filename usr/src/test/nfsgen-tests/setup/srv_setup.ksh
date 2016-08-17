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

# Include common STC utility functions for SMF
. ${DIR}/srv_env.vars
. ${DIR}/nfs-util.kshlib

# Turn on debug info, if requested
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

getopts sc opt
case $opt in
s)
	# Create test group
	groupdel $TGROUP >/dev/null 2>&1
	RUN_CHECK groupadd -g $TGID $TGROUP || exit 1
	# Create test user
	userdel $TUSER01 >/dev/null 2>&1
	RUN_CHECK useradd -u $TUID01 -g $TGROUP -d /tmp $TUSER01 || exit 1
	userdel $TUSER02 >/dev/null 2>&1
	RUN_CHECK useradd -u $TUID02 -g $TGROUP -d /tmp $TUSER02 || exit 1

	# Set mapid domain
	set_nfs_property NFSMAPID_DOMAIN $NFSMAPID_DOMAIN $DIR/mapid_backup \
	    || exit 1
	# Set delegation
	set_nfs_property NFS_SERVER_DELEGATION on $DIR/deleg_backup \
	    || exit 1
	;;
c)
	# Delete test user and group
	RUN_CHECK userdel $TUSER01 || exit 1
	RUN_CHECK userdel $TUSER02 || exit 1
	RUN_CHECK groupdel $TGROUP || exit 1

	# Restore mapid domain
	restore_nfs_property NFSMAPID_DOMAIN $DIR/mapid_backup || exit 1
	# Restore delegation
	restore_nfs_property NFS_SERVER_DELEGATION $DIR/deleg_backup || exit 1
	;;
\?) 
	echo $Usage
	exit 99
	;;
esac

exit 0
