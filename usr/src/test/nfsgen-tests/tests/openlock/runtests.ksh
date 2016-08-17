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

NAME=$(basename $0)

. ${STF_SUITE}/include/nfsgen.kshlib

# Turn on debug info, if requested
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

USAGE="Usage: runtests Test_name deleg scenario mode_index oflag_index"

export Tprog=$1
export Tname=$2
export deleg=$3
export SCENARIO=$4
export MODE_INDEX=$5
export OFLAG_INDEX=$6

if (( $# < 5 )); then
	echo "$USAGE"
	cleanup $STF_UNRESOLVED
fi

if [[ $deleg != none ]]; then
	# set delegation on the server
	# but only do it once if testing the same scenaior
	if [[ ! -f $STF_TMPDIR/deleg_been_set || \
	    `cat $STF_TMPDIR/deleg_been_set` != "$deleg" ]]; then
		RSH root $SERVER \
		    ". $SRV_TMPDIR/srv_env.vars && \
		    . $SRV_TMPDIR/nfs-util.kshlib && \
		    set_nfs_property NFS_SERVER_DELEGATION $deleg" \
			> $STF_TMPDIR/set_deleg.$$ 2>&1
		if (( $? != 0 )); then
			echo "ERROR: failed to set delegation on the server"
			cat $STF_TMPDIR/set_deleg.$$
			cleanup $STF_UNINITIATED
		else
			echo "$deleg" > $STF_TMPDIR/deleg_been_set
		fi
	fi
fi

[[ :${NFSGEN_DEBUG}: == *:opentest:* \
        || :${NFSGEN_DEBUG}: == *:all:* ]] && DPRINT="-d 2"


# In TX config, a regular user has no permission to access
# label path, we need to enter the path as root, then operate
# test file with relative path.
cd $MNTDIR

$Tprog $DPRINT -u $TUID01 -g $TGID -U 60001 -G 60001 -eWS \
	-l $NAME.$CLIENT.$$ $MNTDIR
cleanup $?
