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
# ident	"@(#)srv_setup.ksh	1.1	09/04/27 SMI"
#

#
# setup the $SERVER for testing NFS V4 recovery testing by:
# first removing LOFI file systems setup prior to recovery
# test execution. Setup server with testfiles, export it,
# start reboot/restart daemon.
#

NAME=$(basename $0)

SetDebugMode
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

id | grep "0(root)" > /dev/null 2>&1
if (( $? != 0 )); then
        echo "$NAME: ERROR - Must be root to run this script for setup."
        exit 1
fi

Usage="Usage: $NAME -s | -r | -c \n
		-s: to setup this host w/daemon, testfiles, and share\n
		-r: restore share after reboot\n
		-c: to cleanup the server\n
"

if (( $# < 1 )); then
	echo "$NAME: ERROR - incorrect usage."
	echo $Usage
	exit 2
fi

ENVFILE=ENV_from_client
STF_TMPDIR=Tmpdir_from_client
NFSUTILFILE=NFS_UTIL
TestZFS=TEST_ZFS
SHRDIR=SHR_DIR
SHROPT=SHR_OPT
SHRGRP=SHR_GRP

# source the environment/config file from client to be consistent
. $STF_TMPDIR/$ENVFILE
. $STF_TMPDIR/$NFSUTILFILE

getopts src opt
case $opt in
  s)
	# make sure nfs4red reboot/reset-nfsd daemon is running
	chmod +x $STF_TMPDIR/nfs4red > /dev/null 2>&1
	$STF_TMPDIR/nfs4red > /dev/null 2>&1 &
	ps -e | grep -w "nfs4red" > /dev/null
	if (( $? != 0 )); then
		$STF_TMPDIR/nfs4red > /dev/null 2>&1 &
	fi
	
	echo "Done - setup nfs4red OKAY."
        rm -f ${STF_TMPDIR}/*.out.$$ ${STF_TMPDIR}/err.*
        ;;

  r)
	# restore share mount
	# check already shared
	shared=$(share | grep $SHRDIR)
	[[ -n $shared ]] && exit 0

	sharemgr_share $SHRGRP $SHRDIR $SHROPT
	if (( $? != 0 )); then
		exit 3
	fi
	;;

  c) 
	pkill -x -u 0 nfs4red 

        echo "Done - recovery cleanup of test filesystems/daemons OKAY"
	cd $STF_TMPDIR
        rm -f *.out.* recov_setserver nfs4red /etc/rc3.d/S99nfs4red
        ;;

  \?) 
	echo $Usage
	exit 2
	;;
esac

exit 0
