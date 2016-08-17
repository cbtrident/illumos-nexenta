#! /bin/sh
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
# ident	"@(#)S99nfs4red.sh	1.1	09/04/27 SMI"
#

NAME=`basename $0`

# Script to restart the 'nfs4red' after system reboot.
# This should be installed at /etc/rc3.d as 'S99nfs4red'
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

[ ! -d /usr/bin ] && exit

id | grep "0(root)" > /dev/null 2>&1
if [ $? -ne 0 ]; then
        echo "$NAME: This script require root permission to run."
        exit 99
fi

ENVFILE=ENV_from_client
STF_TMPDIR=Tmpdir_from_client

# source the environment/config file from client to be consistent
. $STF_TMPDIR/$ENVFILE

NOTICEDIR=$SHRDIR/._Notice__Dir_.
LPROG=$STF_TMPDIR/nfs4red

if [ ! -d $NOTICEDIR ]; then
	echo "$NAME: NOTICEDIR=[$NOTICEDIR] not found"
	exit 2
fi
rm -f $NOTICEDIR/re* $NOTICEDIR/DONE_reboot

if [ ! -x $LPROG ]; then
	echo "$NAME: LPROG=[$LPROG] not found/executable"
	exit 2
fi
echo "$LPROG \c"
$LPROG &
echo "started"

# nfsd should be started by now,  notify client
i=5
timer=2
while [ $i -le $timer ]
do
	pgrep nfsd > /dev/null 2>&1 
	if [ $? -eq 0 ]; then
		i="OK"
		break
	fi
	i=`expr $i + 1`
	sleep 2
done
if [ $i = "OK" ]; then
        echo "ReBoot NFSD(`pgrep nfsd`) started" > $NOTICEDIR/DONE_reboot
else
        echo "ReBoot: nfsd STF_FAILed" > $NOTICEDIR/DONE_reboot
fi
	
exit 0
