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
# ident	"@(#)nfs4red.ksh	1.1	09/04/27 SMI"
#

NAME=$(basename $0)

SetDebugMode
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

id | grep "0(root)" > /dev/null 2>&1
if (( $? != 0 )); then
        echo "$NAME: This script require root permission to run."
        exit 99
fi

ENVFILE=ENV_from_client
STF_TMPDIR=Tmpdir_from_client

# source the environment/config file from client to be consistent
. $STF_TMPDIR/$ENVFILE

NOTICEDIR=$SHRDIR/._Notice__Dir_.

[[ ! -d $NOTICEDIR ]] && mkdir -m 0777 -p $NOTICEDIR || chmod 0777 $NOTICEDIR

fmri=svc:/network/nfs/server:default
timeout=10

# call recov_setserver -r
rm -f ${STF_TMPDIR}/share_restore.log $SHRDIR/shr_r.error $SHRDIR/shr_r.success
/usr/bin/ksh ${STF_TMPDIR}/recov_setserver -r > ${STF_TMPDIR}/share_restore.log 2>&1
if (( $? != 0 )); then
	share >> ${STF_TMPDIR}/share_restore.log 2>&1
	touch $SHRDIR/shr_r.error
	chmod 0777 $SHRDIR/shr_r.error
else
	touch $SHRDIR/shr_r.success
	chmod 0777 $SHRDIR/shr_r.success
fi

while :; do
	sleep 2
	action=$(ls -d $NOTICEDIR/re* 2>/dev/null | nawk -F\/ '{print $NF}')

	case $action in
	  reset-nfsd)
		echo "Restarting the 'nfsd' in $(uname -n) ..."
		rm -f $NOTICEDIR/DONE_reset
		svcadm disable ${fmri}

		pkill -x -u 0 nfsd
		sleep 1

		svcadm enable ${fmri}
		timer=${timeout}
		sleep 2
		/usr/bin/ksh ${STF_TMPDIR}/recov_setserver -r > ${STF_TMPDIR}/share_restore.log 2>&1
		if (( $? != 0 )); then
			echo "failed to re-share" > $NOTICEDIR/DONE_reset
		fi
		i=1
		while (( $i <= $timer )); do
			pgrep nfsd > /dev/null 2>&1
			if (( $? == 0 )); then
				i="OK"
				break
			fi
			i=$(($i+1))
			sleep 1
		done
		if [[ "$i" == "OK" ]]; then
			echo "ReSet NFSD($(pgrep nfsd)) started" > $NOTICEDIR/DONE_reset
		else
			echo "ReSet nfsd STF_FAILed" > $NOTICEDIR/DONE_reset
		fi
		;;
	  reboot)
		echo "Rebooting $(uname -n), please wait ..."
		rm -f $NOTICEDIR/DONE_reboot
		rm -f $NOTICEDIR/re*
		sync; sync; reboot 
		;;
	  requit)
		rm -f $NOTICEDIR/re*
		break;;
	  *)
		continue;;

	esac
	rm -f $NOTICEDIR/re*
done
exit 0
