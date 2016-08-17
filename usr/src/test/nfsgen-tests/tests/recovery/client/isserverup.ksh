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

#
#  script to talk to reboot/restart daemon and check when
#  server is alive again for NFSv4 client recovery tests
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

if (( $# != 1 ))
then
	print -u2 "Usage: $0 <reboot|reset-nfsd>"
	exit $STF_FAIL
fi

function resetNfsdOnServer
{
        [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
                && set -x

        RUN_CHECK rm -f $MNTDIR/$NOTICEDIR/DONE_* || return $STF_FAIL
        RUN_CHECK touch $MNTDIR/$NOTICEDIR/reset-nfsd || return $STF_FAIL
        resultfile=$MNTDIR/$NOTICEDIR/DONE_reset
        sleep 15

        # check nfsd on SERVER restarted
        maxtry=5
        i=1
	while (( $i <= $maxtry )); do
                if [[ -f $resultfile ]]; then
                        grep "started" $resultfile
                        if (( $? != 0 )); then
                                cat $resultfile
				echo "nfsd not started"
                                return $STF_FAIL
                        else
				echo "nfsd started"
                                return $STF_PASS
                        fi
                else
                        i=$(($i+1))
                        sleep 5
                fi
        done

	echo "nfsd not started"
        return $STF_FAIL
}

COMMAND=$1

case $COMMAND in
	reboot) touch $MNTDIR/$NOTICEDIR/reboot
		# Ping until down
		wait_now $REBOOTIMER "! ping $rhost 5 > /dev/null 2>&1"
		if (( $? != 0 )); then
			echo "$SERVER did not reboot within $REBOOTIMER seconds"
			exit $STF_FAIL
		fi

		echo $SERVER is now DEAD

		# Ping until up
		if /usr/sbin/ping $SERVER $REBOOTIMER >/dev/null 2>&1
		then
		    echo $SERVER is now ALIVE
                    wait_now 600 "ls $MNTDIR/shr_r.success > /dev/null 2>&1"
                    if (( $? != 0 )); then
                        echo "SERVER($SERVER) didn't export $SHRDIR whithin 10 mins"
                        cat $MNTDIR/share_restore.log
			rm -f $MNTDIR/shr_r.success $MNTDIR/shr_r.error $MNTDIR/share_restore.log
			exit $STF_FAIL
                    else
		        echo "check SHRDIR:$SHRDIR restore success"
			rm -f $MNTDIR/shr_r.success $MNTDIR/shr_r.error $MNTDIR/share_restore.log
			exit $STF_PASS
                    fi
		else
		    echo $SERVER never came back up after $REBOOTIMER seconds
		    exit $STF_FAIL
		fi
		;;

	reset-nfsd) 
		resetNfsdOnServer
		exit $?
		;;
		
*) print -u2 "Invalid command: $COMMAND"
esac

exit $STF_FAIL
