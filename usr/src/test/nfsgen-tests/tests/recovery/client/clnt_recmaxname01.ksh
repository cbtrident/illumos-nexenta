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
# Client recovery with a file with a long path name
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

# Turn on debugging if DEBUG variable is set.
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
PATH=/usr/bin:.:$PATH

export RECOVERY_EXECUTE_PATH=$DIR
export RECOVERY_STAT_PATH=$STF_SUITE/bin/
prog=$STF_SUITE/bin/file_operator
if [[ ! -x $prog ]]; then
        echo "$NAME: test program '$prog' not found or not exexutable"
        echo "\t Test UNINITIATED"
        return $STF_UNINITIATED
fi

function internalCleanup 
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
   rc=$1
   Nmnt=$2
   rm -fr $Nmnt/d
   umount -f $Nmnt
   (( $rc == 0 )) && rm -f $STF_TMPDIR/${NAME}*.$$
   rmdir $Nmnt
   exit $rc
}

# First check this test is not started before previous tests
# grace period ends.
echo "xxx" > $MNTDIR/wait_for_grace
if (( $? != 0 )); then
        echo "cannot create file: $MNTDIR/wait_for_grace"
        touch $MNTDIR/wait_for_grace
        ls $MNTDIR
        exit $STF_FAIL
fi
rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

# Start test
# --------------------------------------------------------------------
function assertion_func
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

   typeset longfile=$1
   typeset Nmnt=$2
   typeset actionType=$3

   $prog -W -c -u -o 4 -s 800 -L "1 1 0 0" -B "32768 1024 1024" $longfile \
	> $STF_TMPDIR/$NAME.lck.$$ 2>&1 &
   pid1=$!
   wait_now 200 "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.lck.$$" \
	> /dev/null 2>&1
   if (( $? != 0 )); then
        echo "\t Test FAIL: failed to make 1st write lock within 200 seconds"
	cat $STF_TMPDIR/$NAME.lck.$$
	kill $pid1 > /dev/null 2>&1
	internalCleanup $STF_FAIL $Nmnt
   fi

   # now signal server to reboot
   $DIR/isserverup $actionType > $STF_TMPDIR/$NAME.reboot.$$ 2>&1
   if (( $? != 0 )); then
        echo "\t Test UNRESOLVED: failed to $actionType on $SERVER"
	cat $STF_TMPDIR/$NAME.reboot.$$
	kill $pid1 > /dev/null 2>&1
	internalCleanup $STF_UNRESOLVED $Nmnt
   fi

   sleep 5
   # verify the lock still valid in the file
   $prog -W -c -o 4 -L "1 0 0 0" -B "0 0 -1" $longfile > $STF_TMPDIR/$NAME.lck2.$$ 2>&1
   wait_now 200 "grep \"unavailable\" $STF_TMPDIR/$NAME.lck2.$$" > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "\t Test FAIL: second lock did not fail"
	cat $STF_TMPDIR/$NAME.lck2.$$
	kill $pid1 > /dev/null 2>&1
	internalCleanup $STF_FAIL $Nmnt
   fi

   kill $pid1 > /dev/null 2>&1
   rm $longfile

   echo "\tTest PASS"
   return $STF_PASS
}


# Start main program here:
# ----------------------------------------------------------------------
# Get the system maxpathlen and build the path
MLEN=$(grep -w MAXPATHLEN /usr/include/sys/param.h | \
	grep '^\#define' | awk '{print $3}')
NCH=$(echo "$ZONE_PATH/a" | wc -c)	# the mntptr '$ZONE_PATH/a' and NULL
(( NCH = NCH + 2 ))			# the file '/f'
Nlen=$(($MLEN - $NCH))
(( $Nlen % 2 == 0 )) && Nmnt="$ZONE_PATH/a" || Nmnt="$ZONE_PATH/az"
Mdir="$Nmnt"
i=1
while (( $i < $Nlen )); do
	Mdir="$Mdir/d"
	i=$(($i + 2))
done

# Now mount the test directory to '/a"
[ ! -d $Nmnt ] && mkdir -m 0777 -p $Nmnt
umount $Nmnt > /dev/null 2>&1
mount -F nfs -o ${MNTOPT} ${SERVER}:${SHRDIR} $Nmnt \
	> $STF_TMPDIR/$NAME.mnt.$$ 2>&1
if (( $? != 0 )); then
	echo "$NAME: test setup"
	echo "\t Test UNINITIATED: failed to mount [${SERVER}:${SHRDIR}]"
	cat $STF_TMPDIR/${NAME}.mnt.$$
	internalCleanup $STF_UNINITIATED $Nmnt
fi

mkdir -p $Mdir
Lfile="$Mdir/f"

#----------------------------------
As_a="Client locks a maxpathlen file, then server reboot;\n\t"
As_a="$As verify the lock still valid, expect OK"
As_b="Client locks a maxpathlen file, then server restart-nfsd;\n\t"
As_b="$Bs verify the lock still valid, expect OK"

echo "$NAME{a}: $As_a"
assertion_func $Lfile $Nmnt "reboot"
retcode=$?

echo "$NAME{a}: $As_b"
assertion_func $Lfile $Nmnt "reset-nfsd"
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) && internalCleanup $STF_PASS $Nmnt || internalCleanup $STF_FAIL $Nmnt
