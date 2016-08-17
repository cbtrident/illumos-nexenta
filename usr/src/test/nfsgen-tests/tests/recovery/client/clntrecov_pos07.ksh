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
# NFSv4 process recovery:
# a: Verify process1 recovers after process2 locks
#    an overlapped region of the same file after server reboot, expect OK
# b: Verify process1 recovers after process2 locks
#    an overlapped region of the same file after server nfsd-reset , expect OK
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
PATH=/usr/bin:$PATH

prog=$STF_SUITE/bin/file_operator
if [[ ! -x $prog ]]; then
        echo "$NAME: the executable program '$prog' not found."
   	echo "\t Test UNINITIATED"
   	exit $STF_UNINITIATED
fi


# First check this test is not started before previous tests
# grace period ends.
echo "xxx" > $MNTDIR/wait_for_grace
rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

TESTFILE="openfile.$$"


function assertion_func 
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

   typeset actionType=$1
   typeset -i timer=REBOOTIMER/60

   # process1 locks region 0-20 of a file:
   $prog -W -c -u -o 4 -s $(expr $REBOOTIMER + 300) -L "1 0 0 21" -B "0 0 0" \
	 $MNTDIR/$TESTFILE > $STF_TMPDIR/$NAME.out.$$ &
   pid1=$!

   wait_now 200 "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.$$" > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "$NAME: process1 did not have 0-(20-1) bytes locked?"
	cat $STF_TMPDIR/$NAME.out.$$
	kill $pid1 > /dev/null 2>&1
	rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
	echo "\t Test FAIL" 
        return $STF_FAIL
   fi

   # Reboot SERVER or restart nfsd on server
   $DIR/isserverup $actionType > $STF_TMPDIR/$NAME.srv.$$ 2>&1
   if (( $? != 0 )); then
        echo "$NAME: $actionType on SERVER failed in $timer minutes"
	cat $STF_TMPDIR/$NAME.srv.$$
	kill $pid1 > /dev/null 2>&1
	rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
        return $STF_FAIL
   fi

   # Now process2 tries to lock the same file on an overlapped region
   $prog -W -c -u -o 4 -s 30 -L "1 0 19 30" -B "0 0 -1" $MNTDIR2/$TESTFILE \
	> $STF_TMPDIR/$NAME.out2.$$ 2>&1
   kill $pid1 > /dev/null 2>&1

   grep "unavailable" $STF_TMPDIR/$NAME.out2.$$ > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "$NAME: $SERVER's reboot cleared process1 locks"
	cat $STF_TMPDIR/$NAME.out2.$$
	rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
   echo "\tTest PASS"
   return $STF_PASS
}


# Start main program here:
# ----------------------------------------------------------------------
ASSERTION_a=" Verify process1 recovers after process2 locks \
        an overlapped region of the same file after server reboot, expect sucess"
ASSERTION_b="Verify process1 recovers after process2 attempts to lock \
        an overlapped region of thesame file after nfsd dies and restarts, expect sucess"

echo "$NAME{b}: $ASSERTION_b"
assertion_func "reset-nfsd"
retcode=$?

echo "$NAME{a}: $ASSERTION_a"
assertion_func "reboot"
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) && cleanup $STF_PASS || cleanup $STF_FAIL

