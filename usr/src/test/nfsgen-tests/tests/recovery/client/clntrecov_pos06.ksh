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
# NFSv4 client recovery:
# a: Verify process1 recovers after process2 attempts to lock 
#    same file after server reboots, expect OK
# b: Verify process1 recovers after process2 attempts to lock 
#    same file after nfsd dies and restarts, expect OK
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
PATH=/usr/bin:$PATH

export RECOVERY_EXECUTE_PATH=$DIR
export RECOVERY_STAT_PATH=$STF_SUITE/bin/

prog=$STF_SUITE/bin/file_operator
if [[ ! -x $prog ]]; then
        echo "$NAME: the executable program '$prog' not found."
   	echo "\t Test UNINITIATED"
   	exit $STF_UNINITIATED
fi


cd $MNTDIR
# First check this test is not started before previous tests
# grace period ends.
echo "xxx" >  $MNTDIR/wait_for_grace
rm -rf wait_for_grace > /dev/null 2>&1

TESTFILE="openfile.$$"


function assertion_func
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

   typeset actionType=$1

   # process1 locks file:
   $prog -W -c -u -o 4 -s $(expr $REBOOTIMER + 300) -L "1 0 0 0" -B "0 0 0" \
   	$TESTFILE > $STF_TMPDIR/$NAME.out.$$ 2>&1 &
   pid1=$!
   wait_now 200 "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.$$" > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "$NAME: localhost did not have file locked?"
	cat $STF_TMPDIR/$NAME.out.$$
	kill $pid1 > /dev/null 2>&1
	rm -f $TESTFILE $STF_TMPDIR/$NAME.*.$$
	echo "\t Test FAIL" 
        return $STF_FAIL
   fi

   # Reboot SERVER to clear the blocking lock ...
   $DIR/isserverup $actionType > $STF_TMPDIR/$NAME.srv.$$ 2>&1
   if (( $? != 0 )); then
        echo "$NAME: $actionType on SERVER failed"
	cat $STF_TMPDIR/$NAME.srv.$$
	kill $pid1 > /dev/null 2>&1
	rm -f $TESTFILE $STF_TMPDIR/$NAME.*.$$
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   sleep 10

   # Now another process try to lock the same file:
   $prog -W -c -u -o 4 -s 30  -L "1 0 0 0" -B "0 0 -1" $TESTFILE \
	> $STF_TMPDIR/$NAME.out2.$$ 2>&1

   kill $pid1 > /dev/null 2>&1
   grep "unavailable" $STF_TMPDIR/$NAME.out2.$$ > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "$NAME: $SERVER's reboot cleared localhost's locks"
	cat $STF_TMPDIR/$NAME.out2.$$
	rm -f $TESTFILE $STF_TMPDIR/$NAME.*.$$
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   rm -f $TESTFILE $STF_TMPDIR/$NAME.*.$$
   echo "\tTest PASS"
   return $STF_PASS
}


# Start main program here:
# ----------------------------------------------------------------------

ASSERTION_a="Verify process1 recovers after process2 attempts to lock \
        same file after server reboots, expect sucess"
ASSERTION_b="Verify process1 recovers after process2 attempts to lock \
        same file after nfsd dies and restarts, expect sucess"

echo "$NAME{a}: $ASSERTION_a"
assertion_func "reboot"
retcode=$?

echo "$NAME{b}: $ASSERTION_b"
assertion_func "reset-nfsd"
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) && cleanup $STF_PASS || cleanup $STF_FAIL

