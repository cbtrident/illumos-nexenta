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
# a: Verify conflicting lock from process2 is granted after
#    lease expires and process1 gets killed, should succeed.
# b: Verify conflicting lock from process1 or process2 is granted after
#    lease expires and process2 or process1 releases the lock, should succeed.
# c: Verify conflicting lock from process2 is granted after
#    lease expires and process1 releases the lock, should succeed.
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
PATH=/usr/bin:$PATH

prog=$STF_SUITE/bin/file_operator
TESTFILE="openfile.$$"
timeout=200

if [[ -n $ZONE_PATH ]]; then
	echo "\n\tThis test hits CR#6749743 which causes the server panic\n"
	exit $STF_UNTESTED
fi

if [[ ! -x $prog ]]; then
        echo "$NAME:the executable program '$prog' not found."
        echo "\t Test FAIL"
        return $STF_FAIL
fi


# First check this test is not started before previous tests
# grace period ends.
echo "xxx" > $MNTDIR/wait_for_grace
rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

# Start test
# --------------------------------------------------------------------
# a: Verify conflicting lock from localhost is granted after
# lease expires and process2 gets killed, should succeed.
function assertion_a 
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
   ASSERTION="Verify conflicting lock from process2 is granted after \
	lease expires and process1 gets killed"

   ASSERTION="$ASSERTION, expect successful"
   echo "$NAME{a}: $ASSERTION"

   # First write lock the file in a process and hold for a long time:
   $prog -W -c -u -o 4 -s $REBOOTIMER -L "1 1 0 0" -B "0 0 0" $MNTDIR/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c2.$$ 2>&1 &
   pid1=$!
   wait_now 200 \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the process with pid=$pid1 did not get the write lock ..."
	cat $STF_TMPDIR/$NAME.out.c2.$$
	kill $pid1
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # Now write lock the same file on localhost; should be block
   $prog -W -c -u -o 4 -s 10 -L "1 1 0 0" -B "0 0 -1" $MNTDIR2/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.$$ 2>&1 &
   pid2=$!
   wait_now 5 \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.$$ > /dev/null 2>&1" \
   	> /dev/null
   if (( $? == 0 )); then
        echo "$NAME: the process with pid=$pid2 also got the write lock before \
        process with pid=$pid2 releasing it, it is unexpected."
	cat $STF_TMPDIR/$NAME.out.$$
	kill $pid1
	kill $pid2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # kill the first process to clear the blocked lock...
   kill $pid1
   sleep 5 
   # check the first process already killed
   kill -0 $pid1 > $STF_TMPDIR/$NAME.out.ps.$$ 2>&1
   grep "o such process" $STF_TMPDIR/$NAME.out.ps.$$ > /dev/null 2>&1
   if (( $? != 0 )); then
	echo "$NAMW: failed to kill the first process with pid=$pid1"
	cat $STF_TMPDIR/$NAME.out.ps.$$
	kill $pid1
	kill $pid2
	echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # the second process should get the write lock now ...
   wait_now $timeout \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the second process with pid=$pid2 still did not get the write lock \
	even waiting for $timeout seconds after the first process killed."
        cat $STF_TMPDIR/$NAME.out.$$
	kill $pid2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   wait $pid2
   if (( $? != 0 )); then
	echo "wait the second process with pid=$pid2 failed"
	echo "\t Test FAIL"
	return $STF_FAIL
   else
   	echo "\tTest PASS"
   	return $STF_PASS
   fi
}

# --------------------------------------------------------------------
# b: Verify conflicting lock from process1 or process2 is granted after
# lease expires and process2 or process1 releases the lock, should succeed.
#
# It implements the following scenarios to make sure server is not confused
# with the processs and the locks, and process can recover the states:
# - process1 write lock the file
# - process2 try write lock the file, block
# - process1 release the lock
# - process2 gets the lock, then release it
# - process1 read lock the file
# - process2 try write lock the file, block
# - process1 release the lock
# - process2 gets the lock
# - process1 try read lock some offset, block
# - process2 release the lock; then set read lock
# - server calls clear_locks to both processs
# - verify both process1 and process2 still have the read lock
# 
function assertion_b 
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
   ASSERTION="Verify conflicting lock from localhost or process2 is granted \
	after lease expires and another process releases the lock"
   ASSERTION="$ASSERTION, expect successful"
   echo "$NAME{b}: $ASSERTION"

   # First check this test is not started before previous tests
   # grace period ends.
   echo "xxx" > $MNTDIR/wait_for_grace
   rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

   # First write lock the file in process1 and hold for a period of time:
   $prog -W -c -u -o 4 -s 30 -L "1 1 0 0" -B "0 0 0" $MNTDIR/$TESTFILE \
	 > $STF_TMPDIR/$NAME.out.c1.$$ 2>&1 &
   pid1=$!
   wait_now $timeout \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c1.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the process1 with pid=$pid1 did not get the write lock ..."
	cat $STF_TMPDIR/$NAME.out.c1.$$
	kill $pid1
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # Now write lock the same file in process2; should be block
   $prog -W -c -u -o 4 -s 20 -L "1 1 0 0" -B "0 0 -1" $MNTDIR2/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c2.$$ 2>&1 &
   pid2=$!
   wait_now 10 \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2.$$ > /dev/null 2>&1" \
   > /dev/null
   if (( $? == 0 )); then
        echo "$NAME: the process2 with pid=$pid2 also got the write lock before \
        localhost releasing it, it is unexpected."
	cat $STF_TMPDIR/$NAME.out.c2.$$
	kill $pid1
	kill $pid2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # send SIGUSR1 to first process1, process1 will release the lock
   kill -16 $pid1

   # the process2 should get the write lock now ...
   wait_now $timeout \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the process2 with pid=$pid2 still did not get the write lock \
	even waiting for $timeout seconds after process1 released it."
	cat $STF_TMPDIR/$NAME.out.c2.$$
	kill $pid1
	kill $pid2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   wait $pid1
   if (( $? != 0 )); then
	echo "wait process1 with pid=$pid1 finish failed"
	cat $STF_TMPDIR/$NAME.out.c1.$$
	kill $pid1
	kill $pid2
        return $STF_FAIL
   fi
   wait $pid2
   if (( $? != 0 )); then
	echo "wait process2 with pid=$pid2 finish failed"
	cat $STF_TMPDIR/$NAME.out.c2.$$
	kill $pid2
        return $STF_FAIL
   fi
   sleep 5 

   # Read lock the file in process1 and hold for a period of time:
   $prog -R -c -u -o 4 -L "0 1 0 0" -B "0 0 0" $MNTDIR/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c1r.$$ 2>&1 &
   pid1=$!
   wait_now $timeout \
   "grep \"got shared lock\" $STF_TMPDIR/$NAME.out.c1r.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the process1 did not get the read lock ..."
	cat $STF_TMPDIR/$NAME.out.c1r.$$
	kill $pid1
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # Try to write lock the same file in process2; should be block
   $prog -W -c -u -o 4 -L "1 1 0 0" -B "0 0 0" $MNTDIR2/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c2w.$$ 2>&1 &
   pid2=$!
   wait_now 5 \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2w.$$ > /dev/null 2>&1" \
	   > /dev/null
   if (( $? == 0 )); then
        echo "$NAME: the process2 with pid=$pid2 has got the write lock before \
        localhost releasing it, it is unexpected."
	cat $STF_TMPDIR/$NAME.out.c2w.$$
	kill $pid1
	kill $pid2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # send SIGUSR1 to first process1, process1 will release the lock
   kill -16 $pid1

   # the process2 should get the write lock now ...
   wait_now $timeout \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2w.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the process2 with pid=$pid2 still did not get the write lock \
	even waiting for $timeout seconds after localhost released it."
	cat $STF_TMPDIR/$NAME.out.c2w.$$
	kill $pid2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   wait $pid1
   if (( $? != 0 )); then
	echo "wait process1 with pid=$pid1 finish failed"
	cat $STF_TMPDIR/$NAME.out.c1r.$$
	kill $pid1
	kill $pid2
        return $STF_FAIL
   fi

   # process1 try to read lock the file with offset 0 and length 20 bytes;
   # should be block
   $prog -R -c -u -o 4 -s 80 -L "0 1 0 20" -B "0 0 0" $MNTDIR/$TESTFILE > \
	$STF_TMPDIR/$NAME.out.c1o.$$ 2>&1 &
   pid1=$!
   wait_now 10 \
   "grep \"got shared lock\" $STF_TMPDIR/$NAME.out.c1o.$$ > /dev/null 2>&1" \
   > /dev/null
   if (( $? == 0 )); then
        echo "$NAME: the process1 has got the read lock before \
        process2 releasing it, it is unexpected."
	cat $STF_TMPDIR/$NAME.out.c1o.$$
	kill $pid1
	kill $pid2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # send SIGUSR1 to first process2, process2 will release the lock
   kill -16 $pid2

   # the localhost should get the read lock now ...
   wait_now $timeout \
   "grep \"got shared lock\" $STF_TMPDIR/$NAME.out.c1o.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the localhost still did not get the read lock \
	even waiting for $timeout seconds after process2 with pid=$pid2 released it."
	cat $STF_TMPDIR/$NAME.out.c1o.$$
	kill $pid1
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # process2 try to read lock the same file also:
   $prog -R -c -u -o 4 -s 80 -L "0 1 0 0" -B "0 0 0" $MNTDIR2/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c2r.$$ 2>&1 &
   pid2=$!
   wait_now $timeout \
   "grep \"got shared lock\" $STF_TMPDIR/$NAME.out.c2r.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the process2 with pid=$pid2 did not get the read lock ..."
	cat $STF_TMPDIR/$NAME.out.c2r.$$
	kill $pid1
	kill $pid2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # SERVER calls clear_locks to both processs to make sure process can recovery
   # the states:
   RSH root $SERVER "clear_locks $CLIENT" > $STF_TMPDIR/$NAME.out.c1c.$$ 2>&1

   # send SIGUSR1 to both process1 and process2
   kill -16 $pid1
   kill -16 $pid2

   wait $pid1
   if (( $? != 0 )); then
	echo "wait process1 with pid=$pid1 finish failed"
	cat $STF_TMPDIR/$NAME.out.c1o.$$
	kill $pid1
	kill $pid2
        return $STF_FAIL
   fi
   wait $pid2
   if (( $? != 0 )); then
	echo "wait process2 with pid=$pid2 finish failed"
	cat $STF_TMPDIR/$NAME.out.c2r.$$
	kill $pid2
        return $STF_FAIL
   fi

   echo "\tTest PASS"
   return $STF_PASS
}

# --------------------------------------------------------------------
# c: Verify conflicting lock from process2 is granted after
# lease expires and process1 releases the lock, should succeed.
#
# It implements the following scenarios to make sure server is not confused
# with the processes and the locks, and process can recover the states:
# - process1 write lock the file
# - process2 try write lock the file, block
# - process1 release the lock
# - process2 gets the lock, then release it
# - process1 read lock the file
# - process2 try write lock the file, block
# - process1 release the lock
# - process2 gets the lock
# - process1 try read lock some offset, block
# - process2 release the lock; then set read lock
# - server calls clear_locks to both processes
# - verify both process1/process2 still have the read lock
# 
function assertion_c 
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
   ASSERTION="Verify conflicting lock from process2 is granted \
	after lease expires and process1 releases the lock"
   ASSERTION="$ASSERTION, expect successful"
   echo "$NAME{c}: $ASSERTION"

   # First check this test is not started before previous tests
   # grace period ends.
   echo "xxx" > $MNTDIR/wait_for_grace
   rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

   # First write lock the file in process1 and hold for a period of time:
   $prog -W -c -u -o 4 -s 30 -L "1 1 0 0" -B "0 0 0" $MNTDIR/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c1.$$ 2>&1 &
   pid1_1=$!
   wait_now $timeout \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c1.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the 1st process did not get the write lock ..."
	cat $STF_TMPDIR/$NAME.out.c1.$$
	kill $pid1_1
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # Now write lock the same file again on localhost; should be block
   $prog -W -c -u -o 4 -s 20 -L "1 1 0 0" -B "0 0 0" $MNTDIR2/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c2.$$ 2>&1 &
   pid1_2=$!
   wait_now 10 \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2.$$ > /dev/null 2>&1" \
   > /dev/null
   if (( $? == 0 )); then
        echo "$NAME: the 2nd process also got the write lock before \
        the 1st process releasing it, it is unexpected."
	cat $STF_TMPDIR/$NAME.out.c2.$$
	kill $pid1_1
	kill $pid1_2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # send SIGUSR1 to 1st holdlock process
   kill -16 $pid1_1

   # the 2nd process should get the write lock now ...
   wait_now $timeout \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the 2nd process still did not get the write lock \
	even waiting for $timeout seconds after the 1st process released it."
	cat $STF_TMPDIR/$NAME.out.c2.$$
	kill $pid1_2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # send SIGUSR1 to 2nd holdlock process
   kill -16 $pid1_2

   wait $pid1_1
   if (( $? != 0 )); then
        echo "wait process1 with pid=$pid1_1 finish failed"
        cat $STF_TMPDIR/$NAME.out.c1.$$
        kill $pid1_1
        kill $pid1_2
        return $STF_FAIL
   fi
   wait $pid1_2
   if (( $? != 0 )); then
        echo "wait process2 with pid=$pid1_2 finish failed"
        cat $STF_TMPDIR/$NAME.out.c2.$$
        kill $pid1_2
        return $STF_FAIL
   fi

   # Read lock the file on localhost and hold for a period of time:
   $prog -R -c -u -o 4 -s 30 -L "0 1 0 0" -B "0 0 0" $MNTDIR/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c1r.$$ 2>&1 &
   pid1_1=$!
   wait_now $timeout \
   "grep \"got shared lock\" $STF_TMPDIR/$NAME.out.c1r.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the 1st process did not get the read lock ..."
	cat $STF_TMPDIR/$NAME.out.c1r.$$
	kill $pid1_1
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # Try to write lock the same file on localhost; should be block
   $prog -W -c -u -o 4 -s 30 -L "1 1 0 0" -B "0 0 0" $MNTDIR2/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c2w.$$ 2>&1 &
   pid1_2=$!
   wait_now 10 \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2w.$$ > /dev/null 2>&1" \
  	 > /dev/null
   if (( $? == 0 )); then
        echo "$NAME: the 2nd process has got the write lock before \
        the 1st process releasing it, it is unexpected."
	cat $STF_TMPDIR/$NAME.out.c2w.$$
	kill $pid1_1
	kill $pid1_2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   kill -16 $pid1_1

   # the 2nd process should get the write lock now ...
   wait_now $timeout \
   "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.c2w.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the 2nd process still did not get the write lock \
	even waiting for $timeout seconds after the 1st process released it."
	cat $STF_TMPDIR/$NAME.out.c2w.$$
	kill $pid1_2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   wait $pid1_1
   if (( $? != 0 )); then
        echo "wait process1 with pid=$pid1_1 finish failed"
        cat $STF_TMPDIR/$NAME.out.c1r.$$
        kill $pid1_1
        kill $pid1_2
        return $STF_FAIL
   fi

   # try to read lock the file again with offset 0 and length 20 bytes;
   # should be block
   $prog -R -c -u -o 4 -s 80 -L "0 1 0 20" -B "0 0 0" $MNTDIR/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c1o.$$ 2>&1 &
   pid1_1=$!
   wait_now 5 \
   "grep \"got shared lock\" $STF_TMPDIR/$NAME.out.c1o.$$ > /dev/null 2>&1" \
   	> /dev/null
   if (( $? == 0 )); then
        echo "$NAME: the 1st process has got the read lock before \
        the 2nd process releasing it, it is unexpected."
	cat $STF_TMPDIR/$NAME.out.c1o.$$
	kill $pid1_1
	kill $pid1_2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   kill -16 $pid1_2

   # the localhost should get the read lock now ...
   wait_now $timeout \
   "grep \"got shared lock\" $STF_TMPDIR/$NAME.out.c1o.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the 1st process still did not get the read lock \
	even waiting for $timeout seconds after the 2nd process released it."
	cat $STF_TMPDIR/$NAME.out.c1o.$$
	kill $pid1_1
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   wait $pid1_2
   if (( $? != 0 )); then
        echo "wait process2 with pid=$pid1_2 finish failed"
        cat $STF_TMPDIR/$NAME.out.c2w.$$
        kill $pid1_2
        return $STF_FAIL
   fi

   # try to read lock the same file also:
   $prog -R -c -u -o 4 -s 80 -L "0 1 0 0" -B "0 0 -1" $MNTDIR2/$TESTFILE \
	> $STF_TMPDIR/$NAME.out.c2r.$$ 2>&1 &
   pid1_2=$!
   wait_now $timeout \
   "grep \"got shared lock\" $STF_TMPDIR/$NAME.out.c2r.$$ > /dev/null 2>&1"
   if (( $? != 0 )); then
        echo "$NAME: the 2nd process did not get the read lock ..."
	cat $STF_TMPDIR/$NAME.out.c2r.$$
	kill $pid1_1
	kill $pid1_2
        echo "\t Test FAIL"
	return $STF_FAIL
   fi

   # SERVER calls clear_locks to localhost to make sure process can recovery
   # the states:
   RSH root $SERVER "clear_locks $CLIENT" > $STF_TMPDIR/$NAME.out.c1c.$$ 2>&1

   kill -16 $pid1_1

   wait $pid1_1
   if (( $? != 0 )); then
        echo "wait process1 with pid=$pid1_1 finish failed"
        cat $STF_TMPDIR/$NAME.out.c1o.$$
        kill $pid1
        kill $pid2
        return $STF_FAIL
   fi
   wait $pid1_2
   if (( $? != 0 )); then
        echo "wait process2 with pid=$pid1_2 finish failed"
        cat $STF_TMPDIR/$NAME.out.c2r.$$
        kill $pid1_2
        return $STF_FAIL
   fi


   echo "\tTest PASS"
   return $STF_PASS
}

# Start main program here:
# ----------------------------------------------------------------------
assertion_a
retcode=$?

assertion_b
retcode=$(($retcode+$?))

assertion_c
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) \
	&& cleanup $STF_PASS "" "$MNTDIR/$TESTFILE $STF_TMPDIR/$NAME*.$$" \
	|| cleanup $STF_FAIL "" "$MNTDIR/$TESTFILE $STF_TMPDIR/$NAME*.$$"
