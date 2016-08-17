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
# a: Verify multiple clients lock on multiple files and server reboots,
# expect OK
# b: Verify multiple clients lock on multiple files after nfsd dies and
# restarts, expect OK
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
PATH=/usr/bin:$PATH

prog=$STF_SUITE/bin/file_operator

TESTFILE="openfile.$$"
TESTFILE2="openfile2.$$"
TESTFILE3="openfile3.$$"

# proc to check result and print out failure messages
if [[ ! -x $prog ]]; then
        echo "$NAME: the executible program '$prog' not found."
        echo "\t Test FAIL"
        return $STF_FAIL
fi


# First check this test is not started before previous tests
# grace period ends.
echo "xxx" > $MNTDIR/wait_for_grace
rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

# Start test
# --------------------------------------------------------------------
function assertion_func
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

   typeset actionType=$1
   typeset -i timer=REBOOTIMER/60
   typeset -i tmpcode=0

   # the localhost locks offset 0 and length 20 bytes:
   $prog -W -c -u -o 4 -s $(expr $REBOOTIMER + 300) -L "1 0 0 20" -B "0 0 0" \
	$MNTDIR/$TESTFILE > $STF_TMPDIR/$NAME.out.$$ 2>&1 &
   pid1=$!

   # Now 2nd client instance locks a different file with offset 0 \
   # and length 20 bytes:
   $prog -W -c -u -o 4 -s $(expr $REBOOTIMER + 300) -L "1 0 0 20" -B "0 0 0" \
	$MNTDIR/$TESTFILE2 > $STF_TMPDIR/$NAME.out2.$$ 2>&1 &
   pid2=$!

   # Now a third client instance locks offset 0 and length 20 bytes on \
   # a different file:
   $prog -W -c -u -o 4 -s $(expr $REBOOTIMER + 300) -L "1 0 0 20" -B "0 0 0" \
	$MNTDIR/$TESTFILE3 > $STF_TMPDIR/$NAME.out3.$$ 2>&1 &
   pid3=$!

   # check process[1|2|3] already locked the files
   wait_now 200 "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.$$" > /dev/null 2>&1
   tmpcode=$?
   wait_now 200 "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out2.$$" > /dev/null 2>&1
   tmpcode=$(($tmpcode+$?))
   wait_now 200 "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out3.$$" > /dev/null 2>&1
   tmpcode=$(($tmpcode+$?))
   if (( $tmpcode != 0 )); then
	echo "$NAME: process[1|2|3] did not have 0-(20-1) bytes locked?"
	cat $STF_TMPDIR/$NAME.out.$$
	cat $STF_TMPDIR/$NAME.out2.$$
	cat $STF_TMPDIR/$NAME.out3.$$
	kill $pid1 > /dev/null 2>&1
	kill $pid2 > /dev/null 2>&1
	kill $pid3 > /dev/null 2>&1
	rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
	echo "\t Test FAIL"
        return $STF_FAIL
   fi
  
   ${DIR}/isserverup $actionType > $STF_TMPDIR/$NAME.srv.$$ 2>&1 
   if (( $? != 0 )); then
        echo "$NAME: $actionType on $SERVER failed within $timer minutes"
        echo "\t Test FAIL"
        cat $STF_TMPDIR/$NAME.out.$$
        return $STF_FAIL
   fi

   # Check that first process still has the lock after server reboot
   $prog -W -c -u -o 4 -s 30 -L "1 0 0 20" -B "0 0 -1" $MNTDIR/$TESTFILE \
        > $STF_TMPDIR/$NAME.out.2.$$ 2>&1

   # Check that 2nd client instance still has the lock after server reboot
   $prog -W -c -u -o 4 -s 30 -L "1 0 0 20" -B "0 0 -1" $MNTDIR/$TESTFILE2 \
        > $STF_TMPDIR/$NAME.out2.2.$$ 2>&1

    #Check that 3rd client instance still has the lock after server reboot
   $prog -W -c -u -o 4 -s 30 -L "1 0 0 20" -B "0 0 -1" $MNTDIR/$TESTFILE3 \
        > $STF_TMPDIR/$NAME.out3.2.$$ 2>&1

   # kill the lock processes
   kill $pid1 > /dev/null 2>&1
   kill $pid2 > /dev/null 2>&1
   kill $pid3 > /dev/null 2>&1

   grep "unavailable" $STF_TMPDIR/$NAME.out.2.$$ > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "$NAME: 1rst client instance did not have \
	0-(20-1) bytes locked?"
	cat $STF_TMPDIR/$NAME.out.$$
	rm -f $STF_TMPDIR/$NAME* $MNTDIR/$TESTFILE*
	echo "\t Test FAIL" 
        return $STF_FAIL
   fi

   grep "unavailable" $STF_TMPDIR/$NAME.out2.2.$$ > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "$NAME: 2nd client instance did not have \
	0-(20-1) bytes locked?"
	cat $STF_TMPDIR/$NAME.out2.2.$$
	rm -f $STF_TMPDIR/$NAME* $MNTDIR/$TESTFILE*
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   grep "unavailable" $STF_TMPDIR/$NAME.out3.2.$$ > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "$NAME: 3rd client instance did not have 0-(20-1) bytes locked?"
	cat $STF_TMPDIR/$NAME.out3.$$
	rm -f $STF_TMPDIR/$NAME* $MNTDIR/$TESTFILE*
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   # cleanup test file
   rm -f $MNTDIR/$TESTFILE* > /dev/null 2>&1

   # cleanup tmp files
   rm -f $STF_TMPDIR/$NAME.* > /dev/null 2>&1

   echo "\tTest PASS"
   return $STF_PASS
}


# Start main program here:
# ----------------------------------------------------------------------
ASSERTION_a="Verify client recovery from multiple client instances \
        lock on multiple files and server reboots, expect sucess"
ASSERTION_b="Verify client recovery multiple client instances lock \
        on multiple files after nfsd dies and resets, expect sucess"

echo "$NAME{a}: $ASSERTION_a"
assertion_func "reboot"
retcode=$?

echo "$NAME{b}: $ASSERTION_b"
assertion_func "reset-nfsd"
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) && cleanup $STF_PASS || cleanup $STF_FAIL
