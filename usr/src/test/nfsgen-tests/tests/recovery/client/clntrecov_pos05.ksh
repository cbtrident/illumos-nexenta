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
# a: Verify client recovers it's lock after server re-boots, expect OK
# b: Verify client recovers it's lock after nfsd dies and re-starts, expect OK
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)

. ${STF_SUITE}/include/nfsgen.kshlib

prog=$STF_SUITE/bin/file_operator

TESTFILE="openfile.$$"

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

  # Invoke open and hold lock 
  $prog -W -c -o 4 -s $(expr $REBOOTIMER + 60) -L "1 0 0 0" -B "0 0 0" $MNTDIR/$TESTFILE > \
  	$STF_TMPDIR/$NAME.out.$$ 2>&1 &
  pid1=$!

  wait_now 200 "grep \"got exclusive lock\" $STF_TMPDIR/$NAME.out.$$" > /dev/null 2>&1
  if (( $? != 0 )); then
        echo "$NAME: client failed to got exclusive lock in 200 seconds"
        cat $STF_TMPDIR/$NAME.out.$$
        kill $pid1
        rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
  fi

  # Now, reboot SERVER or restart nfsd on server
  ${DIR}/isserverup $actionType > $STF_TMPDIR/$NAME.srv.$$ 2>&1
  if (( $? != 0 )); then
        echo "$NAME: reboot SERVER or restart nfsd on SERVER failed in $timer minutes"
	kill $pid1
        cat $STF_TMPDIR/$NAME.srv.$$
	rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
        return $STF_FAIL
  fi
 
  # Check lock recovery by 2nd process attempting to acquire the lock   
  $prog -W -c -u -o 4 -s 30  -L "1 0 0 0" -B "0 0 -1" $MNTDIR/$TESTFILE > \
  	$STF_TMPDIR/$NAME.out2.$$ 2>&1

  # Now cleanup process locks
  kill $pid1 > /dev/null 2>&1

  sleep 10

  grep "unavailable" $STF_TMPDIR/$NAME.out2.$$ > /dev/null 2>&1
  if (( $? != 0 )); then
        echo "$NAME: 2nd process was able to get the lock \
	after $SERVER reboot or nfsd restarted on server."
        cat $STF_TMPDIR/$NAME.out2.$$
	rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
  fi

  # cleanup test file
  rm $MNTDIR/$TESTFILE* 2>&1

  # cleanup tmp files
  rm $STF_TMPDIR/$NAME.* 2>&1

   echo "\tTest PASS"
   return $STF_PASS
}


# Start main program here:
# ----------------------------------------------------------------------
ASSERTION_a="Verify client recovers it's lock after server re-boots, expect sucess"
ASSERTION_b="Verify client recovers it's lock after nfsd dies, expect sucess"

echo "$NAME{a}: $ASSERTION"
assertion_func "reboot"
retcode=$?

echo "$NAME{b}: $ASSERTION"
assertion_func "reset-nfsd"
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) && cleanup $STF_PASS || cleanup $STF_FAIL
