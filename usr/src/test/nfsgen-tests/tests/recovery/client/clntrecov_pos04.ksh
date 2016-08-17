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
# a: Verify client recovers on write op after server reboots; 
# try to close after reboot, expect OK
# b: Verify client recovers on write op after after nfsd dies and
# and restarts; try to close after nfsd restart, expect OK
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
PATH=/usr/bin:$PATH
prog=$STF_SUITE/bin/file_operator

export RECOVERY_EXECUTE_PATH=$DIR
export RECOVERY_STAT_PATH=$STF_SUITE/bin/

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
   actionType=$1

   # start a process to open and write data info a file
   # it also read those data back for check after server reboot or
   # nfsd restart on server
   $prog -c -W -o 4 -e $RANDOM -B "32768 1024 1024" $MNTDIR/$TESTFILE > \
   $STF_TMPDIR/$NAME.out.$$ 2>&1 &
   pid=$!

   # wait untill prog wrote all data into the file
   wait_now 200 "grep \"I am ready\" $STF_TMPDIR/$NAME.out.$$" \
   > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "$NAME: client failed to write 32MB data into $STF_TMPDIR/$NAME.out.$$ \
                in 200 seconds"
        cat $STF_TMPDIR/$NAME.out.$$
        kill $pid
        rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
  fi

  # reboot server or restart nfsd on server
  $DIR/isserverup $actionType > $STF_TMPDIR/$NAME.reboot.$$ 2>&1
  if (( $? != 0 )); then
        echo "$NAME: failed to reboot $SERVER"
        cat $STF_TMPDIR/$NAME.reboot.$$
        kill $pid
        rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
  fi

  # signal the test program to read data back
  kill -16 $pid

  wait $pid
  if (( $? != 0 )); then
        echo "wait the process with pid=$pid failed"
        echo "\t Test FAIL"
        kill $pid
        rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
        return $STF_FAIL
  fi

   rm -f $MNTDIR/$TESTFILE* $STF_TMPDIR/$NAME.*
   echo "\tTest PASS"
   return $STF_PASS
}


# Start main program here:
# ----------------------------------------------------------------------
ASSERTION_a="Verify client recovers on write op after server reboot; \
        try to close after reboot, expect sucess"
ASSERTION_b="Verify client recovers on write op after after nfsd dies and \
        and restarts; try to close after nfsd restart, expect sucess"

echo "$NAME{a}: $ASSERTION"
assertion_func "reboot"
retcode=$?

echo "$NAME{b}: $ASSERTION"
assertion_func "reset-nfsd"
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) && cleanup $STF_PASS || cleanup $STF_FAIL
