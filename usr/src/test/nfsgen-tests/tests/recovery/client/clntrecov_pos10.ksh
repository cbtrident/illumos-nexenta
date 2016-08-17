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
# a: Verify client recovers on write op; after server reboots
#    try to write to same file and stat it, expect OK
# b: Verify client recovers on write op; after nfsd dies and
#    restarts try to write to same file and stat it, expect OK
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
PATH=/usr/bin:$PATH

# used to export EXECUTION path
export RECOVERY_EXECUTE_PATH=$DIR
export RECOVERY_STAT_PATH=$STF_SUITE/bin/

# Global variables
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
   actionType=$1

   # start a process to open and write data info a file
   # it also read those data back for check after server reboot or
   # nfsd restart on server
   $prog -W -o 4 -e $RANDOM -B "32768 1024 1024" $MNTDIR/$TESTFILE > \
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

   # kill first write process
   kill $pid

   # recovery: the second open and write on same file should succeed 
   # after reboot.
   # successfully
   $prog -W -o 4 -e $RANDOM -B "32768 1024 -1" $MNTDIR/$TESTFILE > \
	$STF_TMPDIR/$NAME.out2.$$ 2>&1
   if (( $? != 0 )); then
        echo "$NAME: the client didn't recover from write op \
                after server reboot..."
	cat $STF_TMPDIR/$NAME.out2.$$
   	rm -f $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   # Verify the stat attributes of the test file are the same
   # for both opens
   nawk '/^st_/ && ! /st_[cm]time/ && ! /^st_bl/ {print}' \
   $STF_TMPDIR/$NAME.out.$$ > $STF_TMPDIR/$NAME.stat.$$ 2>&1
   if (( $? != 0 )); then
        echo "$NAME: nawk failed to get stat info after \
		the 1rst open and write before server reboot..."
	cat $STF_TMPDIR/$NAME.stat.$$
   	rm -f $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   nawk '/^st_/ && ! /st_[cm]time/ && ! /^st_bl/ {print}' \
   $STF_TMPDIR/$NAME.out2.$$ > $STF_TMPDIR/$NAME.stat2.$$ 2>&1
   if (( $? != 0 )); then
        echo "$NAME: stat failed to get stat info after \ 
		the 2nd open and write after server reboot..."
	cat $STF_TMPDIR/$NAME.stat2.$$
   	rm -f $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   diff $STF_TMPDIR/$NAME.stat.$$ $STF_TMPDIR/$NAME.stat2.$$ > \
   $STF_TMPDIR/$NAME.diff.$$ 2>&1
   if (( $? != 0 )); then
        echo "$NAME: Differences in stat files found"
	cat $STF_TMPDIR/$NAME.diff.$$
   	rm -f $STF_TMPDIR/$NAME.*
        echo "\t Test FAIL"
        return $STF_FAIL
   fi

   # cleanup test and tmpfiles
   rm -f $STF_TMPDIR/$NAME.*
   rm -f $MNTDIR/$TESTFILE
   # after cleanup and before start of test case b
   sleep 1

   echo "\tTest PASS"
   return $STF_PASS
}


# Start main program here:
# ----------------------------------------------------------------------
ASSERTION="Verify client recovers on write op; after server reboots \
        try to write to same file and stat it, expect sucess"
ASSERTION_b="Verify client recovers on write op; after nfsd dies and \
        restarts try to write to same file and stat it, expect sucess"

echo "$NAME{a}: $ASSERTION"
assertion_func "reboot"
retcode=$?

echo "$NAME{b}: $ASSERTION"
assertion_func "reset-nfsd"
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) && cleanup $STF_PASS || cleanup $STF_FAIL
