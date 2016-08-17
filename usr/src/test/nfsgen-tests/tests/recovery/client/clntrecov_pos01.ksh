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
# a: Verify client recovers on a stat lookup op after server \
# re-boots, expect OK
# b: Verify client recovers on a stat lookup op after nfsd dies and \
# restarts, expect OK
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
PATH=/usr/bin:$PATH

# Global variables
TESTFILE="textfile.txt"

if [ ! -x $DIR/$prog ]; then
        echo "$NAME: STF_FAILED"
        echo "\t the executible program '$prog' not found."
        return $STF_FAIL
fi

# Start test
# --------------------------------------------------------------------
# a: Verify client recovery on a stat lookup after server re-boots, \
# expect OK
ASSERTION="Verify client recovery on a stat lookup after server \
re-boots"
ASSERTION="$ASSERTION, expect successful"
echo "$NAME{a}: $ASSERTION"

# stat file before server reboots 
#${DIR}/stat $MNTDIR/$TESTFILE > $STF_TMPDIR/$NAME.out.$$ 2>&1
#wait
#if [ $? -ne 0 ]; then
#        echo "$NAME: "
#        echo "\tCouldn't stat file"
#        echo "\t Test FAIL"
#        return 1
#fi

#$DIR/isserverup reboot > $STF_TMPDIR/$NAME.boot.$$ 2>&1
#grep "no answer from $SERVER" $STF_TMPDIR/$NAME.boot.$$ 2>&1 
#if [ $? -eq 0 ]; then
#        echo "$NAME: "
#        echo "\tSERVER did not reboot properly"
#        echo "\t Test FAIL"
#        return 1
#fi

# stat file after server reboots and verify over the wire lookup
#${DIR}/stat $MNTDIR/$TESTFILE > $STF_TMPDIR/$NAME.out2.$$ 2>&1
#wait
#if [ $? -ne 0 ]; then
#        echo "$NAME: "
#        echo "\tCouldn't stat file after server reboot"
#        echo "\t Test FAIL"
#        return 1
#fi

#diff $STF_TMPDIR/$NAME.out.$$ $STF_TMPDIR/$NAME.out2.$$ > \
#$STF_TMPDIR/$NAME.diff.$$ 2>&1
#if [ $? -ne 0 ]; then
#        echo "$NAME: "
#        echo "\tstat: found file attribute differences"
#	cat $STF_TMPDIR/$NAME.diff.$$
#        echo "\t Test FAIL"
#        return 1
#fi
echo "\tTest UNTESTED"

# cleanup test and tmpfiles
#rm -f $STF_TMPDIR/$NAME.out.*
#rm -f $MNTDIR/$TESTFILE

# --------------------------------------------------------------------
# b: Verify client recovers on stat lookup after nfsd dies and \
# restarts, expect OK
ASSERTION="Verify client recovers on stat lookup after nfsd \
dies"
ASSERTION="$ASSERTION, expect successful"
echo "$NAME{b}: $ASSERTION"

# stat file before server reboots
#${DIR}/stat $MNTDIR/$TESTFILE > $STF_TMPDIR/$NAME.out.$$ 2>&1
#wait
#if [ $? -ne 0 ]; then
#        echo "$NAME: "
#        echo "\tCouldn't stat file"
#        echo "\t Test FAIL"
#        return 1
#fi

#$DIR/issserverup nfsd-reset > $STF_TMPDIR/$NAME.restart.$$ 2>&1

# stat file after server reboots and verify over the wire lookup
#${DIR}/stat $MNTDIR/$TESTFILE > $STF_TMPDIR/$NAME.out2.$$ 2>&1
#wait
#if [ $? -ne 0 ]; then
#        echo "$NAME: "
#        echo "\tCouldn't stat file after server reboot"
#        echo "\t Test FAIL"
#        return 1
#fi

#diff $STF_TMPDIR/$NAME.stat.$$ $STF_TMPDIR/$NAME.stat2.$$ > \
#$STF_TMPDIR/$NAME.diff.$$ 2>&1
#if [ $? -ne 0 ]; then
#        echo "$NAME: "
#        echo "\tDifferences in stat files found"
#        cat $STF_TMPDIR/$NAME.diff.$$
#        echo "\t Test FAIL"
#        return 1
#fi
echo "\tTest UNTESTED"

exit  $STF_UNTESTED

# cleanup test and tmpfiles
#rm -f $STF_TMPDIR/$NAME.out.*
#rm -f $MNTDIR/$TESTFILE
