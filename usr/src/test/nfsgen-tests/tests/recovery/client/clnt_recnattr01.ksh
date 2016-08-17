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
# Client recovery with named attribute files.
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

# Turn on debugging if DEBUG variable is set.
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& set -x

DIR=$(dirname $0)
PATH=/usr/bin:.:$PATH

echo "xxx" > $MNTDIR/wait_for_grace
if (( $? != 0 )); then
        echo "cannot create file: $MNTDIR/wait_for_grace"
        exit $STF_FAIL
fi

export RECOVERY_EXECUTE_PATH=$DIR
export RECOVERY_STAT_PATH=$STF_SUITE/bin/
prog=$STF_SUITE/bin/holdopenat
if [[ ! -x $prog ]]; then
        echo "$NAME: test program '$prog' not found or not exexutable"
        echo "\t Test UNINITIATED"
        exit $STF_UNINITIATED
fi

# make sure the server is not in the GRACE period due to previous test
SRVNDIR=$MNTDIR/$NOTICEDIR
echo "ckgrace" > $SRVNDIR/ckgrace 2> $STF_TMPDIR/$NAME.ckgrace.$$
if (( $? != 0 )); then
        echo "$NAME: test setup - ckgrace failed"
        echo "\t Test UNINITIATED"
        cat $STF_TMPDIR/$NAME.ckgrace.$$
        rm -f $STF_TMPDIR/$NAME.ckgrace.$$
        exit $STF_UNINITIATED
fi
rm -f $SRVNDIR/* $STF_TMPDIR/$NAME.ckgrace.$$


# Start test
# --------------------------------------------------------------------
# a: Client open/write to a named_attr file, server reboot, and verfiy
#    client is able to read back the data and close the file.
function assertion_a 
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
   As="Client open/write to a named_attr file, server reboot; \n"
   As="$As \t verify client is able read back and close the file, expect OK"
   echo "$NAME{a}: $As"

   # call the program with reboot flag
   $prog -f $MNTDIR/${NAME}_a.$$ -u $SRVNDIR/DONE_reboot > \
   	$STF_TMPDIR/$NAME.out.$$ 2>&1 &
   sleep 2

   # signal server to reboot; then wait
   touch $SRVNDIR/reboot
   wait
   grep "GOOD" $STF_TMPDIR/$NAME.out.$$ | grep "successful" > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "\t Test FAIL: $prog did not exit with <successful>"
	cat $STF_TMPDIR/$NAME.out.$$
        return $STF_FAIL
   fi

   echo "\tTest PASS"
   return $STF_PASS
}


# --------------------------------------------------------------------
# b: Client open/write to a named_attr file, server restart-nfsd, verfiy
#    client is able to read back the data and close the file.
function assertion_b 
{
   [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
   Bs="Client open/write to a named_attr file, server restart-nfsd; \n"
   Bs="$Bs \t verify client is able read back and close the file, expect OK"
   echo "$NAME{b}: $Bs"

   # make sure the server is not in the GRACE period due
   # to previous test
   echo "xxx" > $MNTDIR/wait_for_grace
   rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

   # call the program with reset (nfsd) flag
   $prog -f $MNTDIR/${NAME}_b.$$ -u $SRVNDIR/DONE_reset > \
   	$STF_TMPDIR/$NAME.out.$$ 2>&1 &
   sleep 2

   # signal server to restart nfsd; then wait
   touch $SRVNDIR/reset-nfsd
   wait
   grep "GOOD" $STF_TMPDIR/$NAME.out.$$ | grep "successful" > /dev/null 2>&1
   if (( $? != 0 )); then
        echo "\t Test FAIL: $prog did not exit with <successful>"
	cat $STF_TMPDIR/$NAME.out.$$
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

(( $retcode == $STF_PASS )) \
	&& cleanup $STF_PASS "" "$STF_TMPDIR/${NAME}*.$$ \
	$SRVNDIR/ckgrace $SRVNDIR/DONE_*" \
	|| cleanup $STF_FAIL "" "$STF_TMPDIR/${NAME}*.$$ \
	$SRVNDIR/ckgrace $SRVNDIR/DONE_*"

