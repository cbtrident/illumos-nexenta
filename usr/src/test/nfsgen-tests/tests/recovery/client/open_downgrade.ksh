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
# This is a regression test for 6248250. In this test, we will generate 
# an OPEN_DOWNGRADE operation on a stale file handler. Without the fix, nfs 
# client code didn't check NFS4ERR_STALE error and re-sent OPEN_DOWNGRADE 
# again and again. On user level, it could be observed the user process 
# was hang.
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
OPENDG_ASSERTIONS=${OPENDG_ASSERTIONS:-"a"}

export RECOVERY_EXECUTE_PATH=$DIR
export RECOVERY_STAT_PATH=$STF_SUITE/bin/

# Wait until grace period ends
echo "xxx" > $MNTDIR/wait_for_grace
rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

TESTFILE=$NAME.$$.test
LOGFILE=$STF_TMPDIR/$NAME.$$.err

function setup 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

	# execute $SERVER root \
	RSH root $SERVER \
	    "cd $SHRDIR; touch $TESTFILE; chmod 666 $TESTFILE" 1>/dev/null \
	    2>$LOGFILE
	ckresult $? "failed to create $TESTFILE ERROR" $LOGFILE || return 1
}

# Start test assertions here
# ----------------------------------------------------------------------
# a: generate an OPEN_DOWNGRADE operation on a stale file handler
function assertion_a
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

	ASSERTION="Client tries to generate an OPEN_DOWNGRADE operation"
	ASSERTION="$ASSERTION on a stale file handler,"
	ASSERTION="$ASSERTION expect NFS4ERR_STALE error be handled properly"
	echo "$NAME{a}: $ASSERTION"

	PROG=$STF_SUITE/bin/open_dg
	INTERVAL=8
        STF_WARNING="\tSTF_WARNING: The failure of this case was known to cause"
	STF_WARNING="$STF_WARNING NFS client kept looping and didn't response to any"
	STF_WARNING="$STF_WARNING further NFS operations. So you many need to re-setup"
	STF_WARNING="$STF_WARNING the test environment and continue the rest tests."

	# start test program
	$PROG $MNTDIR/$TESTFILE 1>$LOGFILE 2>&1 &
	pid=$!
	sleep $INTERVAL
	grep "fd1 and fd2 were opened" $LOGFILE > /dev/null
	ckresult -n $? "failed to open test file STF_UNRESOLVED" $LOGFILE
	if (( $? != 0 )); then
                kill -9 $pid
		rm -f $LOGFILE
                return $STF_UNRESOLVED
        fi


	# do the following steps on server to help to generate 
	# NFS4ERR_STALE error when client sends OPEN_DOWNGRADE
	# below. Note that the step of removing the file is necessary.
	# Or else server returns NFS4ERR_EXPIRED error, which is 
	# not what we want to test in this case.
	# execute $SERVER root "rm -f $SHRDIR/$TESTFILE && \
	RSH root $SERVER "rm -f $SHRDIR/$TESTFILE && \
	    unshare $SHRDIR && share $SHRDIR" 1>/dev/null 2>$STF_TMPDIR/$NAME.$$.rsh
	ckresult $? "failed to execute commands on server STF_UNRESOLVED" $STF_TMPDIR/$NAME.$$.rsh 
	if (( $? != 0 )); then
		kill -9 $pid 
		rm -f $LOGFILE $STF_TMPDIR/$NAME.$$.rsh
		return $STF_UNRESOLVED
	fi

	# close fd1 to generate OPEN_DOWNGRADE
	kill -USR1 $pid 
	sleep $INTERVAL
	grep "NFS4ERR_STALE" $LOGFILE | grep fd1 > /dev/null
	ckresult -n $? "Unknown error on closing fd1 STF_FAIL" $LOGFILE
	if (( $? != 0 )); then
		echo $STF_WARNING
		kill -9 $pid 
		rm -f $LOGFILE $STF_TMPDIR/$NAME.$$.rsh
		return $STF_FAIL
	fi

	# close fd2
	kill -USR2 $pid 
	sleep $INTERVAL
	grep "NFS4ERR_STALE" $LOGFILE | grep fd2 > /dev/null
	ckresult $? "Unknown error on closing fd2 STF_FAIL" $LOGFILE 
	if (( $? != 0 )); then
		echo $STF_WARNING
		kill -9 $pid 
		rm -f $LOGFILE $STF_TMPDIR/$NAME.$$.rsh
		return $STF_FAIL
	fi

	rm -f $LOGFILE $STF_TMPDIR/$NAME.$$.rsh

	echo "\t Test PASS"
	return $STF_PASS
}

# Start main program here:
# ----------------------------------------------------------------------

setup || cleanup $STF_UNINITIATED "" "$MNTDIR/$TESTFILE $LOGFILE $STF_TMPDIR/$NAME.$$.rsh"

retcode=0
for t in $OPENDG_ASSERTIONS; do
        assertion_$t
        retcode=$(($retcode+$?))
done

(( $retcode == $STF_PASS )) \
	&& cleanup $STF_PASS "" "$MNTDIR/$TESTFILE $LOGFILE $STF_TMPDIR/$NAME.$$.rsh" \
	|| cleanup $STF_FAIL "" "$MNTDIR/$TESTFILE $LOGFILE $STF_TMPDIR/$NAME.$$.rsh"

