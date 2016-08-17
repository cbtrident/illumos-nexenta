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
# a: Verify that SERVER will provide conflicting lock to other
#    client after the lease expired
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)

prog=$STF_SUITE/bin/file_operator
timeout=250
locktimeout=$((${LEASE_TIME:-180} + 100))
TESTFILE01="rwfile.$$"

[[ $MNTDIR2 == $SHRDIR ]] && mntdir2="${MNTDIR2}_other" || mntdir2=$MNTDIR2

# assertion_a
# CLIENTA: open a file, lock and write the file
# SERVER: cut down the nfs communication between CLIENTA and SERVER during CLIENTA is writing
# CLIENTB(SERVER): open the same file, try to lock and write data
# CLIENTA: kill the writing process on CLIENTA
# SERVER: after the write process on CLIENTB(SERVER) finished, restore the nfs communication
#	  between CLIENTA and SERVER
# CLIENTA: start to open the same file, check the data wrotten by CLIENTB(SERVER)
#
function assertion_a
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset pid1=""
	typeset pid2=""
	typeset pidnw=""
	typeset seed=$RANDOM

	# open and write file on CLIENT
	checkseed=$RANDOM
	$prog -W -c -u -o 4 -L "1 1 0 0" -B "32768 2048 1024" $MNTDIR/$TESTFILE01 \
		> $STF_TMPDIR/$NAME.out.$$ 2>&1 &
	pid1=$!

	# make sure the 1st write process is ready
	wait_now $timeout "grep \"I am ready\" $STF_TMPDIR/$NAME.out.$$" \
		> $STF_TMPDIR/$NAME.err.$$ 2>&1
	if (( $? != 0 )); then
		echo "1st write process failed to get lock and write 32MB data \
			in $timeout seconds"
		cat $STF_TMPDIR/$NAME.err.$$
		cat $STF_TMPDIR/$NAME.out.$$
		kill $pid1
		echo "\t Test FAIL"
		return $STF_FAIL
	fi

	# ready to cut the communication between CLIENT and SERVER
	RUN_CHECK $CMD sync || return $STF_FAIL
	RUN_CHECK $CMD touch $TMPDIR/network_block_flag \
		$TMPDIR/network_feedback_file || return $STF_FAIL

	[[ $IS_IPV6 == 1 ]] && IPOPT="-v ipv6" || IPOPT=""
	if [[ $IS_ZONE == 0 ]]; then
		ipf_network $IPOPT \
			-t $timeout \
			-f $TMPDIR/network_block_flag \
			-k $TMPDIR/network_feedback_file \
			-r "block out from $CLIENT to $SERVER port=2049" \
			> $STF_TMPDIR/$NAME.reset_nw.$$ 2>&1 &
		pidnw=$!
	else
		# RSH doesn't support to run the command in background.
		ssh root@$SERVER /usr/bin/ksh -c \
			"'. $TMPDIR/nfs-util.kshlib; \
			. $TMPDIR/libsmf.shlib; \
			ipf_network $IPOPT \
			-t $timeout \
			-f $TMPDIR/network_block_flag \
			-k $TMPDIR/network_feedback_file \
			-r \"block in from $CLIENT to $SERVER port=2049\"' " \
			> $STF_TMPDIR/$NAME.reset_nw.$$ 2>&1 &
		pidnw=$!
	fi


	# make sure network already blocked
	wait_now $timeout "$CMD [[ ! -f $TMPDIR/network_feedback_file ]] \
		> /dev/null 2>&1"
	if (( $? != 0 )); then
		echo "Failed to block the communication between client and server"
		cat $STF_TMPDIR/$NAME.reset_nw.$$
		kill $pid1
		return $STF_FAIL
	fi
	
	# start another process on SERVER to write the same file
	TESTFILEONSERVER="${mntdir2}/$TESTFILE01"
	wait_now $locktimeout "RSH root $SERVER \
		\"export LD_LIBRARY_PATH=$SRV_TMPDIR/recovery/bin/:$LD_LIBRARY_PATH; \
		$SRV_TMPDIR/recovery/bin/file_operator \
		-W -c -u -o 3 -e $seed -L \\\"1 1 0 0\\\" -B \\\"32768 2048 -1\\\" \
		$TESTFILEONSERVER \" " > $STF_TMPDIR/$NAME.w2.out.$$ 2>&1
	if (( $? != 0 )); then
		echo "file_operator on $SERVER failed"
		cat $STF_TMPDIR/$NAME.w2.out.$$
		# restore the network communication between CLIENT and SERVER
		RUN_CHECK $CMD rm $TMPDIR/network_block_flag
		wait $pidnw
		echo "\tTest FAIL"
		return $STF_FAIL
	fi

	# before restore the network communication between CLIENT and SERVER
	# kill the first proccess on CLIENT
	kill -9 $pid1
	if (( $? != 0 )) ; then
		echo "failed to kill pid1($pid1)"
		cat $STF_TMPDIR/$NAME.out.$$
		cat $STF_TMPDIR/$NAME.w2.out.$$
		# restore the network communication between CLIENT and SERVER
		RUN_CHECK $CMD rm $TMPDIR/network_block_flag
		wait $pidnw
		echo "\tTest FAIL"
		return $STF_FAIL
	fi

	# ok, restore the network communication between CLIENT and SERVER
	RUN_CHECK $CMD rm $TMPDIR/network_block_flag
	wait $pidnw
	if (( $? != 0 )); then
		echo "failed to wait ipf_network"
		kill -9 $pidnw
		cat $STF_TMPDIR/$NAME.reset_nw.$$
		echo "\t Test FAIL"
		return $STF_FAIL
	fi

	# here, open the same file on CLIENT for read and check
	$prog -R -c -u -o 0 -e $seed -L "0 1 0 0" -B "32768 2048 2048" \
		$MNTDIR/$TESTFILE01 > $STF_TMPDIR/$NAME.out2.$$ 2>&1 &
	pid2=$!
	wait_now $timeout "grep \"I am ready\" $STF_TMPDIR/$NAME.out2.$$" \
		> $STF_TMPDIR/$NAME.err.$$ 2>&1
	if (( $? != 0 )); then
		echo "failed to get 'READY' signal from pid2 in $timeout seconds"
		cat $STF_TMPDIR/$NAME.err.$$
		cat $STF_TMPDIR/$NAME.out2.$$
		kill $pid2
		echo "\t Test FAIL"
		return $STF_FAIL
	fi

	# signal pid2 to read data back for check
	kill -16 $pid2

	wait $pid2
	if (( $? != 0 )); then
		cat $STF_TMPDIR/$NAME.out2.$$
		echo "\tTest FAIL"
		return $STF_FAIL
	else
		echo "\tTest PASS"
		return $STF_PASS
	fi
}

# setup another mountpoint on SERVER
function internalSetup_pos01
{
	RUN_CHECK RSH root $SERVER "\"mkdir -p -m 0777 ${mntdir2}; \
		mount -o $MNTOPT2 $SERVER:$SHRDIR ${mntdir2}\"" \
		|| exit $STF_UNINITIATED
}

#cleanup mountpoint on SERVER
function internalCleanup_pos01
{
	RUN_CHECK RSH root $SERVER "\"umount ${mntdir2}; rm -rf ${mntdir2}\"" \
		|| exit $STF_FAIL
}
	

# Start main program here:
# ----------------------------------------------------------------------

# ipfilter doesn't support shared stack zones, so we can't set rules
# in non-global zone,  we need to set ipfilter rule in the server.
# For SETUP=none, we can't execute the command in the server.
# So in that case UNSUPPORTED is returned.
if [[ `zonename` != global ]]; then
	if [[ $SETUP == none ]]; then
		return $STF_UNSUPPORTED
	else
		IS_ZONE=1
		CMD="RSH root $SERVER"
		TMPDIR=$SRV_TMPDIR
	fi
else
	IS_ZONE=0
	CMD=""
	TMPDIR=$STF_TMPDIR
fi

internalSetup_pos01
retcode=0

ASSERTION_A="Verify that SERVER will provide conflicting layout and lock to other\
	client after the lease expiration, expect success"

echo "$NAME{a}: $ASSERTION_A"
assertion_a
retcode=$?

internalCleanup_pos01
RUN_CHECK $CMD rm -f $TMPDIR/network_feedback_file $TMPDIR/network_block_flag

(( $retcode == $STF_PASS )) \
    && cleanup $STF_PASS "" "$MNTDIR/$TESTFILE01 $STF_TMPDIR/$NAME.*.$$" \
    || cleanup $retcode "" "$MNTDIR/$TESTFILE01 $STF_TMPDIR/$NAME.*.$$" 

