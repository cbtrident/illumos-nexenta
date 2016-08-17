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
# a: Verify that CLIENT continues to write data after nfs communication (between SERVER and CLIENT)
#    disable-enable cycle on SERVER
# b: Verify that CLIENT continues to read data after nfs communication (between SERVER and CLIENT)
#    disable-enable cycle on SERVER
# c: Verify that CLIENT continues to write data after nfs communication (between SERVER and CLIENT)
#    disable-enable cycle on SERVER. During the period of communication disabled, CLIENT try to do 
#    IO (will hang)
# d: Verify that CLIENT continues to read data after nfs communication (between SERVER and CLIENT)
#    disable-enable cycle on SERVER. During the period of communication disabled, CLIENT try to do 
#    IO (will hang)
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

DIR=$(dirname $0)
prog=$STF_SUITE/bin/file_operator

if [[ ! -x $prog ]]; then
	echo "$NAME: the executible program '$prog' not found."
	echo "\t Test FAIL"
	return $STF_FAIL
fi

function internalCleanup
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x
	filelist="$STF_TMPDIR/$NAME.out.$$ \
		$STF_TMPDIR/$NAME.out2.$$"
	rm -f $filelist $*
}

# For READ test, in order to avoid reading data from cache wrotten by WRITE test
# here we intended to prepare a file for read later
function internalSetup
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset testfile=$1
	rm -f $testfile
	$prog -W -c -o 4 -e $RANDOM -B "32768 2048 -1" $testfile > \
		$STF_TMPDIR/$NAME.out.$$ 2>&1
	if (( $? != 0 )); then
		internalCleanup $testfile
		echo "\tTest FAIL"
		exit $STF_FAIL
	fi
}


# main function
function assertion_func
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	if (( $# < 5 )); then
		echo "Invalid arguments: $*"
		return $STF_FAIL
	fi

	typeset testfile=$1
	typeset iooption=$2
	typeset testseed=$3
	typeset buffoption=$4
	typeset ioduringblock=$5
	typeset timeout=250
	typeset pid=""
	typeset pidnw=""
	typeset nwret=""


	# start to write or read
	$prog $iooption -c -o 4 -e $testseed "$buffoption" $testfile \
		> $STF_TMPDIR/$NAME.out.$$ 2>&1 & 
	pid=$!

	# make sure the process is ready
	wait_now $timeout "grep \"I am ready\" $STF_TMPDIR/$NAME.out.$$" \
		> $STF_TMPDIR/$NAME.err.$$ 2>&1
	if (( $? != 0 )); then
		echo "failed to get 'READY' sign from IO process"
		cat $STF_TMPDIR/$NAME.err.$$
		kill -9 $pid
		internalCleanup $testfile
		echo "\t Test FAIL"
		return $STF_FAIL
	fi


	# ipfilter doesn't support shared stack zones, so we can't
	# set rules locally, and need to rsh to server to set it
	# on the server.
	if [[ `zonename` != global ]]; then
		IPF_DIR=in
		HOSTOPT="-s $SERVER"
        else
		IPF_DIR=out
		HOSTOPT=""
        fi

	[[ $IS_IPV6 == 1 ]] && IPOPT="-v ipv6" || IPOPT=""
	if (( $ioduringblock == 1 )); then
		# touch block flag for ipfilter
		$CMD touch $TMPDIR/network_block_flag
		if (( $? != 0 )); then
			echo "failed to touch $STF_TMPDIR/network_block_flag"
			kill -9 $pid
			internalCleanup $testfile
			echo "\t Test FAIL"
			return $STF_FAIL
		fi
		# block the nfs communication between CLIENT and SERVER
		if [[ $IS_ZONE == 0 ]]; then
		    ipf_network $IPOPT \
		        -t $timeout -f $STF_TMPDIR/network_block_flag \
		        -r "block $IPF_DIR from $CLIENT to $SERVER port=2049" \
		        > $STF_TMPDIR/$NAME.reset_nw.$$ 2>&1 &
		    pidnw=$!
		else
		    # RSH doesn't support to run commands in background
		    ssh root@$SERVER /usr/bin/ksh -c \
		        "'. $TMPDIR/nfs-util.kshlib; \
		        . $TMPDIR/libsmf.shlib; \
		        ipf_network $IPOPT \
		        -t $timeout -f $STF_TMPDIR/network_block_flag \
		        -r \"block $IPF_DIR from $CLIENT to $SERVER port=2049\" \
		        '" > $STF_TMPDIR/$NAME.reset_nw.$$ 2>&1 &
		    pidnw=$!
		fi

		# make sure the network is blocked before IO.
		wait_now $timeout "$CMD ipfstat -oi | grep \"port = 2049\" > /dev/null" 
		if (( $? !=0 )); then
			echo "Failed to block the network"
			cat $STF_TMPDIR/$NAME.reset_nw.$$
			kill -9 $pid $pidnw
			internalCleanup $testfile
			echo "\t Test FAIL"
			return $STF_FAIL
		fi

		# conti to do IO during block perod
		kill -16 $pid

		# sleep for a while before restore the network communication
		sleep 10

		# remove block flag file to restore ipfilter settings on $SERVER
		RUN_CHECK $CMD rm $TMPDIR/network_block_flag
		wait $pidnw
		# make sure ipf_network() work well.
		wait_now 240 "grep \"ipf_network finished\" \
			$STF_TMPDIR/$NAME.reset_nw.$$ > /dev/null"
		nwret=$?
	else
		if [[ $IS_ZONE == 0 ]]; then
		    ipf_network $IPOPT -t 30 \
		        -r "block $IPF_DIR from $CLIENT to $SERVER port=2049" \
		        > $STF_TMPDIR/$NAME.reset_nw.$$ 2>&1
		    nwret=$?
		else
		    RSH root $SERVER \
			"export STF_TMPDIR=$SRV_TMPDIR; \
		        . $TMPDIR/nfs-util.kshlib; \
		        . $TMPDIR/libsmf.shlib; \
		        ipf_network $IPOPT -t 30 \
		        -r \"block $IPF_DIR from $CLIENT to $SERVER port=2049\"" \
		        > $STF_TMPDIR/$NAME.reset_nw.$$ 2>&1
		    nwret=$?
		fi
	fi

	if (( $nwret != 0 )); then
		echo "block nfs communication return failure"
		RUN_CHECK $CMD rm -f $TMPDIR/network_block_flag
		kill $pid
		cat $STF_TMPDIR/$NAME.reset_nw.$$
		internalCleanup $testfile
		echo "\t Test FAIL"
		return $STF_FAIL
	fi

	(( $ioduringblock == 0 )) && kill -16 $pid

	# wait the io process to finish
	wait $pid

	internalCleanup $testfile
	if (( $? == 0 )); then
		echo "\tTest PASS"
		return $STF_PASS
	else
		echo "\tTest FAIL"
		return $STF_FAIL
	fi
}


# Start main program here:
# ----------------------------------------------------------------------

# ipfilter doesn't support shared stack zones, so we can't set rules
# in non-global zone,  we need to set ipfilter rule in the server. 
# For SETUP=none, we can't execute the command in the server.
# So in that case UNSUPPORTED is returned.
if [[ `zonename` != global ]]; then
	if [[ $SETUP == none ]]; then
		echo "The test doesn't support local zone with SETUP=none config"
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

internalSetup $MNTDIR/openfile_r.$$
retcode=0

ASSERTION_A="Verify that client continues to write data after network disable-enable \
           cycle on SERVER, expect success"
ASSERTION_B="Verify that client continues to read data after network disable-enable \
           cycle on SERVER, expect success"
ASSERTION_C="Verify that client continues to write data after network disable-enable \
	    cycle on SERVER, expect success. During the period of network disabled, \
	    CLIENT try to do IO" 
ASSERTION_D="Verify that client continues to read data after network disable-enable \
	    cycle on SERVER, expect success. During the period of network disabled, \
	    CLIENT try to do IO" 

echo "$NAME{a}: $ASSERTION_A"
assertion_func $MNTDIR/openfile_w.$$ -W $RANDOM "-B \"32768 2048 0\"" 0
retcode=$(($retcode+$?))

echo "$NAME{b}: $ASSERTION_B"
assertion_func $MNTDIR/openfile_r.$$ -R $RANDOM "-B \"32768 2048 0\"" 0
retcode=$(($retcode+$?))

echo "$NAME{c}: $ASSERTION_C"
assertion_func $MNTDIR/openfile_w2.$$ -W $RANDOM "-B \"32768 2048 0\"" 1
retcode=$(($retcode+$?))

echo "$NAME{d}: $ASSERTION_D"
assertion_func $MNTDIR/openfile_r.$$ -R $RANDOM "-B \"32768 2048 0\"" 1
retcode=$(($retcode+$?))


internalCleanup $MNTDIR/openfile_r.$$ $MNTDIR/openfile_w.$$ \
	$MNTDIR/openfile_w2.$$

(( $retcode == $STF_PASS )) && cleanup $STF_PASS || cleanup $STF_FAIL
