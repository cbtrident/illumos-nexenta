#! /usr/bin/ksh
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
# These cases are intended to test client recovery when server
# randomly returns a BAD_SEQID error.
#
# Strategy
#    Modify seqid on client, inspect the behavior of client
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& set -x

DIR=$(dirname $0)
SEQID_DIR=${SEQID_DIR:-"$ZONE_PATH/BadSeqid"}
TESTFILE="$SEQID_DIR/bad_seqid.txt"
SEQID_CASES=${SEQID_CASES:-"a b c"}

# used to export EXECUTION path
export RECOVERY_EXECUTE_PATH=$DIR
export RECOVERY_STAT_PATH=$STF_SUITE/bin/


# distinguish different kinds of error
# For the fatal errors, the test will be terminated and only
# some assertions info will be printed, such as mdb fails.
# For the failure that seqid can't be fetched, the test will
# continue
typeset cont_flg=0
typeset prog=$STF_SUITE/bin/file_operator

# fail to intialize, print some basic cases info
function prt_info 
{
	CODE=$1
	shift
	MSG="$*"
	for seqid_case in $SEQID_CASES; do
		echo "$NAME{$seqid_case}: $MSG"
		echo "\tTest $CODE"
	done
}

# check result and print out failure messages
function ckres 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

        op=$1
        st=$2
        expt=$3
        if [[ -n $4 ]]; then
                res=$4
                # if $res is an operation output file, get its content
                if [[ -f $res ]]; then
                        res=$(cat $res)
                else
                        # is a string, get all components from $4 to last
                        shift; shift; shift
                        res="$@"
                fi
        fi
        tmp=$(echo $expt | sed 's/|/ /g')
        expt=$tmp
        code="STF_FAIL"
        # if exported var for code different from STF_FAIL
        [[ -n $ckres_code ]] && code=$ckres_code
        ret=$(echo $expt | grep "$st")
        if (( $? != 0 )); then
                echo "\tTest $code: $op returned ($st), expected ($expt)"
                [[ -n $res ]] && echo "\t\tres = $res\n"
		return 1
        else
                echo "\tTest PASS"
		return 0
        fi
}


ck_zone 1 " "
if (( $? != 0 )); then
	prt_info STF_UNSUPPORTED "Not supported in non-global zone."
	exit $STF_UNSUPPORTED
fi

# the parameters to open the testfile
is_cipso "vers=4" $SERVER
if (( $? == $CIPSO_NFSV4 )); then
	#
	# For Trusted Extensions the user role
	# 'root' while in the global zone can
	# read files from non-global zones.
	# Non-root roles cannot.
	#
	PARMS="root"
else
	PARMS="$TUSER01"
fi

# clean up the tmp files
function internalCleanup 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset local_res=$1
	[[ -n $pid1 ]] && kill $pid1 > /dev/null 2>&1 && pid1=""
	[[ -n $pid2 ]] && kill $pid2 > /dev/null 2>&1 && pid2=""
	
	if (( $local_res != 0 )); then
		[[ -s $STF_TMPDIR/$NAME.1.$$ ]] && echo "--$NAME.1.$$--" \
			&& cat $STF_TMPDIR/$NAME.1.$$
		[[ -s $STF_TMPDIR/$NAME.2.$$ ]] && echo "--$NAME.2.$$--" \
			&& cat $STF_TMPDIR/$NAME.2.$$
	fi
	umount -f $SEQID_DIR > /dev/null 2>&1
	rm -rf $STF_TMPDIR/${NAME}* $SEQID_DIR
	exit $local_res
}

# Start the tests with some information
echo " "
echo "Testing at CLIENT=[`uname -n`] to SERVER=[$SERVER]"
echo "\ton the directory=[$SEQID_DIR]"
echo "Started BAD_SEQID tests at [`date`] ..."
echo " "

umount -f $SEQID_DIR > /dev/null 2>&1
mkdir -p -m 0777 $SEQID_DIR
if (( $? != 0 )); then
	prt_info STF_UNINITIATED "ERROR: Cannot create $SEQID_DIR."
	exit $STF_UNINITIATED
fi
mount -F nfs -o rw,vers=4 $SERVER:$SHRDIR $SEQID_DIR > /dev/null 2>&1
res=$?
if (( $res != 0 )); then
	prt_info STF_UNINITIATED "ERROR: Cannot mount $SEQID_DIR on $CLIENT."
	internalCleanup $STF_UNINITIATED
fi

echo "Test NFS4ERR_BAD_SEQID" > $TESTFILE
res=$?
if (( $res != 0 )); then
	prt_info STF_UNINITIATED "ERROR: Cannot create $TESTFILE on $CLIENT."
	internalCleanup $STF_UNINITIATED
fi

chmod 666 $TESTFILE
COMMAND="::nfs4_oob"

case $(isainfo -k) in
	sparcv9 ) offset=0x16 ;;
	amd64 ) offset=0x14 ;;
	* ) offset=0x10 ;;
esac

# record the tried times
# increase it when can't get seqid in normal operations
# reset to 0 at the beginning of each case
typeset -i try_times=0
typeset -i max_try=5
typeset addr_base
typeset seqid
typeset caseid
typeset pid1 pid2

# set up environment for the test
function refresh_mnt 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset local_res
	[[ -n $pid1 ]] && kill -9 $pid1 > /dev/null 2>&1 && pid1=""
	[[ -n $pid2 ]] && kill -9 $pid2 > /dev/null 2>&1 && pid2=""

	umount -f $SEQID_DIR > /dev/null 2>&1
	mount -F nfs -o rw $SERVER:$SHRDIR $SEQID_DIR > /dev/null 2>&1
	if (( $? != 0 )); then 
		echo "\tWarning: Cannot mount $SEQID_DIR on $CLIENT." \
		return $STF_FAIL 
	else
		return $STF_PASS
	fi
}

# Get the current seqid list
# If error is returned, the test will terminate, only some cases info
# is printed
function snap_seqid 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset filename=$1
	ret=$(echo $COMMAND | mdb -kw 2>$filename)
	if (( $? != 0 )); then
		echo "\tWarning: Cannot get seqid on $CLIENT." 
		echo $ret 
		cat $filename
		return $STF_FAIL
	fi
	echo "$ret" | grep -v "^$" | grep -v SeqID | sort > $filename 2>/dev/null
	return $STF_PASS
}

# Get the target seqid which will be got via compare the two seqids
# before and after a specified operation. If only one seqid is got,
# it will be treated as the wanted
# If 1 is returned, the test can be contiured, try again to get seqid
# If other error is returned, the test will terminate, only some
# cases info is printed
function get_seqid 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset -i num=0
	# get the seqid list after the operation
	snap_seqid $STF_TMPDIR/$NAME.2.$$
	(( $? != 0 )) && return $STF_FAIL

	# compare two seqid file to get the seqid
	comm -13 $STF_TMPDIR/$NAME.1.$$ $STF_TMPDIR/$NAME.2.$$ \
		>$STF_TMPDIR/$NAME.3.$$ 2>&1
	(( $? != 0 )) && echo "\tWarning: Comm files error on $CLIENT." \
		&& cat $STF_TMPDIR/$NAME.3.$$ && return 1
	num=$(wc -l $STF_TMPDIR/$NAME.3.$$ | awk '{print $1}')
	if (( num == 1 )); then
		# get a uniq seqid, treat it as the desired one
		addr_base=$(cat $STF_TMPDIR/$NAME.3.$$ | awk '{print $1}')
		seqid=$(cat $STF_TMPDIR/$NAME.3.$$ | awk '{print $4}')
		return $STF_PASS
	else
		num=0
		while read addr cred refcnt sid justcre seqinuse; do
			grep $addr $STF_TMPDIR/$NAME.1.$$ > /dev/null
			ret=$?
			if [[ $1 == assert_b ]]; then
				(( $ret == 0 )) && num=$((num + 1)) \
					&& addr_base=$addr && seqid=$sid
			else
				(( $ret != 0 )) && num=$((num + 1)) \
					&& addr_base=$addr && seqid=$sid
			fi
		done < $STF_TMPDIR/$NAME.3.$$
		if (( num != 1 )); then
			# did not get A seqid, try again
			# it's the only branch to increase try_times
			addr_base=""
			seqid=""
			return $STF_FAIL
		fi
	fi
}

# Modify the value of seqid
# If error is returned, the test will terminate, only some cases info
function write_seqid 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	if [[ -z $addr_base || -z $seqid ]]; then
		echo "\tWarning: addr_base or seqid is null."
		return $STF_FAIL
	fi

	seqid=$(($seqid+10))
	echo "$addr_base+$offset/w $seqid" | mdb -kw > $STF_TMPDIR/$NAME.3.$$ 2>&1
	local_res=$?
	if (( $local_res != 0 )); then
		echo "\tWarning: Cannot modify seqid on $CLIENT."
		cat $STF_TMPDIR/$NAME.3.$$
	fi
	return $local_res
}

# test case a
# ----------------------------------------------------------------------
# 1) client mounts server
# 2) client opens a file for READ, but doesn't close it (this sends over
#    OP_OPEN and generates an open owner).
# 3) use mdb to modify the newly created open owner's seqid
# 4) client now opens the same  file for WRITE - this should send over
#    OP_OPEN and get back BAD_SEQID
function bad_seqid_a 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

	try_times=0
	cont_flg=1
	ex="send over OP_OPEN and get back NFS4ERR_BAD_SEQID"
	echo $caseid "Client opens a file for READ and doesn't close it.\n\
	Modify the newly created open owner's seqid. Opens the same\n\
	file for WRITE, expect: " $ex

	MSG="incorrect status of file close in WRITE"
	FILE_STATUS=0

	while (( try_times < max_try )); do
		(( try_times+=1 ))
		refresh_mnt
		(( $? != 0 )) && continue

		# get the seqid list before the operation
		snap_seqid $STF_TMPDIR/$NAME.1.$$
		(( $? != 0 )) && continue

		$prog -R -c -o 0 -B "0 0 0" $TESTFILE \
			> $STF_TMPDIR/$NAME.outw.$$ &
		pid1=$!

		wait_now 200 "grep \"I am ready\" $STF_TMPDIR/$NAME.outw.$$" \
              	  > $STF_TMPDIR/$NAME.err.$$ 2>&1
		if (( $? != 0 )); then
			echo "file_opeartor failed to be ready with 200 seconds"
			kill $pid1
			return $STF_FAIL
		fi

		get_seqid
		(( $? == 0 )) && write_seqid && (( $? == 0 )) && \
			cont_flg=0 && break
		
		# kill pid1 before continue
		kill $pid1
	done

	if (( $cont_flg != 0 )); then
		MSG="Cannot get seqid on $CLIENT after $max_try tries"
		ckres snap_seqid $cont_flg $STF_PASS $MSG
		kill $pid1
		return $STF_FAIL
	else
		$prog -W -c -o 7 -B "0 0 -1" $TESTFILE
		ckres NFS4ERR_BAD_SEQID $? $FILE_STATUS $MSG
		if (( $? != 0 )); then
			kill $pid1
			echo "check close operation failed"
			return $STF_FAIL
		fi
		kill $pid1 > /dev/null 2>&1
		return $STF_PASS
	fi
}

# test case b
# ----------------------------------------------------------------------
# 1) client mounts server
# 2) client opens a file for READ, but doesn't close it (this sends over
#    OP_OPEN and generates an open owner).
# 3) client opens the same file for WRITE, but doesn't close it (this
#    sends over another OP_OPEN).
# 4) use mdb to modify the newly created open owner's seqid
# 5) client close its file descriptor for WRITE - this should send over
#    OP_OPEN_DOWNGRADE and get back BAD_SEQID
function bad_seqid_b 
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
	
	try_times=0
	cont_flg=1
	ex="send over OP_OPEN_DOWNGRADE and get back NFS4ERR_BAD_SEQID"
	echo $caseid "Client opens a file for READ and doesn't close it.\n\
	Client opens the same file for WRITE and doesn't close it.\n\
	Modify the newly created open owner's seqid, close its file\n\
	descriptor for WRITE, expect: " $ex

	MSG="incorrect status of file close in WRITE"
	FILE_STATUS=5	# I/O error

	while (( try_times < max_try )); do
		(( try_times+=1 ))
		refresh_mnt
		(( $? != 0 )) && continue

                $prog -R -c -o 0 -B "0 0 0" $TESTFILE \
			> $STF_TMPDIR/$NAME.outR.$$ 2>&1 & 
		pid1=$!

		wait_now 200 "grep \"I am ready\" $STF_TMPDIR/$NAME.outR.$$" \
              	  > $STF_TMPDIR/$NAME.err.$$ 2>&1
		if (( $? != 0 )); then
			echo "file_opeartor failed to be ready with 200 seconds"
			kill $pid1
			return $STF_FAIL
		fi

		# get the seqid list before the operation
		snap_seqid $STF_TMPDIR/$NAME.1.$$
		(( $? != 0 )) && continue

                $prog -W -c -o 4 -B "0 0 0" $TESTFILE \
			> $STF_TMPDIR/$NAME.outW.$$ 2>&1 & 
		pid2=$!

		wait_now 200 "grep \"I am ready\" $STF_TMPDIR/$NAME.outW.$$" \
              	  > $STF_TMPDIR/$NAME.err.$$ 2>&1
		if (( $? != 0 )); then
			echo "file_opeartor failed to be ready with 200 seconds"
			kill $pid1
			kill $pid2
			return $STF_FAIL
		fi

		get_seqid assert_b
		(( $? == 0 )) && write_seqid && (( $? == 0 )) && \
			cont_flg=0 && break
	
		# kill pid1 and pid2 before continue
                kill $pid1
                kill $pid2
	done

	if (( $cont_flg != 0 )); then
		MSG="Cannot get seqid on $CLIENT after $max_try tries"
		ckres snap_seqid $cont_flg $STF_PASS $MSG
		return $STF_FAIL
	else
		kill -16 $pid2 > /dev/null 2>&1
		wait $pid2 > /dev/null 2>&1
		ckres NFS4ERR_BAD_SEQID $? $FILE_STATUS $MSG
		if (( $? != 0 )); then
			kill $pid1
			echo "check pid2=$pid2 failed"
			return $STF_FAIL
		fi
		kill -16 $pid1 > /dev/null 2>&1
		wait $pid1 > /dev/null 2>&1
		if (( $? != 0 )); then
			echo "failed to wait pid1=$pid1"
			return $STF_FAIL
		fi
	fi

	return $STF_PASS
}

# test case c
# ----------------------------------------------------------------------
# 1) client mounts server
# 2) client opens a file for READ, but doesn't close it (this sends over
#    OP_OPEN and generates an open owner).
# 3) use mdb to modify the newly created open owner's seqid
# 4) client closes the file - this should send over OP_CLOSE and get back
#    BAD_SEQID
function bad_seqid_c
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
	try_times=0
	cont_flg=1
	ex="send over OP_CLOSE and get back NFS4ERR_BAD_SEQID"
	echo $caseid "Client opens a file for READ and doesn't close it. \
	Modify the newly created open owner's seqid and close \
	the file, expect: " $ex

	MSG="incorrect status of close file in READ"
	FILE_STATUS=5	# I/O error

	while (( try_times < max_try )); do
		(( try_times+=1 ))
		refresh_mnt
		(( $? != 0 )) && continue

		# get the seqid list before the operation
		snap_seqid $STF_TMPDIR/$NAME.1.$$
		(( $? != 0 )) && continue

                $prog -R -c -o 0 -B "0 0 0" $TESTFILE > \
			$STF_TMPDIR/$NAME.outR.$$ 2>&1 &
		pid1=$!

		wait_now 200 "grep \"I am ready\" $STF_TMPDIR/$NAME.outR.$$" \
                  > $STF_TMPDIR/$NAME.err.$$ 2>&1
                if (( $? != 0 )); then
                        echo "file_opeartor failed to be ready with 200 seconds"
                        kill $pid1
                        return $STF_FAIL
                fi

		get_seqid 
		(( $? == 0 )) && write_seqid && (( $? == 0 )) && \
			cont_flg=0 && break

		# kill pid1 before continue
                kill $pid1
	done

	if (( $cont_flg != 0 )); then
		MSG="Cannot get seqid on $CLIENT after $max_try tries"
		ckres snap_seqid $cont_flg $STF_PASS $MSG
		kill $pid1
		return $STF_FAIL
	else
		kill -16 $pid1 > /dev/null 2>&1
		wait $pid1 > /dev/null 2>&1
		ckres NFS4ERR_BAD_SEQID $? $FILE_STATUS $MSG
		if (( $? != 0 )); then
			echo "failed to check close operation with pid=$pid1"
			return $STF_FAIL
		fi
	fi

	return $STF_PASS
}

bad_seqid_a
retcode=$?

bad_seqid_b
retcode=$(($retcode+$?))

bad_seqid_c
retcode=$(($retcode+$?))

(( $retcode == $STF_PASS )) && internalCleanup $STF_PASS || internalCleanup $STF_FAIL
