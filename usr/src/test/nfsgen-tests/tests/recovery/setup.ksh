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
# For recovery testing purposes, cleanup server filesystem from
# previous nfs4_gen test suite being run. Setup server with 
# reboot capability.
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

[[ $SETUP == "none" ]] && exit $STF_UNSUPPORTED

DIR=$(dirname $0)

function internalCleanup 
{
	fileList="$STF_TMPDIR/recov_setserver \
		$STF_TMPDIR/nfs4red \
		$STF_TMPDIR/S99nfs4red \
		$STF_TMPDIR/rsh.out.$$ \
		$STF_TMPDIR/recov_setclient2 \
		$STF_TMPDIR/rcp.out.$$"

	cleanup $1 "" $fileList
}
	

function prepareRemoteEnv 
{
	rm -f $STF_TMPDIR/$SERVER.recov_env
	echo "PATH=/opt/SUNWstc-genutils/bin:/usr/bin:/usr/sbin:/usr/lib/nfs:\$PATH; export PATH" \
       		 > $STF_TMPDIR/$SERVER.recov_env
	echo "NFSGEN_DEBUG=$NFSGEN_DEBUG; export NFSGEN_DEBUG" >> $STF_TMPDIR/$SERVER.recov_env
	echo "CLIENT=$CLIENT; export CLIENT" >> $STF_TMPDIR/$SERVER.recov_env
	echo "SERVER=$SERVER; export SERVER" >> $STF_TMPDIR/$SERVER.recov_env
	echo "SHRDIR=$SHRDIR; export SHRDIR" >> $STF_TMPDIR/$SERVER.recov_env
	echo "MNTOPT=$MNTOPT; export MNTOPT" >> $STF_TMPDIR/$SERVER.recov_env
	echo "LC_ALL=C; export LC_ALL" >> $STF_TMPDIR/$SERVER.recov_env
	echo "NOTICEDIR=$NOTICEDIR; export NOTICEDIR" >> $STF_TMPDIR/$SERVER.recov_env
}


# add environment variables to srv_setup script:
rm -f $STF_TMPDIR/recov_setserver $STF_TMPDIR/srv_checkDir.ksh
cd $DIR
prepareRemoteEnv

# check STF_TMPDIR
cat > $STF_TMPDIR/srv_checkDir.ksh << EOF
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
checkdir=\$1
swapList="\`mount | grep swap | awk '{print \$1}'\`"
for i in \$swapList
do
        echo \$checkdir | grep \^\$i
        if [[ \$? == 0 ]]; then
                echo "\$checkdir is in a swap partition, temp files will lost after reboot"
                return 1
        fi
done
EOF

#check STF_TMPDIR is not located in a swap partition
RUN_CHECK RSH root $SERVER "mkdir -p $SRV_TMPDIR" || exit $STF_UNINITIATED
RUN_CHECK scp $STF_TMPDIR/srv_checkDir.ksh root@$SERVER:$SRV_TMPDIR || exit $STF_UNINITIATED
RSH root $SERVER "/usr/bin/ksh $SRV_TMPDIR/srv_checkDir.ksh $SRV_TMPDIR" > $STF_TMPDIR/rsh.out.$$ 2>&1
if (( $? != 0 )); then
        echo "check $SRV_TMPDIR is in a swap partition on $SERVER failed"
        cat $STF_TMPDIR/rsh.out.$$
        exit $STF_UNINITIATED
fi

SETD="NFSGEN_DEBUG=0; export NFSGEN_DEBUG"
[[ :${NFSGEN_DEBUG}: == *:${NAME}:* || :${NFSGEN_DEBUG}: == *:all:* ]] \
        && SETD="NFSGEN_DEBUG=$NFSGEN_DEBUG; export NFSGEN_DEBUG"

sed -e "s%Tmpdir_from_client%$SRV_TMPDIR%" -e "s%SetDebugMode%$SETD%"\
	-e "s%ENV_from_client%$SERVER.recov_env%" -e "s%NFS_UTIL%nfs-util.kshlib%"\
	-e "s%TEST_ZFS%$TestZFS%" -e "s%SHR_DIR%$SHRDIR%"\
	-e "s%SHR_OPT%$SHROPT%" -e "s%SHR_GRP%$SHRGRP%" srv_setup > $STF_TMPDIR/recov_setserver
if (( $? != 0 )); then
        echo "$NAME: can't setup [recov_setserver] file."
	internalCleanup $STF_UNINITIATED
fi

# and the reboot scripts
sed -e "s%Tmpdir_from_client%$SRV_TMPDIR%" \
	-e "s%SetDebugMode%$SETD%"\
        -e "s%ENV_from_client%$SERVER.recov_env%" nfs4red > $STF_TMPDIR/nfs4red
if [ $? -ne 0 ]; then
        echo "$NAME: can't setup [nfs4red] file."
	internalCleanup $STF_UNINITIATED
fi

sed -e "s%Tmpdir_from_client%$SRV_TMPDIR%" \
        -e "s%ENV_from_client%$SERVER.recov_env%" \
	-e "s%SetDebugMode%$SETD%" S99nfs4red > $STF_TMPDIR/S99nfs4red
if (( $? != 0 )); then
        echo "$NAME: can't setup [S99nfs4red] file."
	internalCleanup $STF_UNINITIATED
fi


# ... now setup the $SERVER
RSH root $SERVER "mkdir -p $SRV_TMPDIR" > $STF_TMPDIR/rsh.out.$$ 2>&1
if (( $? != 0 )); then
	echo "$NAME: create temp direcotry on $SERVER failed:"
	cat $STF_TMPDIR/rsh.out.$$
	internalCleanup $STF_OTHER
fi

# copy server programs over to $SERVER for setup
scp $STF_TMPDIR/recov_setserver $STF_TMPDIR/$SERVER.recov_env $STF_TMPDIR/nfs4red \
	$STF_SUITE/include/nfs-util.kshlib root@$SERVER:${SRV_TMPDIR} \
	> $STF_TMPDIR/rcp.out.$$ 2>&1
if (( $? != 0 )); then
	echo "$NAME: copying setup files to $SERVER failed:"
	cat $STF_TMPDIR/rcp.out.$$
	internalCleanup $STF_OTHER
fi

scp $STF_TMPDIR/S99nfs4red root@$SERVER:/etc/rc3.d > $STF_TMPDIR/rcp.out.$$ 2>&1
if (( $? != 0 )); then
        echo "$NAME: copying S99nfs4red file to $SERVER failed:"
        cat $STF_TMPDIR/rcp.out.$$
	internalCleanup $STF_OTHER
fi

RSH root $SERVER "/usr/bin/ksh ${SRV_TMPDIR}/recov_setserver -s" \
	> $STF_TMPDIR/rsh.out.$$ 2>&1
ret=$?
grep "OKAY" $STF_TMPDIR/rsh.out.$$ | grep -v echo > /dev/null 2>&1
if (( $? == 0 && $ret == 0 )); then
	# If server returned some warning, print it out
	grep "STF_WARNING" $STF_TMPDIR/rsh.out.$$ | grep -v echo > /dev/null 2>&1
	if (( $? == 0 )); then
		echo "$NAME: setup $SERVER have warnings:"
		grep STF_WARNING $STF_TMPDIR/rsh.out.$$
	fi
else
	grep "ERROR" $STF_TMPDIR/rsh.out.$$ | grep -v echo > /dev/null 2>&1
	if (( $? == 0 )); then
		echo "$NAME: setup $SERVER had errors:"
	else
		echo "$NAME: setup $SERVER failed:"
	fi
	cat $STF_TMPDIR/rsh.out.$$
	internalCleanup $STF_OTHER
fi
[[ :${NFSGEN_DEBUG}: == *:${NAME}:* || :${NFSGEN_DEBUG}: == *:all:* ]] \
	&& cat $STF_TMPDIR/rsh.out.$$

echo "  SERVER=$SERVER recovery setup OK!! "

internalCleanup $STF_PASS
