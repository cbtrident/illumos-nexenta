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

DIR=$(dirname $0)
NAME=$(basename $0)

. ${STF_SUITE}/include/nfsgen.kshlib

# Turn on debug info, if requested
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

# NFS version being tested
export TESTVERS=4

# Create temp dir on server
RUN_CHECK RSH root $SERVER "mkdir -p $SRV_TMPDIR/$SETUP" \
    || exit $STF_UNINITIATED

# Copy files
cat > $STF_TMPDIR/srv_env.vars << EOF
export SHRDIR="$SHRDIR"
export SHROPT="$SHROPT"
export SHRGRP="$SHRGRP"
export _NFS_STF_DEBUG="$_NFS_STF_DEBUG"
export PATH=$PATH:/opt/SUNWstc-genutils/bin
EOF
RUN_CHECK scp $DIR/srv_setup                    \
    $STF_TMPDIR/srv_env.vars                    \
    $STF_TOOLS/contrib/include/libsmf.shlib     \
    $STF_TOOLS/contrib/include/nfs-smf.kshlib   \
    $STF_SUITE/include/nfs-util.kshlib  \
    root@$SERVER:$SRV_TMPDIR/$SETUP || exit $STF_UNINITIATED

# Call server script to share SHRDIR
RUN_CHECK RSH root $SERVER "$SRV_TMPDIR/$SETUP/srv_setup -s" \
	> $STF_TMPDIR/setup.$$ || exit $STF_UNINITIATED

grep "^OKAY " $STF_TMPDIR/setup.$$  > /dev/null 2>&1
if (( $? != 0 )); then
	echo "ERROR: Check shared filesystem failed"
	cat $STF_TMPDIR/setup.$$
	rm -rf $STF_TMPDIR/setup.$$
	exit $UNTESTED
fi

strfs=$(cat $STF_TMPDIR/setup.$$)
rm $STF_TMPDIR/setup.$$
FS_TYPE=$(echo $strfs | awk '{print $2}')
if [[ $FS_TYPE == "ufs" ]]; then
	TestZFS=0
elif [[ $FS_TYPE == "zfs" ]]; then
	TestZFS=1
else
	TestZFS=2
fi
if [[ $TestZFS == 2 ]]; then # fs is neither zfs nor ufs
	echo "$NAME: SHRDIR<$SHRDIR> on server<$SERVER> is based $FS_TYPE,"
        echo "\t this test suite only supports UFS and ZFS!"
        exit $UNSUPPORTED
fi
if [[ $TestZFS == 1 ]]; then # fs is zfs
        ZFSPOOL=$(echo $strfs | awk '{print $3}')
        zpool_stat=$(echo $strfs | awk '{print $4}')
        if [[ $zpool_stat != "ONLINE" ]]; then
                echo "$NAME: SHRDIR<$SHRDIR> on server<$SERVER> is based ZFS,"
                echo "\t but zpool<$ZFSPOOL> is not online: $zpool_stat"
                exit $UNTESTED
        fi
fi

# Save the variables in config file
cat >> $1 <<-EOF
export FS_TYPE=$FS_TYPE
export TestZFS=$TestZFS
export ZFSPOOL=$ZFSPOOL
export TESTVERS=$TESTVERS
EOF

# Mount it
RUN_CHECK mkdir -p $MNTDIR || exit $STF_UNINITIATED
RUN_CHECK mount -o $MNTOPT $SERVER:$SHRDIR $MNTDIR || exit $STF_UNINITIATED

exit $STF_PASS
