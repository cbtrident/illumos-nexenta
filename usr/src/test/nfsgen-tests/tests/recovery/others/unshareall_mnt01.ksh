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
# NFSv4 test to verify client can't mount after server unshareall
#
. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& set -x

DIR=$(dirname $0)

# proc to check result and print out failure messages 
# ckres rc message cat_file
function ckres 
{
    [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
    rc=$1
    msg=${2}
    cf=${3}

    if (( $rc != 0 )); then
	echo "\t Test STF_FAIL: $msg"
	[[ -f $cf ]] && cat $cf
    fi
    return $rc
}

# First check this test is not started before previous tests
# grace period ends.
echo "xxx" > $MNTDIR/wait_for_grace
rm -rf $MNTDIR/wait_for_grace > /dev/null 2>&1

TMPmnt=$ZONE_PATH/$NAME.$$
mkdir -m 0777 -p $TMPmnt


# Start test assertions here
# ----------------------------------------------------------------------
# a: Client tries to mount after server unshareall, expect fail
function assertion_a 
{
    [[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x
    ASSERTION="Client tries to mount after server unshareall"
    ASSERTION="$ASSERTION, expect fail"
    echo "$NAME{a}: $ASSERTION"
    # set SRVPATH be a "was" exported fs
    SRVPATH=$SHRDIR

    # First test it mount'ble from client
    mount -o vers=4,rw $SERVER:$SRVPATH $TMPmnt > $STF_TMPDIR/$NAME.mnt.$$ 2>&1
    ckres $? "mount <vers=4,rw $SERVER:$SRVPATH> failed" $STF_TMPDIR/$NAME.mnt.$$
    (( $? != 0 )) && return $STF_FAIL

    # verify the mount point is access'ble
    ls -lL $TMPmnt > $STF_TMPDIR/$NAME.ck.$$ 2>&1
    ckres $? "unable to access the mnt-point after unshare" $STF_TMPDIR/$NAME.ck.$$
    (( $? != 0 )) && return $STF_FAIL

    # umount it
    umount $TMPmnt > $STF_TMPDIR/$NAME.umnt.$$ 2>&1
    ckres $? "umount failed" $STF_TMPDIR/$NAME.umnt.$$
    (( $? != 0 )) && return $STF_FAIL

    # now have the SERVER to do an unshareall
    RSH root $SERVER "/usr/sbin/sharemgr stop -a" > $STF_TMPDIR/$NAME.srv.$$ 2>&1
    ckres $? "unshare $SRVPATH failed" $STF_TMPDIR/$NAME.srv.$$
    (( $? != 0 )) && return $STF_FAIL

    # and try to mount again with "/" and the original FS
    mount -o vers=4,ro $SERVER:/ $TMPmnt > $STF_TMPDIR/$NAME.mnt.$$ 2>&1
    if (( $? == 0 )); then 
	echo "\t Test STF_FAIL: mount <vers=4,ro $SERVER:/> did not fail"
	cat $STF_TMPDIR/$NAME.mnt.$$
	return $STF_FAIL
    fi

    mount -o vers=4,rw $SERVER:$SRVPATH $TMPmnt > $STF_TMPDIR/$NAME.mnt.$$ 2>&1
    if (( $? == 0 )); then 
	echo "\t Test STF_FAIL: mount <vers=4,ro $SERVER:$SRVPATH> did not fail"
	cat $STF_TMPDIR/$NAME.mnt.$$
	return $STF_FAIL
    fi

    # finally re-shareall in SERVER
    RSH root $SERVER "/usr/sbin/sharemgr start -a" > $STF_TMPDIR/$NAME.srv.$$ 2>&1
    ckres $? "shareall $SRVPATH failed" $STF_TMPDIR/$NAME.srv.$$
    (( $? != 0 )) && return $STF_FAIL

    RSH root $SERVER "/usr/bin/ksh ${SRV_TMPDIR}/recov_setserver -r" > $STF_TMPDIR/$NAME.srv.$$ 2>&1
    ckres $? "reshare $SHRDIR on $SERVER failed" $STF_TMPDIR/$NAME.srv.$$
    (( $? != 0 )) && return $STF_FAIL

    echo "\t Test PASS"
    return $STF_PASS
}


# Start main program here:
# ----------------------------------------------------------------------

assertion_a 
(( $? == $STF_PASS )) && cleanup $STF_PASS "" "$TMPmnt $STF_TMPDIR/$NAME.*.$$" \
	|| cleanup $STF_FAIL "" "$TMPmnt $STF_TMPDIR/$NAME.*.$$"

