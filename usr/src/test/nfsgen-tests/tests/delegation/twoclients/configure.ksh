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

CLNT2_MNTDIRV4="$ZONE_PATH/clnt2_mount_v4"
CLNT2_MNTOPTV4="vers=4"

CLNT2_MNTDIRV3="$ZONE_PATH/clnt2_mount_v3"
CLNT2_MNTOPTV3="vers=3"

CLNT2_MNTDIRV2="$ZONE_PATH/clnt2_mount_v2"
CLNT2_MNTOPTV2="vers=2"

if [[ $CLIENT2 == $SERVER ]]; then
	# server local filesystem
	export CLNT2_TESTDIR_LIST=$SHRDIR
else
	# client2's mount points
        if [[ -z $ZONE_PATH ]]; then
		export CLNT2_TESTDIR_LIST="$CLNT2_MNTDIRV4 \
			$CLNT2_MNTDIRV3 $CLNT2_MNTDIRV2"
	else
		# TX doesn't support nfsv2
		export CLNT2_TESTDIR_LIST="$CLNT2_MNTDIRV4 $CLNT2_MNTDIRV3"
	fi
fi

cat >> $1 <<-EOF
export CLNT2_MNTDIRV4=$CLNT2_MNTDIRV4
export CLNT2_MNTOPTV4=$CLNT2_MNTOPTV4
export CLNT2_MNTDIRV3=$CLNT2_MNTDIRV3
export CLNT2_MNTOPTV3=$CLNT2_MNTOPTV3
export CLNT2_MNTDIRV2=$CLNT2_MNTDIRV2
export CLNT2_MNTOPTV2=$CLNT2_MNTOPTV2
export CLNT2_TESTDIR_LIST="$CLNT2_TESTDIR_LIST"
EOF
