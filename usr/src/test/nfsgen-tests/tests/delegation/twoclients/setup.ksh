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

. ${STF_SUITE}/include/nfsgen.kshlib
. ${STF_SUITE}/tests/delegation/include/delegation.kshlib

# Turn on debug info, if requested
NAME=$(basename $0)
[[ :${NFSGEN_DEBUG}: == *:${NAME}:* \
        || :${NFSGEN_DEBUG}: == *:all:* ]] && set -x

# Check CLIENT2 is set and reachable
if  [[ -z $CLIENT2 ]]; then
        print -u2 "CLIENT2 variable must be set, exiting."
	exit $STF_UNTESTED
fi

if [[ $CLIENT2 == $SERVER ]] && [[ $SETUP == "none" ]] ; then
	print -u2 "Skip tests in this subdir[SETUP: $SETUP, CLIENT2: $CLIENT2]"
	exit $STF_UNTESTED
fi

RUN_CHECK /usr/sbin/ping $CLIENT2 || exit $STF_UNINITIATED
RUN_CHECK RSH root $CLIENT2 "mkdir -p $SRV_TMPDIR/delegation/bin" || \
	exit $STF_UNINITIATED

[[ $IS_KRB5 == 1 ]] && KOPT=",$SecOPT" || KOPT=""
if [[ $CLIENT2 != $SERVER ]]; then
	# Mount test dirs on CLIENT2
	# make sure to use the same path as current client
	realMNT=$(get_realMNT $MNTDIR 2> $STF_TMPDIR/$NAME.err.$$)
	(( $? != 0 )) && cleanup $STF_UNINITIATED $STF_TMPDIR/$NAME.err.$$
	mDIR=$(echo $MNTDIR | sed "s%$realMNT%%")
	nSDIR=${SHRDIR}${mDIR}

	RUN_CHECK RSH root $CLIENT2 \
	    "mkdir -p $CLNT2_MNTDIRV4 $CLNT2_MNTDIRV3 $CLNT2_MNTDIRV2" || \
		exit $STF_FAIL
	if [[ -z $ZONE_PATH ]]; then
		RUN_CHECK RSH root $CLIENT2 \
		    "mkdir -p $CLNT2_MNTDIRV4 $CLNT2_MNTDIRV3 $CLNT2_MNTDIRV2" || \
			exit $STF_FAIL
		RUN_CHECK RSH root $CLIENT2 \
		    "\"mount -o $CLNT2_MNTOPTV4 $SERVER:$nSDIR $CLNT2_MNTDIRV4 && \
		    mount -o $CLNT2_MNTOPTV3 $SERVER:$nSDIR $CLNT2_MNTDIRV3 && \
		    mount -o $CLNT2_MNTOPTV2$KOPT $SERVER:$nSDIR $CLNT2_MNTDIRV2\"" \
		        || exit $STF_FAIL
	else
		# TX doesn't support nfsv2
		RUN_CHECK RSH root $CLIENT2 \
		    "mkdir -p $CLNT2_MNTDIRV4 $CLNT2_MNTDIRV3" || \
			exit $STF_FAIL
		RUN_CHECK RSH root $CLIENT2 \
		    "\"mount -o $CLNT2_MNTOPTV4 $SERVER:$nSDIR $CLNT2_MNTDIRV4 && \
		    mount -o $CLNT2_MNTOPTV3 $SERVER:$nSDIR $CLNT2_MNTDIRV3\"" \
		        || exit $STF_FAIL
	fi
fi

# put variables into a file on the CLIENT2, and source it before
# calling the programs(file_operator,chg_usr_exec).
echo "export LD_LIBRARY_PATH=$SRV_TMPDIR/delegation/bin" \
	> $STF_TMPDIR/deleg.env

# Copy utilites on CLIENT2(or SERVER)
filelist="${STF_SUITE}/tests/delegation/bin/${CLIENT2_ARCH}/* \
	${STF_SUITE}/lib/${CLIENT2_ARCH}/libnfsgen.so \
	${STF_SUITE}/bin/${CLIENT2_ARCH}/file_operator \
	${STF_SUITE}/bin/${CLIENT2_ARCH}/chg_usr_exec"

if [[ $CLIENT2_BIN_USED == 0 ]]; then
	RUN_CHECK rcp $filelist $STF_TMPDIR/deleg.env \
		$CLIENT2:$SRV_TMPDIR/delegation/bin \
		|| exit $STF_FAIL
else
	RUN_CHECK rcp $STF_TMPDIR/deleg.env $CLIENT2:$SRV_TMPDIR/delegation/bin \
		|| exit $STF_FAIL
	RUN_CHECK RSH root $CLIENT2 "cp $filelist $SRV_TMPDIR/delegation/bin" \
		|| exit $STF_FAIL
fi

exit $STF_PASS
