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
# cleanup script for nfs server environment
#

. ${STF_SUITE}/include/nfsgen.kshlib

NAME=$(basename $0)
DIR=$(dirname $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

[[ $SETUP == "none" ]] && exit $STF_PASS

# now cleanup the SERVER
RSH root $SERVER "/usr/bin/ksh ${SRV_TMPDIR}/recov_setserver -c; \
	rm -f ${SRV_TMPDIR}/recov_setserver ${SRV_TMPDIR}/nfs-smf.kshlib" \
	> ${STF_TMPDIR}/rsh.out.$$ 2>&1
grep "OKAY" ${STF_TMPDIR}/rsh.out.$$ | grep -v echo > /dev/null 2>&1
if (( $? != 0 )); then
	grep ERROR ${STF_TMPDIR}/rsh.out.$$ | grep -v echo > /dev/null 2>&1
	if (( $? == 0 )); then
		echo "$NAME: cleanup $SERVER failed:"
		cat ${STF_TMPDIR}/rsh.out.$$
	fi
	cleanup $STF_FAIL "" ${STF_TMPDIR}/rsh.out.$$
else
	# If server returned some warning, print it out
	grep "STF_WARNING" $STF_TMPDIR/rsh.out.$$ | grep -v echo > /dev/null 2>&1
	if (( $? == 0 )); then
		cat $STF_TMPDIR/rsh.out.$$
	fi
fi

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& cat $STF_TMPDIR/rsh.out.$$
echo "$NAME: $SERVER rec_cleanup OK!! "

cleanup $STF_PASS "" "${STF_TMPDIR}/*.out.$$ \
	${STF_TMPDIR}/S99nfs4red \
	${STF_TMPDIR}/nfs4red \
	${STF_TMPDIR}/recov_setserver \
	${STF_TMPDIR}/recov_setclient2"
