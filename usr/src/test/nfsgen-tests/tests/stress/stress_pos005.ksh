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

readonly FILE=$(whence -p ${0})
readonly NAME=$(basename $0)
readonly DIR=$(dirname $0)

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& set -x

if [[ $SHRDIR == "/" ]]; then
        echo "As SHRDIR is set '/', the case can't run 'ls' in MNTDIR"
        exit $STF_UNTESTED
fi

echo "\n $NAME: looping mount/ls in ${SERVER}:$SHRDIR mounting <${MNTOPT}>"
echo "\t START TIME: `date`\n"

#
# Default of 500 iterations unless 1st parameter to
# testcase sez otherwise.
#
ST05_ITER=${ST05_ITER:-500}
echo "\t ==> Going to loop thru ${ST05_ITER} times"

# create a tmp dir as a mount point
TMPMNT=${ZONE_PATH}${STF_TMPDIR}/${NAME}.mnt.$$
mkdir -p ${TMPMNT}
[[ $MNTOPT == "" ]] && MNTOPT="rw"
typeset i=0
while (( $i < ${ST05_ITER} )); do
	# Do the mount
	mount -o ${MNTOPT} ${SERVER}:${SHRDIR} ${TMPMNT} > ${STF_TMPDIR}/mnt.$i.$$ 2>&1 
	if (( $? != 0 )); then
		echo "ERROR: KID=$i, Mount failed"
		cat ${STF_TMPDIR}/mnt.$i.$$
		cleanup $STF_FAIL
	fi

	ls -lR ${TMPMNT} > $STF_TMPDIR/ls.$i.$$ 2>&1
	if (( $? != 0 )); then
		echo "ERROR: KID=$i, ls -lR ${TMPMNT} failed"
		cat $STF_TMPDIR/ls.$i.$$
		umount -f ${TMPMNT}
		cleanup $STF_FAIL
	fi

	umount ${TMPMNT} > ${STF_TMPDIR}/umnt.$i.$$ 2>&1
	if (( $? != 0 )); then
		echo "ERROR: KID=$i, Unmount failed"
		cat ${STF_TMPDIR}/umnt.$i.$$
		cleanup $STF_FAIL
	fi
	(( i = i+1 ))
done

rm -rf ${TMPMNT}

echo "\t Test PASS: Test run completed successfully"
echo "\t END TIME: `date`\n"
cleanup $STF_PASS
