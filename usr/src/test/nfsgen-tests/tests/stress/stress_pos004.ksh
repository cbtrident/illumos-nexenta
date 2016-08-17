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

[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
        || :${NFSGEN_DEBUG}: = *:all:* ]] && set -x


if [[ $SHRDIR == "/" ]]; then
	echo "As SHRDIR is set '/', the case can't run 'find' in MNTDIR"
	exit $STF_UNTESTED
fi

# ----------------------------------------------------------------------
echo "\n $NAME: multiple <find>s in ${SERVER}:$SHRDIR mounting <${MNTDIR}>"
echo "\t START TIME: `date`\n"

#
# Default of 5 child processes if ST04_KIDS is not set
#
ST04_KIDS=${ST04_KIDS:-5}
echo "\t ==> Going to start ${ST04_KIDS} processes"
typeset i=0
while (( $i < ${ST04_KIDS} )); do
	(
    		[[ :$NFSGEN_DEBUG: = *:${NAME}:* \
            		|| :${NFSGEN_DEBUG}: = *:all:* ]] && set -x

		cd ${MNTDIR} > $STF_TMPDIR/cd.$i.$$
		if (( $? != 0 )); then
			cat $STF_TMPDIR/cd.$i.$$
			echo "KID=$i: chdir into ${MNT} failed."
			cleanup $STF_UNINITIATED
		fi
    
		find . -ls > $STF_TMPDIR/find.$i.$$ 2>&1
		if (( $? != 0 )); then
			echo " KID=$i, find failed"
			cat $STF_TMPDIR/find.$i.$$
			cleanup $STF_FAIL
		fi
	)&
	(( i = i+1 ))
done

# Now wait for all processes to complete
wait

echo "\t Test PASS: Test run completed successfully"
echo "\t END TIME: `date`\n"
cleanup $STF_PASS
