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

NAME=$(basename $0)
CDIR=$(dirname $0)

# Turn on debug info, if requested
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

[[ $IS_KRB5 == 1 ]] && KOPT="-k $KPASSWORD" || KOPT=""

echo "adding stress_pos001"
if [[ -z $ZONE_PATH ]]; then
	stf_addassert -u root -t stress_pos001 -c chg_usr_exec \
		"$KOPT $TUSER01 stress_pos001 -T \$ST01_RUNS -Q \$ST01_NAP \
		-I \$ST01_ITER -f ${MNTDIR}/$$.stress_pos001 -d \$STRESS_DEBUG"
else
	stf_addassert -u root -t stress_pos001 -c stress_pos001 \
		"-T \$ST01_RUNS -Q \$ST01_NAP -I \$ST01_ITER \
		-f ${MNTDIR}/$$.stress_pos001 -d \$STRESS_DEBUG"
fi

echo "adding stress_pos002"
if [[ -z $ZONE_PATH ]]; then
	stf_addassert -u root -t stress_pos002 -c chg_usr_exec \
		"$KOPT $TUSER01 stress_pos002 -b ${MNTDIR} -n \${ST02_FNUM} \
		-W \${ST02_NAP} -d \$STRESS_DEBUG"
else
	stf_addassert -u root -t stress_pos002 -c stress_pos002 \
		"-b ${MNTDIR} -n \${ST02_FNUM} -W \${ST02_NAP} -d \$STRESS_DEBUG"
fi

echo "adding stress_pos003{a}"
stf_addassert -u root -t stress_pos003{a} -c stress_pos003 \
	"-S 1 -b ${MNTDIR} -n 128 -W 1 -d \$STRESS_DEBUG"

echo "adding stress_pos003{b}"
stf_addassert -u root -t stress_pos003{b} -c stress_pos003 \
	"-S 2 -b ${MNTDIR} -n 512 -d \$STRESS_DEBUG"

echo "adding stress_pos003{c}"
stf_addassert -u root -t stress_pos003{c} -c stress_pos003 \
	"-S 4 -b ${MNTDIR} -n 512 -d \$STRESS_DEBUG"

#  Solaris doesn't support the negative seek with fcntl(2) for NFS;
#  so this assertion is now commented out.
#echo "adding stress_pos003{d}"
#stf_addassert -u root -t stress_pos003{d} -c stress_pos003 \
#	"-S 3 -b ${MNTDIR} -n 512 -d \$STRESS_DEBUG"

exit 0
