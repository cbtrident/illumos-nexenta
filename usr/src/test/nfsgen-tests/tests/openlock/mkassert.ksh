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

if [[ $IS_KRB5 == 1 ]]; then
	echo "Open and lock test don't support krb5"
	exit $STF_PASS
fi

[[ $SETUP == none ]] && deleg_conf=none \
	|| deleg_conf="on off"

typeset -i i
RUNTEST=${STF_SUITE}/tests/openlock/runtests
for deleg in $deleg_conf; do
    for tprog in opentest locktest; do
	for scen in A B C D E; do
	    i=1
	    mode_index=0
            # open tests
            if [[ $tprog == "opentest" ]]; then 
		while (( $mode_index < 7)); do
			[[ $scen == A && $mode_index > 3 ]] && break;
			[[ $scen == B && $mode_index > 3 ]] && break;
			# for scenarioD, we only set mode to 0600
			[[ $scen == D && $mode_index != 0 ]] && break;
			oflag_index=0
			while (( $oflag_index < 4)); do
			    [[ $scen == D && $oflag_index > 2 ]] && break;

			    [[ $deleg == "none" ]] \
			    	&& prefix=open_scen${scen}_pos \
				|| prefix=open_Deleg${deleg}_scen${scen}_pos
			    tname=$(get_casename $prefix $i)
			    echo "adding $tname: scenario${scen}, \c"
			    echo "DELEG=$deleg, MODE_INDEX=$mode_index, \c"
			    echo "OFLAG_INDEX=$oflag_index"
			    stf_addassert -u root -t $tname -c $RUNTEST \
			        "$tprog $tname $deleg $scen $mode_index $oflag_index"
			    i=`expr $i + 1`
			    oflag_index=`expr $oflag_index + 1`

			    # We only have one case for E
			    # set mode to 0755 and flag to O_TRUNC
			    [[ $scen == E ]] && break 2;
			done
			mode_index=`expr $mode_index + 1`
		done
             # lock tests
             else
                 [[ $scen == "D" || $scen == "E" ]] && break
                 while (( $mode_index < 3)); do
			for oflag_index in 0 1 2 3; do
			    # mode(0400) is only allowed to combine with flag(O_RDONLY)
			    [[ $mode_index == 1 && $oflag_index != 3 ]] && continue

			    # mode(0200) is only allowed to combine with flag(O_WRONLY)
			    [[ $mode_index == 2 && $oflag_index != 2 ]] && continue

			    [[ $deleg == "none" ]] \
			    	&& prefix=lock_scen${scen}_pos \
				|| prefix=lock_Deleg${deleg}_scen${scen}_pos
			    tname=$(get_casename $prefix $i)
			    echo "adding $tname: scenario${scen}, \c"
			    echo "DELEG=$deleg, MODE_INDEX=$mode_index, \c"
			    echo "OFLAG_INDEX=$oflag_index"
			    stf_addassert -u root -t $tname -c $RUNTEST \
			        "$tprog $tname $deleg $scen $mode_index $oflag_index"
			    i=`expr $i + 1`

			    # We only have one case for C, set mode to 0600
			    # flag to O_CREAT|O_TRUNC|O_RDWR
			    [[ $scen == C ]] && break 2;
			done
			mode_index=`expr $mode_index + 1`
		 done
             fi
	done
    done
done

exit 0
