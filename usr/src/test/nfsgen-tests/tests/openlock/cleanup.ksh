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

NAME=$(basename $0)

. ${STF_SUITE}/include/nfsgen.kshlib

# Turn on debug info, if requested
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

# These tests don't support krb5, so nothing to do.
[[ $IS_KRB5 == 1 ]] && cleanup $STF_UNTESTED

# Restore SERVER's delegation, ignore if SETUP=none
if [[ $SETUP != none ]]; then
	# Set it to default "on" if unable to locate the orginal value
	deleg_val=$(grep -i _delegation $STF_TMPDIR/$SERVER.deleg_val | \
		awk -F\= '{print $2}')
	[[ -z $deleg_val ]] && deleg_val="on"

	# and only reset it at server if it's different from current setting
	if [[ ! -f $STF_TMPDIR/deleg_been_set || \
	    `cat $STF_TMPDIR/deleg_been_set` != "$deleg_val" ]]; then
		RSH root $SERVER \
			". $SRV_TMPDIR/srv_env.vars && \
			. $SRV_TMPDIR/nfs-util.kshlib && \
			set_nfs_property NFS_SERVER_DELEGATION $deleg_val" \
				> $STF_TMPDIR/set_deleg.$$ 2>&1
		if (( $? != 0 )); then
			echo "WARNING: failed to reset delegation to \c"
			echo "<$deleg_val> on SERVER=<$SERVER>"
			cat $STF_TMPDIR/set_deleg.$$
			cleanup $STF_WARNING
		fi
		rm -f $STF_TMPDIR/$SERVER.deleg_val \
			$STF_TMPDIR/set_deleg.$$ $STF_TMPDIR/deleg_been_set
	fi
else
	echo "$NAME: <SETUP=none>"
	echo "\tPlease verify SERVER's delegation is reset to valid value."
	cleanup $STF_PASS ""  \
	    "$STF_TMPDIR/srv_env.vars $STF_TMPDIR/deleg_been_set"
fi
