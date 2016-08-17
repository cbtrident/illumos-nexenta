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

if [[ $IS_KRB5 == 1 ]]; then
        echo "All tests under this directory don't support krb5 !!"
        cleanup $STF_UNTESTED
fi

# Save SERVER's current delegation info, ignore if SETUP=none
if [[ $SETUP != none ]]; then
	RSH root $SERVER \
		"/usr/sbin/sharectl get -p SERVER_DELEGATION nfs" \
		> $STF_TMPDIR/$SERVER.deleg_val 2>$STF_TMPDIR/$SERVER.deleg_val.err
	if (( $? != 0 )); then
		echo "ERROR: failed to get delegation from SERVER=<$SERVER>"
		cat $STF_TMPDIR/$SERVER.deleg_val
		cleanup $STF_UNINITIATED "" $STF_TMPDIR/$SERVER.deleg_val*
	fi
else
	echo "$NAME: <SETUP=none>"
	echo "\tPlease verify SERVER has valid delegation for your testing"
fi
