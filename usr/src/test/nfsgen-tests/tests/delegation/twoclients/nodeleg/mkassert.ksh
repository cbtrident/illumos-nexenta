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

tests="clntb_reading01 clntb_writing01 clntb_writing02"

for test in $tests; do
	for CLNT2_TESTDIR in $CLNT2_TESTDIR_LIST; do
		# Skip v2 and v3 mount points
		if echo $CLNT2_TESTDIR | grep "_v2" >/dev/null \
		    || echo $CLNT2_TESTDIR | grep "_v3" >/dev/null ; then
			continue;
		fi

		tag=$test
		echo "adding $tag test"
		stf_addassert -u root -t $tag -c $test "$CLNT2_TESTDIR"
	done
done
