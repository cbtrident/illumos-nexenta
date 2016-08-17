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

tests="clntb_read clntb_write01 clntb_write02 \
       clntb_chmod01 clntb_chmod02 clntb_remove01 clntb_remove02 \
       clntb_rename01 clntb_rename02 clntb_acl01 clntb_acl02 \
       exec_clntb_write exec_clntb_run"

for test in $tests; do
	for CLNT2_TESTDIR in $CLNT2_TESTDIR_LIST; do
		tag=$test
		if [[ $CLIENT2 != $SERVER ]]; then
			vers=$( echo $CLNT2_TESTDIR | cut -d_ -f3)
		fi
		[[ -n $vers ]] && tag=${test}_${vers}

		echo "adding $tag test"
		stf_addassert -u root -t $tag -c $test "$CLNT2_TESTDIR"
	done
done
