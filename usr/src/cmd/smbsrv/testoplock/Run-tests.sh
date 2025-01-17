#!/bin/sh

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
#

# Helper program to run fksmbd (user-space smbd for debugging)
# using binaries from the proto area.

[ -n "$ROOT" ] || {
  echo "Need a bldenv to set ROOT=..."
  exit 1;
}

# OK, setup env. to run it.

LD_LIBRARY_PATH=$ROOT/usr/lib:$ROOT/lib
export LD_LIBRARY_PATH

TOL=$ROOT/usr/lib/smbsrv/testoplock

TESTS=${@:-case??.txt}

# run the test cases
for t in $TESTS
do
    name=${t%.txt}
    $TOL < $name.txt > $name.tmp
    if diff -u $name.tmp $name.ref >/dev/null 2>&1 ; then
	echo "$name PASS"
	rm $name.tmp
    else
	echo "$name FAIL"
	diff -u $name.tmp $name.ref
    fi
done
	 
