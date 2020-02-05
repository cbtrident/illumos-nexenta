#! /usr/bin/ksh
#
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
# Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#
# zpool create can set 'align' property
#
# STRATEGY:
# 1. Create a pool
# 2. Verify that we can set 'align' only to allowed values on that pool
#

function cleanup
{
	poolexists testpool && destroy_pool testpool
	rm -f $filevdev
}

typeset good=("0" "512" "1024" "1K" "4096" "4k" "1M" "1m")
typeset bad=("256" "3K" "1" "2M" "1N" "1G")

log_onexit cleanup

log_assert "zpool create can set 'align' property"

filevdev=/var/tmp/filevdev.txt
log_must mkfile 256M $filevdev

for align in ${good[@]}
do
	log_must zpool create -o align=$align testpool $filevdev
	typeset value=$(get_pool_prop align testpool)

	if [[ "$(to_bytes $align)" != "$(to_bytes $value)" ]]; then
		log_fail "'zpool create' did not set align value to $align "\
		    "(current = $value)"
	fi
	log_must destroy_pool testpool
done

for align in ${bad[@]}
do
	log_mustnot zpool create -o align=$align testpool $filevdev
done

log_pass "zpool create can set 'align' property"
