#!/usr/bin/ksh -p
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. ${STF_SUITE}/include/libtest.shlib
. ${STF_SUITE}/tests/stress/include/stress.kshlib

# DESCRIPTION:
#	Running multiple copies of dataset_create_write_destroy,
#	dataset_create_write_destroy_attr and dataset_xattr on separate
#	mirrored pools shall not cause the system to fail, hang or panic.
#
# STRATEGY:
#	1. Setup phase will have created several mirrored pools
#	2. Multiple copies of dataset_create_write_destroy are fired off
#	   one per mirror in the background.
#	3. Multiple copies of dataset_create_write_destroy_attr are filed off
#	   one per mirror in the background.
# 	4. Multiple copies of dataset_xattr are filed off one per mirror in the
# 	   background.
#	5. Wait for 10 seconds, then repeat the operation at step 2,3,4.
#	6. Wait for our stress timeout value to finish, and kill any remaining
#          tests. The test is considered to have passed if the machine stays up
#	   during the time the stress tests are running and doesn't hit the stf
#	   time limit.

log_assert "parallel dataset_create_write_destroy," \
	"dataset_create_write_destroy_attr and dataset_run_xattr" \
	"on multiple mirrored pools won't fail"

log_onexit cleanup

typeset pool=
typeset child_pids=

for pool in $(get_pools); do
	log_note "dataset_create_write_destroy $pool"
	dataset_create_write_destroy $pool > /dev/null 2>&1 &
	child_pids="$child_pids $!"

	log_note "dataset_create_write_destroy_exattr $pool"
	dataset_create_write_destroy_exattr $pool > /dev/null 2>&1 &
	child_pids="$child_pids $!"

	log_note "dataset_run_xattr $pool "
	dataset_run_xattr $pool > /dev/null 2>&1 &
	child_pids="$child_pids $!"
done

#
# Monitor stress processes until they exit or timed out
#
stress_timeout $STRESS_TIMEOUT $child_pids

log_pass
