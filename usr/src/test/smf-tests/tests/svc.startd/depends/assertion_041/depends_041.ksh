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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# start __stf_assertion__
#
# ASSERTION: depends_041
# DESCRIPTION:
#  If adding a dependent service to an existing service creates
#  a circular dependency then that service will go into the
#  maintenance state. All the other services will enter the offline
#  state.
#
# end __stf_assertion__
#

. ${STF_TOOLS}/include/stf.kshlib
. ${STF_SUITE}/include/gltest.kshlib
. ${STF_SUITE}/include/svc.startd_config.kshlib
. ${STF_SUITE}/tests/svc.startd/include/svc.startd_common.kshlib

typeset service_setup=0
function cleanup {
	rm -f $svccfg_errfile
	common_cleanup
	rm -f $service_state1 $service_state2 $service_state3
}

trap cleanup 0 1 2 15

readonly ME=$(whence -p ${0})
readonly MYLOC=$(dirname ${ME})

DATA=$MYLOC

readonly registration_template=$DATA/service_041.xml

extract_assertion_info $ME

# make sure that the svc.startd is running
verify_daemon
if [ $? -ne 0 ]; then
	print -- "--DIAG: $assertion: svc.startd is not executing. Cannot "
	print -- "  continue"
	exit $STF_UNRESOLVED
fi

# Make sure the environment is clean - the test service isn't running
print -- "--INFO: Cleanup any old $test_FMRI1, $test_FMRI2 state"
service_cleanup $test_service
if [ $? -ne 0 ]; then
	print -- "--DIAG: $assertion: cleanup of a previous instance failed"
	exit $STF_UNRESOLVED
fi

print -- "--INFO: generating manifest for importation into repository"
manifest_generate $registration_template \
	TEST_SERVICE=$test_service \
	TEST_INSTANCE1=$test_instance1 \
	TEST_INSTANCE2=$test_instance2 \
	TEST_INSTANCE3=$test_instance3 \
	SERVICE_APP=$service_app \
	LOGFILE=$service_log \
	STATEFILE1=$service_state1 \
	STATEFILE2=$service_state2 \
	STATEFILE3=$service_state3 \
	> $registration_file

print -- "--INFO: Importing service into repository"
manifest_purgemd5 $registration_file
svccfg -v import $registration_file >$svccfg_errfile 2>&1

if [ $? -ne 0 ]; then
	print -- "--DIAG: $assertion: Unable to import the services $test_FMRI1"
        print -- "  and $test_FMRI2 error messages from svccfg: "
        print -- "  \"$(cat $svccfg_errfile)\""
	exit $STF_UNRESOLVED
fi
service_setup=1

print -- "--INFO: Waiting for $test_FMRI3 to go to online"
service_wait_state $test_FMRI3 online
if [ $? -ne 0 ]; then
	print -- "--DIAG: $assertion: Service $test_FMRI3 did not go online"
	exit $STF_FAIL
fi

print -- "--INFO: Add dependency from $test_FMRI1 -> $test_FMRI3"
service_dependency_add $test_FMRI1 adepc require_all refresh svc:/$test_FMRI3

print -- "--INFO: Refresh $test_FMRI1"
svcadm refresh $test_FMRI1
if [ $? -ne 0 ]; then
	print -- "--DIAG: $assertion: Service $test_FMRI1 didn't refresh"
	exit $STF_FAIL
fi

print -- "--INFO: Verify service $test_FMRI1 is in maintenance"
service_wait_state $test_FMRI1 maintenance
if [ $? -ne 0 ]; then
	print -- "--DIAG: $assertion: Service $test_FMRI3 is not in maintenance"
	print -- "  it is in '$(svcs -H -o STATE $test_FMRI3)' instead."
	exit $STF_FAIL
fi

print -- "--INFO: Verify that $test_FMRI2 is in offline state"
service_wait_state $test_FMRI2 offline
if [ $? -ne 0 ]; then
	print -- "--DIAG: $assertion: Service $test_FMRI2 is not offline"
	print -- "  it is in '$(svcs -H -o STATE $test_FMRI2)' instead."
	exit $STF_FAIL
fi

print -- "--INFO: Verify that $test_FMRI3 is in offline state"
service_wait_state $test_FMRI3 offline
if [ $? -ne 0 ]; then
	print -- "--DIAG: $assertion: Service $test_FMRI3 is not offline"
	print -- "  it is in '$(svcs -H -o STATE $test_FMRI3)' instead."
	exit $STF_FAIL
fi

print -- "--INFO: Cleaning up service"
cleanup

exit $STF_PASS
