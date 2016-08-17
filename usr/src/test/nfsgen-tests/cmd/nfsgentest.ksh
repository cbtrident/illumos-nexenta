#!/usr/bin/ksh

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
# Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
#

#
# Test wrapper for NFSgen tests
#
# Necessary environments and configure variables here
#
# Required
#
#	CLIENT2	- the 2nd client for twoclients test
#
#	SETUP	- determine what test you want to run.
#	    	  always set to 'nfsv4' unless user wants
#	    	  to manually setup nfs environment. In this
#	     	  case set to 'none'.
#
#	DNS_DOMAIN, SRV_DNS_DOMAIN, CLT2_DNS_DOMAIN is used
#	to construct full qualified domain name.
#
# Optionals
#
#	SHRDIR	- shared directory on server
#	     	  (default is "/nfsgen_share")
#
#	MNTDIR	- mount directory on client
#	     	  (default is "/nfsgen_mount")
#
#	STRESS_TIMEOUT	- By default, the stress test will 
#	              	  return if execution time exceeds 10800s
#
#	STF_RESULTS	- /var/tmp/nfsgen/results by default
#
#
#

DOMAIN=localdomain
export STF_SUITE=/opt/nfsgen-tests
#export TESTROOT=$STF_SUITE/bin
export STF_TOOLS=/opt/SUNWstc-stf
export SETUP=nfsv4
export DNS_DOMAIN=$DOMAIN
export SRV_DNS_DOMAIN=$DOMAIN
export CLT2_DNS_DOMAIN=$DOMAIN
PATH=$PATH:/opt/SUNWstc-genutils/bin
PATH=$PATH:/opt/SUNWstc-stf/bin/$(isainfo -n)
export PATH

#
# Use of LD_LIBRARY_PATH is not a good practise but STF tools
# depends on libstf.so under /opt/SUNWstc-stf and we have to
#
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/SUNWstc-stf/lib/$(isainfo -n)
export LD_LIBRARY_PATH

ALL='acl delegation file_ops openlock recovery stress'
CLNTRUNFILE=$STF_SUITE/tests/delegation/stf_description
TSRUNFILE=$STF_SUITE/tests/stf_description

#
# 2nd client IP is required for delegation/twoclients tests
#
usage() {
	echo "Usage: $0 [-c ip] ip test"
	echo "Where"
	echo "   -c	specify the 2nd client IP for twoclients test"
	echo "   ip	nfs server IP address"
	echo "   test	specified test, run all if not specified"
	exit 1
}

#
# Must be run by root
#
if [ `id -u` -ne 0 ]; then
	echo Must run by root
	exit 1
fi

#
# Get client 2 if specified
#
while getopts ":c:" opt; do
	case $opt in
	   c )
		CLIENT2=$OPTARG;;
	   \?)
		usage();;	
	esac
done
shift $(($OPTIND - 1))

#
# Server is a must
#
if [ $# -lt 1 ]; then
	usage
fi

SERVER=$1
ping $SERVER 5
if [ $? != 0 ]; then
	echo Invalid nfs server IP
	exit 1
fi
export SERVER

if [ -z "$CLIENT2" ]; then
	CLNTEST="oneclient"
else
	ping $CLIENT2
	if [ $? != 0 ]; then
		echo Invalid client 2 IP 
		exit 1
	fi

	CLNTEST="oneclient twoclients"
fi
eval sed -i "s/^STF_EXECUTE_SUBDIRS=.*/STF_EXECUTE_SUBDIRS='$CLNTEST'/g" $CLNTRUNFILE

TEST=$2
#
# Bail out if an invalid test is specified
# No test specified == run all
#
if [ -z "TEST" ]; then
	TEST="ALL"
elif [ "${ALL#*$TEST}" = "$ALL" ]; then
	echo Invalid test is specified
	exit 1
fi
eval sed -i "s/^STF_EXECUTE_SUBDIRS=.*/STF_EXECUTE_SUBDIRS='$TEST'/g" $TSRUNFILE

#
# Setup the server and client
#
stf_configure

#
# Run the whole test suite with stf_execute
# Run the specified tests via '-r' option
#
stf_execute

#
# Cleanup
#
stf_unconfigure
