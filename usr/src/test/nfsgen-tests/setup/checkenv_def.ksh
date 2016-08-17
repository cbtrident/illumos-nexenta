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

. ${STF_SUITE}/include/nfs-util.kshlib

# Check if SETUP is set
if  [[ -z $SETUP ]]; then
        echo "SETUP=<$SETUP> variable must be set, exiting."
	echo "SETUP variable must be set, (e.g. one of none,nfsv4)"
        exit 1
fi

if [[ $SETUP == none ]]; then
	# Check MNTDIR
	if [[ -z $MNTDIR ]] || ! [[ -d $MNTDIR ]]; then
		echo "MNTDIR is either unset or invalid, exiting"
		exit 1
	fi
	# Check TUSER01 and TUSER02
	if [[ -z $TUSER01 ]] \
	    || ! getent passwd $TUSER01 >/dev/null 2>&1; then
		echo "TUSER01=<$TUSER01> is either unset or invalid, exiting"
		exit 1
	fi
	if [[ -z $TUSER02 ]] \
	    || ! getent passwd $TUSER02 >/dev/null 2>&1; then
		echo "TUSER02=<$TUSER02> is either unset or invalid, exiting"
		exit 1
	fi
	exit 0
fi

# Check SERVER is reachable
if  [[ -z $SERVER ]]; then
        echo "SERVER variable must be set, exiting."
        exit 1
fi

RUN_CHECK /usr/sbin/ping $SERVER || exit 1

RUN_CHECK /usr/bin/ssh root@$SERVER /bin/true || exit 1

# Check ZONE_PATH setting for TX
ce_is_system_labeled
if [[ $? == 0 ]]; then
	if [[ -z $ZONE_PATH ]]; then
	    echo "ZONE_PATH not set, exiting."
	    echo "You are running the suite over a CIPSO connection, \c"
	    echo "you MUST set ZONE_PATH with /zone/<zone name>"
	    exit 1
	fi
else
	if [[ -n $ZONE_PATH ]]; then
	    echo "ZONE_PATH is set without TX, exiting."
	    exit 1
	fi
fi


if [[ $OPERATION == list ]] \
    && [[ -f $testsuite/bin/$SETUP/checkenv_def ]] ; then
	$0 -w -l -t $TASK -f bin/$SETUP/checkenv_def -T $testsuite \
	    || exit 1
elif [[ $OPERATION == verify ]] \
    && [[ -f $testsuite/bin/$SETUP/checkenv_def ]]; then
	$0 -w -e -v -t $TASK -f bin/$SETUP/checkenv_def -T $testsuite \
	    || exit 1
fi

# do check for krb5 testing
if [[ $IS_KRB5 == 1 ]]; then
	# need valid DNS server
	ce_host_reachable $DNS_SERVER 1> /dev/null; save_results $?

	# need krb5 support
	ce_file_exist /usr/bin/krb5-config >/dev/null ; save_results $?

	# need krb5tools
	ce_tool_exist $KRB5TOOLS_HOME/bin/kdccfg; save_results $?
	ce_tool_exist $KRB5TOOLS_HOME/bin/kdc_clientcfg; save_results $?
	ce_tool_exist $KRB5TOOLS_HOME/bin/krb5nfscfg; save_results $?
	ce_tool_exist $KRB5TOOLS_HOME/bin/princadm; save_results $?
fi

exit 0
