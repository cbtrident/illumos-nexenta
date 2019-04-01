#!/usr/bin/bash
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
# Copyright 2019 Nexenta Systems, Inc.  All rights reserved.
#

#
# Script to create, delete, list  a pkg service
#

PKGSVC=`basename $0`
SVCCFG=/usr/sbin/svccfg
SVCADM=/usr/sbin/svcadm
SVCS=/usr/bin/svcs
SVCPROP=/usr/bin/svcprop

function cleanup()
{
    if [ ${cmd} = "create"]; then
	echo "Interrupted while creating service ${PKG_SVC_INST}."
	$SVCADM disable ${PKG_SVC_INST}
	echo "Disabled ${PKG_SVC_INST}"
	sleep 1
	$SVCCFG delete ${PKG_SVC_INST}
	echo "Deleted ${PKG_SVC_INST}"
        exit 1
    fi
}

verify_svc()
{
    local inst=$1

    $SVCS -H ${inst} &>/dev/null
    if [ $? != 0 ]; then
	echo "${PKGSVC}: '${inst}' does not match any instances"
	exit 1
    fi
}

verify_root_priv()
{
	if [ "$EUID" -ne 0 ]; then
	    echo "${PKGSVC} Please run as root"
	    exit 1
	fi
}

get_svc_details()
{
    local inst=$1
    local msg=$2
    local port=`$SVCPROP -p pkg/port ${inst}`
    local path=`$SVCPROP -p pkg/inst_root ${inst}`
    local pub=`grep prefix ${path}/cfg_cache | awk '{print $3}'`
    local svcstatus=`$SVCS -H ${inst} `
    local node=`uname -n`
    local ip=`grep ${node} /etc/hosts | awk '{print $1}'`

    echo "
    publisher: ${pub}
    port: ${port}
    location: ${path}
    svc: ${svcstatus}"
    if [ -z ${msg} ] || [ ${msg} != "no_msg" ]; then
	echo "    If svc is online pkgs are at:
    http://`uname -n`:${port} ${pub}
     or
   http://${ip}:${port} ${pub}"
	fi
}
usage() 
{
    echo "
    Usage:
    ${PKGSVC} create <instname> <port_no> <pkg loc> - create a new service instance. Invoke with sudo
    ${PKGSVC} list - lists all pkg services
    ${PKGSVC} info <instname> - details about a specific instance
    ${PKGSVC} restart <instname> - restarts pkg/server:<instname>. Required to republish new bits. Invoke with sudo
    ${PKGSVC} delete <instname> - deletes the instance. Invoke with sudo

    Examples:
    sudo ${PKGSVC} create fred 19505 /tank/nadkarni/NEX-19776-zil-flush/nza-kernel/packages/i386/nightly
    sudo ${PKGSVC} delete fred
  "
    exit 1
}


################################################################################
#                                                                              #
#                           MAIN                                               #
#                                                                              #
################################################################################

#Call cleanup on interrupts
trap cleanup INT

cmd=$1

err=0
case ${cmd} in 
    "create")
	[ $# -eq 4 ] ||  usage
	inst=$2; shift
        #check if svc exists. If true exit. After that assume all works
	if [ ! -z ${inst} ]; then
	    verify_svc pkg/server:${inst}
	    if [ $? == 0 ]; then
	    	echo "${PKGSVC} 'pkg/server:${inst}' instance exists. "
	    	exit 1;
	    fi
	fi
	port=$2; shift
	if [ -z ${port} ] || ! [[ ${port} =~ ^[0-9]+$ ]] || [ ${port} -lt 10000 ]; then
	    echo "\nPort number must be an int and greater than 10000"
	    err=1
	fi
	#add repo.redist
	loc=$2; shift
	fullloc=${loc}/repo.redist
	if [ -z ${loc} ] || [ ! -d  ${loc} ] ||  [ ! -d ${fullloc} ]; then
	    echo "\nDirectory ${loc} does not exit or is not a valid pkg repo path"
	    err=1
	fi
	[ -z ${inst} ] || [ -z ${port} ] || [ -z ${loc} ] || [ ${err} -eq 1 ] && usage
	;;
    "info")
	inst=$2; shift
	;;
    "list")
	;;
    "restart")
	inst=$2; shift
	[ -z ${inst} ] && usage
	;;
    "delete")
	inst=$2; shift
	[ -z ${inst} ] && usage
	;;
    *) usage;;

esac

junk=$2
[ ! -z ${junk} ] && usage

pkg_svc_inst=pkg/server:${inst}

if [ ${cmd} = "create" ]; then
    verify_svc ${inst} 
    if [ $? == 0 ]; then
	echo "$PKGSVC: '${inst}' already exists"
	exit
    fi
    verify_root_priv

    $SVCCFG -s pkg/server add ${inst} || exit 1
    $SVCCFG -s ${pkg_svc_inst} addpg pkg application || exit 1
    $SVCCFG -s ${pkg_svc_inst} addpropvalue pkg/port count: ${port} || exit 1
    $SVCCFG -s ${pkg_svc_inst} addpropvalue pkg/inst_root astring: ${fullloc} || exit 1
    $SVCCFG -s ${pkg_svc_inst} addpropvalue pkg/readonly boolean: true || exit 1
    $SVCADM enable ${pkg_svc_inst} || exit 1
    sleep 1
    $SVCS -H ${pkg_svc_inst} || exit 1
    path=`$SVCPROP -p pkg/inst_root ${pkg_svc_inst}`
    pub=`grep prefix ${path}/cfg_cache | awk '{print $3}'`
    node=`uname -n`
    ip=`grep ${node} /etc/hosts | awk '{print $1}'`
    echo "${PKGSVC} Pkgs at:
    http://${node}:${port} ${pub}
    http://${ip}:${port} ${pub}
"
fi

if [ ${cmd} = "restart" ]; then
    verify_svc ${pkg_svc_inst}
    $SVCADM restart ${pkg_svc_inst} || exit 1
    exit 0
fi

if [ ${cmd} = "info" ]; then 
     [ -z ${pkg_svc_inst} ] && usage
     verify_svc ${pkg_svc_inst}
     get_svc_details ${pkg_svc_inst}
    exit 0
fi
   
[ ${cmd} = "list" ] &&  $SVCS -H pkg/server && exit 0

if [ ${cmd} = "delete" ]; then
        verify_svc ${pkg_svc_inst}
        verify_root_priv
	[ $? != 0 ] && exit 1
	get_svc_details $inst "no_msg"
	while read -p "Continue (y/n)?" choice; do
	    case "$choice" in 
		y|Y )
		    $SVCADM disable ${pkg_svc_inst} || exit 1
		    echo "${PKGSVC} Disabled ${pkg_svc_inst}"
		    sleep 1
		    $SVCCFG delete ${pkg_svc_inst} || exit 1
		    echo "${PKGSVC} Deleted ${pkg_svc_inst}"
		    exit 0
		    ;;
		n|N ) exit 0
		    ;;
		* ) echo "${PKGSVC} Invalid choice";;
	    esac
	done
fi

