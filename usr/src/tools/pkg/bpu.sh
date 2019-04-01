# vim: set filetype=bash
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


BPU=`basename $0`
BEADM=/usr/sbin/beadm
MNTDIR="/tmp/mnt_${BPU}_$$"
PKG_R_MNT="/usr/bin/pkg -R ${MNTDIR}"

cleanup()
{
	$BEADM destroy -fFs ${test_be}
	rmdir ${MNTDIR}
	exit 1
}
verify_root_priv()
{
	if [ "$EUID" -ne 0 ]; then
	    echo "Please run as root"
	    exit
	fi
}

usage()
{
    echo "
        Usage: ${BPU} [-c <use_BE>] <BE_name>  <location> <publisher>

         Apply pkgs to <BE_name> from <location> and <publisher>
         The default action is to clone the active BE to apply the pkgs.
         -c <use_BE> enables one to select a specific BE instead of the active BE. 
            <use_BE> must be an existing BE.
         Example:
              ${BPU} testBE http://hulk:10061 nightlynza
              ${BPU} -c NS-5.3.0.4 testBE http://hulk:10061 nightlynza

        "   
    exit 0
}

################################################################################
#                                                                              #
#                           MAIN                                               #
#                                                                              #
################################################################################


while getopts ":c:" opt; do
    case "${opt}" in 
	c)
	    shift;
	    [ $# -eq  4 ] || usage
	    clone_be=$1
	    [ -z ${clone_be} ] && usage
	    shift
	    ;;
	*)
	    usage
	    ;;
	esac
done

#process the rest of the args here
if [ $# -eq 3 ]; then
    [ -z $1 ] || [ -z $2 ] || [ -z $3 ] && usage
    test_be=$1
    loc=$2
    pub=$3
else 
    usage
fi

verify_root_priv
#Call cleanup on interrupts
trap cleanup INT

if [ ! -z ${clone_be} ]; then
    $BEADM create -e ${clone_be} ${test_be} || exit 1
else 
    ${BEADM} create ${test_be} || exit 1
fi

mkdir ${MNTDIR}
${BEADM} mount ${test_be} ${MNTDIR}
echo "mounting ${test_be} at ${MNTDIR}" 

${PKG_R_MNT} set-publisher --non-sticky nexenta
echo "setting --non-sticky for nexenta publisher"

${PKG_R_MNT} set-publisher --search-first -g ${loc} ${pub}
echo "setting ${loc} ${pub}"

${PKG_R_MNT} change-facet firmware.*.lock=false
echo "disabling pkg firmware locks via change-facet"

echo "updating pkgs for ${test_be}"
${PKG_R_MNT} update 
if [ $? == 0 ]; then
   ${BEADM} unmount ${MNTDIR}
   ${BEADM} activate ${test_be}
  echo "BE ${test_be} has been activated."
else
    echo  "
         pkg update failed. BE ${test_be} has not been activated
         Check the BE mounted at ${MNTDIR}.
        "
fi
