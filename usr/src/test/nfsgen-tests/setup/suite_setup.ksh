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

# This suite_setup file do nothing related to setup; it only print out
# test environment information to journal file.

. $STF_TOOLS/include/stf.kshlib
. ${STF_SUITE}/include/nfs-util.kshlib

echo "\nCurrent test has set the following environment info:"
echo "\tlocal host:\t`hostname` \
	\n\tSERVER:\t\t$SERVER \
	\n\tSETUP:\t\t$SETUP \
	\n\tMNTDIR:\t\t$MNTDIR \
	\n\tMNTOPT:\t\t$MNTOPT \
	\n\tNFSGEN_DEBUG:\t$NFSGEN_DEBUG" 

if [[ $SETUP != none ]]; then
	echo	"\tSHRDIR:\t\t$SHRDIR \
		\n\tSHROPT:\t\t$SHROPT"
fi

if [[ $SETUP == nfsv4 ]]; then
	echo "\tFS_TYPE:\t$FS_TYPE"
	[[ $TestZFS == 1 ]] &&  echo "\tZFSPOOL:\t$ZFSPOOL"
fi

# print test system information
echo ""
print_system_info

if [[ $SETUP != none ]]; then
	[[ $SETUP == nfsv4 ]] && servers="$SERVER $CLIENT2"
	for srv in $servers; do
		echo ""
		print_system_info $srv
	done
fi

echo ""

echo "The current MNTPTR info"
[[ $SETUP == none ]] && MNT=$realMNT || MNT=$MNTDIR
nfsstat -m $MNT

exit 0
