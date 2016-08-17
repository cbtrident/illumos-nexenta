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

DIR=$(dirname $0)
NAME=$(basename $0)

. ${STF_SUITE}/include/nfsgen.kshlib

# Turn on debug info, if requested
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

if [[ $SETUP == "none" ]]; then
	echo "$NAME: SETUP=<$SETUP>, user manual setup"
	echo "\tonly cleanup TMPDIR, user should do other manual cleanup"
	rm -rf $STF_TMPDIR
	exit $STF_PASS
fi

#
# Setup-specific cleanup
#

RUN_CHECK ${STF_SUITE}/bin/$SETUP/unconfigure

#
# General client side cleanup
#    - removing test user
#    - restoring mapid domain
#

# Restore mapid domain on client
restore_nfs_property NFSMAPID_DOMAIN $STF_TMPDIR/mapid_backup

# Delete test user and group on client
RUN_CHECK userdel $TUSER01
RUN_CHECK userdel $TUSER02
RUN_CHECK groupdel $TGROUP

#
# General server side cleanup
#    - removing test user
#    - restoring mapid domain
#

# Run server setup script to do cleanup, pass down env varialbes it needs
RUN_CHECK RSH root $SERVER "$SRV_TMPDIR/srv_setup -c"

# Cleanup the kerberos if needed
[[ $IS_KRB5 == 1 ]] && RUN_CHECK krb5_config -c
 
# Remove temp dir on server
RUN_CHECK RSH root $SERVER "rm -rf $SRV_TMPDIR"

if [[ -n $CLIENT2 && $CLIENT2 != $SERVER && $CLIENT2 != $CLIENT ]]; then
	RUN_CHECK RSH root $CLIENT2 "$SRV_TMPDIR/srv_setup -c"
	RUN_CHECK RSH root $CLIENT2 "rm -rf $SRV_TMPDIR"
fi

rm -rf $STF_TMPDIR

exit $STF_PASS
