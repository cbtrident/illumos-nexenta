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

. ${STF_SUITE}/include/nfsgen.kshlib

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x

if [[ $SETUP == none ]]; then
	echo "SETUP=<$SETUP>"
	echo "    We assume the following users and groups are available in"
	echo "    both client and server that are under testing :"
	echo "\tgroups: ACL_STAFF_GROUP=<$ACL_STAFF_GROUP> \c"
	echo "ACL_OTHER_GROUP=<$ACL_OTHER_GROUP>"
	echo "\tusers:  ACL_ADMIN=<$ACL_ADMIN> ACL_STAFF1=<$ACL_STAFF1>"
	echo "\t        ACL_STAFF2=<$ACL_STAFF2> ACL_OTHER1=<$ACL_OTHER1> \c"
	echo "ACL_OTHER2=<$ACL_OTHER2>"
	echo "    And the test filesystem on server side is ZFS, \c"
	echo "otherwise ACL tests will FAIL"
	exit $STF_PASS
fi

if [[ ${TestZFS} != 1 ]]; then
	echo "\tThe test filesystem on server is not ZFS, FS_TYPE=<$FS_TYPE>;"
	echo "\tACL tests won't run"
	exit $STF_PASS
fi

# Add root group user
add_user -g root $ACL_ADMIN $SERVER > $STF_TMPDIR/usradd.$$ \
	|| exit $STF_UNINITIATED $STF_TMPDIR/usradd.$$

# Create "staff" group.
add_group $ACL_STAFF_GROUP $SERVER > $STF_TMPDIR/grpadd.$$ 2>&1 \
	|| exit $STF_UNINITIATED $STF_TMPDIR/grpadd.$$

# add two user for $ACL_STAFF_GROUP group
for user in $ACL_STAFF1 $ACL_STAFF2; do
	add_user -g $ACL_STAFF_GROUP $user $SERVER > $STF_TMPDIR/usradd.$$ 2>&1 \
		|| exit $STF_FAIL $STF_TMPDIR/usradd.$$
done

# Create the user principals if it's krb5 testing
if [[ $IS_KRB5 == 1 ]]; then
	if [[ -f $KRB5_NO_CLEANUP_FILE ]]; then
		echo "\t The test uses existing Kerberos setup."
		echo "\t Please make sure you have created all principals\c"
		echo "($ACL_ADMIN,$ACL_STAFF1,$ACL_STAFF2,$ACL_OTHER1,$ACL_OTHER2) !!"
	else
		for user in $ACL_ADMIN $ACL_STAFF1 $ACL_STAFF2; do
			${KRB5TOOLS_HOME}/bin/princadm -c -p $user >/dev/null 2>&1
			RUN_CHECK ${KRB5TOOLS_HOME}/bin/princadm -s \
			    -p $user,password=$KPASSWORD || exit $STF_FAIL
		done
	fi
fi

exit $STF_PASS
