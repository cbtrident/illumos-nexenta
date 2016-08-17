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

[[ $SETUP == nfsv4 && ${TestZFS} != 1 ]] && exit $STF_PASS

# Remove the user principals if it's krb5 testing
if [[ $IS_KRB5 == 1 && ! -f $KRB5_NO_CLEANUP_FILE ]]; then
	for user in $ACL_ADMIN $ACL_STAFF1 $ACL_STAFF2; do
		RUN_CHECK ${KRB5TOOLS_HOME}/bin/princadm -c -p $user
	done
fi

# delete test users
for user in $ACL_ADMIN $ACL_STAFF1 $ACL_STAFF2; do
	RUN_CHECK del_user $user $SERVER
done

# delete test groups
RUN_CHECK del_group $ACL_STAFF_GROUP $SERVER

exit $STF_PASS

