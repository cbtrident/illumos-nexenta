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

# This script loops endlessly

DIR=$(dirname $0)

skip_deleg=0
if [[ $1 == "-n" ]]; then
	skip_deleg=1
	shift
else
	if [[ ! -x $DIR/get_deleg_type ]]; then
		echo "Failed to find $DIR/get_deleg_type"
		return 9
	fi	
fi

delay=1
if (( $# >= 1 )); then
	delay=$1
fi

if (( skip_deleg == 0 )); then
	i=$($DIR/get_deleg_type $0)
	echo "delegation type granted: <$i>"
fi

echo "$0 PID is = $$"

j=0
while (( j < delay ))
do
        sleep 1
	let j=j+1
done

return $i
