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

. $STF_SUITE/tests/acl/acl_common.kshlib

#################################################################################
#
# __stc_assertion_start
#
# ID: acl_chmod_rwx_pos002
#
# DESCRIPTION:
#	chmod A{+|-|=} read_data|write_data|execute for owner@ group@ or everyone@
#	correctly alters mode bits .
#
# STRATEGY:
#	1. Loop root and non-root user.
#	2. Get the random initial map.
#	3. Get the random ACL string.
#	4. Separately chmod +|-|= read_data|write_data|execute
#	5. Check map bits 
#
# TESTABILITY: explicit
#
# TEST_AUTOMATION_LEVEL: automated
#
# __stc_assertion_end
#
################################################################################

[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
	&& set -x

echo "ASSERTION: chmod A{+|-|=} read_data|write_data|execute for owner@, group@ " \
	"or everyone@ correctly alters mode bits."

set -A bits 0 1 2 3 4 5 6 7
set -A a_flag owner group everyone
set -A a_access read_data write_data execute
set -A a_type allow deny

#
# Get a random item from an array.
#
# $1 the base set
#
function random_select #array_name
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset arr_name=$1
	typeset -i ind

	eval typeset -i cnt=\${#${arr_name}[@]}
	(( ind = $RANDOM % cnt ))

	eval print \${${arr_name}[$ind]}
}

#
# Create a random string according to array name, the item number and 
# separated tag.
#
# $1 array name where the function get the elements
# $2 the items number which you want to form the random string
# $3 the separated tag
#
function form_random_str #<array_name> <count> <sep>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset arr_name=$1
	typeset -i count=${2:-1}
	typeset sep=${3:-""}

	typeset str=""
	while (( count > 0 )); do
		str="${str}$(random_select $arr_name)${sep}"

		(( count -= 1 ))
	done

	print $str
}

#
# Get the sub string from specified source string
#
# $1 source string
# $2 start position. Count from 1
# $3 offset
#
function get_substr #src_str pos offset
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset pos offset

	$ECHO $1 | \
		$NAWK -v pos=$2 -v offset=$3 '{print substr($0, pos, offset)}'
}

#
# According to the original bits, the input ACE access and ACE type, return the
# expect bits after 'chmod A0{+|=}'.
#
# $1 bits which was make up of three bit 'rwx'
# $2 ACE access which is read_data, write_data or execute
# $3 ACE type which is allow or deny
#
function cal_bits #bits acl_access acl_type
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset bits=$1
	typeset acl_access=$2
	typeset acl_type=$3
	set -A bit r w x

	typeset tmpbits=""
	typeset -i i=0 j
	while (( i < 3 )); do
		if [[ $acl_access == *"${a_access[i]}"* ]]; then
			if [[ $acl_type == "allow" ]]; then
				tmpbits="$tmpbits${bit[i]}"
			elif [[ $acl_type == "deny" ]]; then
				tmpbits="${tmpbits}-"
			fi
		else
			(( j = i + 1 ))
			tmpbits="$tmpbits$(get_substr $bits $j 1)"
		fi

		(( i += 1 ))
	done

	echo "$tmpbits"
}

#
# Based on the initial node map before chmod and the ace-spec, check if chmod
# has the correct behaven to map bits.
#
function check_test_result #init_mode node acl_flag acl_access a_type
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset init_mode=$1
	typeset node=$2
	typeset acl_flag=$3
	typeset acl_access=$4
	typeset acl_type=$5

	typeset -L3 u_bits=$init_mode
	typeset g_bits=$(get_substr $init_mode 4 3)
	typeset -R3 o_bits=$init_mode

	if [[ $acl_flag == "owner" || $acl_flag == "everyone" ]]; then
		u_bits=$(cal_bits $u_bits $acl_access $acl_type)
	fi
	if [[ $acl_flag == "group" || $acl_flag == "everyone" ]]; then
		g_bits=$(cal_bits $g_bits $acl_access $acl_type)
	fi
	if [[ $acl_flag == "everyone" ]]; then
		o_bits=$(cal_bits $o_bits $acl_access $acl_type)
	fi

	typeset cur_mode=$(get_mode $node)
	cur_mode=$(get_substr $cur_mode 2 9)

	if [[ $cur_mode != $u_bits$g_bits$o_bits ]]; then
		echo "FAIL: Current map($cur_mode) != " \
			"expected map($u_bits$g_bits$o_bits)"
		cleanup $STF_FAIL
	fi
}

function test_chmod_map #<node>
{
	[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
		&& set -x

	typeset node=$1	
	typeset init_mask acl_flag acl_access acl_type
	typeset -i cnt

	if (( ${#node} == 0 )); then
		echo "FAIL: file name or directroy name is not defined."
		cleanup $STF_FAIL
	fi

	# Get the initial map
	eval "init_mask=$(form_random_str bits 3)"
	# Get ACL flag, access & type
	eval "acl_flag=$(form_random_str a_flag)"
	(( cnt = ($RANDOM % ${#a_access[@]}) + 1 ))
	eval "acl_access=$(form_random_str a_access $cnt '/')"
	acl_access=${acl_access%/}
	eval "acl_type=$(form_random_str a_type)"

	typeset acl_spec=${acl_flag}@:${acl_access}:${acl_type}

	# Set the initial map and back the initial ACEs
	typeset orig_ace=$STF_TMPDIR/orig_ace.$$
	typeset cur_ace=$STF_TMPDIR/cur_ace.$$

	for operator in "A0+" "A0="; do
		RUN_CHECK usr_exec $CHMOD $init_mask $node || cleanup $STF_FAIL
		eval "init_mode=$(get_mode $node)"
		eval "init_mode=$(get_substr $init_mode 2 9)"
		RUN_CHECK usr_exec eval "$LS -vd $node > $orig_ace" || cleanup $STF_FAIL

		# To "A=", firstly add one ACE which can't modify map
		if [[ $operator == "A0=" ]]; then
			RUN_CHECK $CHMOD A0+user:$ACL_OTHER1:execute:deny \
				$node || cleanup $STF_FAIL
		fi
		RUN_CHECK usr_exec $CHMOD $operator$acl_spec $node \
			|| cleanup $STF_FAIL
		check_test_result \
			$init_mode $node $acl_flag $acl_access $acl_type

		# Check "chmod A-"
		RUN_CHECK usr_exec $CHMOD A0- $node || cleanup $STF_FAIL
		RUN_CHECK usr_exec eval "$LS -vd $node > $cur_ace" || cleanup $STF_FAIL
	
		# original ACEs should be equal to current ACEs 
		if ! $DIFF $orig_ace $cur_ace; then
			echo "FAIL: 'chmod A-' failed."
			cleanup $STF_FAIL
		fi
	done

	if [[ -f $orig_ace ]]; then
		RUN_CHECK usr_exec $RM -f $orig_ace || cleanup $STF_FAIL
	fi
	if [[ -f $cur_ace ]]; then
		RUN_CHECK usr_exec $RM -f $cur_ace || cleanup $STF_FAIL
	fi
}

for user in root $ACL_STAFF1; do
	set_cur_usr $user
	
	typeset -i loop_cnt=20
	while (( loop_cnt > 0 )); do
		RUN_CHECK usr_exec $TOUCH $testfile || cleanup $STF_FAIL
		test_chmod_map $testfile
		RUN_CHECK $RM -f $testfile || cleanup $STF_FAIL

		RUN_CHECK usr_exec $MKDIR $testdir || cleanup $STF_FAIL
		test_chmod_map $testdir
		RUN_CHECK $RM -rf $testdir || cleanup $STF_FAIL

		(( loop_cnt -= 1 ))
	done
done

# chmod A{+|-|=} read_data|write_data|execute for owner@, group@ or everyone@
# correctly alters mode bits passed.
cleanup $STF_PASS
