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

#
# A test purpose file to test functionality of the delete-target
# subfunction of the itadm command
#

# __stc_assertion_start
#
# ID: itadm_delete_target_data_001
#
# DESCRIPTION:
#	Create two target <tgt1> and <tgt2>, delete <tgt1> first. then
#	itadm delete-target <tgt1> <tgt2>. Verify that the command fails, and
#	<tgt2> are not deleted.
#
# STRATEGY:
#
#	Setup:
#		1. Create two target <tgt1> <tgt2>
#
#		2. itadm delete-target <tgt1>
#	Test:
#
#		1. itadm delete-target <tgt1> <tgt2>
#
#		2. ensure that the command fails with an appropriate error
#		   message
#
#		3. itadm list target shows that <tgt2> were not impacted.
#
#	Cleanup:
#		Delete the created target
#
#	STRATEGY_NOTES:
#
#
# TESTABILITY: explicit
#
# AUTHOR: bobbie.long@sun.com zheng.he@sun.com
#
# REVIEWERS:
#
# ASSERTION_SOURCE:
#	http://www.opensolaris.org/os/project/iser/itadm_1m_v4.pdf
#
# TEST_AUTOMATION_LEVEL: automated
#
# STATUS: IN_PROGRESS
#
# COMMENTS:
#
# __stc_assertion_end
#
function tp_itadm_delete_target_data_001
{
	cti_pass

	typeset tc_id tc_desc 
        tc_id="tp_itadm_delete_target_data_001"
	tc_desc="Create two target <tgt1> and <tgt2>, delete <tgt1> first. then"
	tc_desc="${tc_desc} itadm delete-target <tgt1> <tgt2>. Verify that the"
	tc_desc="${tc_desc} command fails, and <tgt2> are not deleted."

	print_test_case "${tc_id} - ${tc_desc}"

	itadm_create POS target -n "${IQN_TARGET}.${TARGET[0]}"
	itadm_create POS target -n "${IQN_TARGET}.${TARGET[1]}"

	itadm_delete POS target -f "${IQN_TARGET}.${TARGET[0]}" 

	itadm_delete NEG target -f "${IQN_TARGET}.${TARGET[0]}" \
				"${IQN_TARGET}.${TARGET[1]}"

	tp_cleanup
}

