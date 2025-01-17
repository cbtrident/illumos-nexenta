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
# A test purpose file to test functionality of the add-hg-member subfunction
# of the stmfadm command.

#
# __stc_assertion_start
# 
# ID: add001
# 
# DESCRIPTION:
# 	Add a host group member to a host group which is existed already
# 
# STRATEGY:
# 
# 	Setup:
# 		Create a host group with specified name
# 		Add a fibre channel initiator port wwn into host group 
# 			by name_type=name_value
# 		Add an iSCSI initiator node name into host group 
# 			by SCSI name string
# 	Test: 
# 		Verify the addition success
# 		Verify the return code               
# 	Cleanup:
# 		Delete the host group
# 
# 	STRATEGY_NOTES:
# 
# KEYWORDS:
# 
# 	add-hg-member
# 
# TESTABILITY: explicit
# 
# AUTHOR: John.Gu@Sun.COM
# 
# REVIEWERS:
# 
# TEST_AUTOMATION_LEVEL: automated
# 
# CODING_STATUS: IN_PROGRESS (2008-02-14)
# 
# __stc_assertion_end
function add001 {
	cti_pass
	tc_id="add001"
	tc_desc="Add a host group member to a host group which is existed already"
	print_test_case $tc_id - $tc_desc

	stmfadm_create POS hg ${HG[0]}

	stmfadm_add POS hg-member -g ${HG[0]} wwn.200000e08b909220
	stmfadm_add POS hg-member -g ${HG[0]} eui.200000e08b909229
	stmfadm_add POS hg-member -g ${HG[0]} iqn.1986-03.com.sun:01.46f7e269
	
	tp_cleanup

}
