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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2017 Nexenta Systems, Inc.
#

CMN_SRCS = common/sw_main_cmn.c

SMF_CMN_SRCS = subsidiary/smf/smf_util.c
SMF_DE_SRCS = subsidiary/smf/smf_diag.c $(SMF_CMN_SRCS)
SMF_RP_SRCS = subsidiary/smf/smf_response.c $(SMF_CMN_SRCS)

PANIC_DE_SRCS = subsidiary/panic/panic_diag.c 

CORE_DE_SRCS = subsidiary/core/core_diag.c
