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
# Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
#

MODULE =	Ericsson-SRU-0101
SRCS=		ericsson.c
SRCDIR =	../common
PLUGINTYPE =	vendor
ALIASES =	Ericsson-KDU-137-976-1	

include ../../Makefile.lib
