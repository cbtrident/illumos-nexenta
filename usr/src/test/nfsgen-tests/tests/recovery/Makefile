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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
#
include $(SRC)/Makefile.master

TEST = recovery
STFDESC = README recovery.vars stf_description
PROGS = checkenv_def cleanup configure nfs4red \
	S99nfs4red setup srv_setup

include ../Makefile.test

.PARALLEL: $(SUBDIRS)

SUBDIRS = client others

include $(SRC)/test/Makefile.com
