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

ROOTOPTPKG = $(ROOT)/opt/nfsgen-tests
NFSV4DIR = $(ROOTOPTPKG)/bin/nfsv4
NFSV4SH = $(NFSV4DIR)

DESC = stf_description
PROGS = configure srv_setup unconfigure

STFDESC = $(DESC:%=$(NFSV4DIR)/%)
SHS = $(PROGS:%=$(NFSV4SH)/%)
$(STFDESC) := FILEMODE = 0444
$(SHS) := FILEMODE = 0555

all lint clean clobber:

install: $(STFDESC) $(SHS)

$(STFDESC) : $(NFSV4DIR)
$(SHS): $(NFSV4SH)

$(NFSV4DIR):
	$(INS.dir)

$(NFSV4SH)/% : %.ksh
	$(INS.rename)

$(NFSV4DIR)/% : %
	$(INS.file)
