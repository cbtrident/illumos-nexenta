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
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/smf-tests

FILES = README STC.INFO STF.INFO

DOCS = $(FILES:%=$(ROOTOPTPKG)/%)
$(DOCS) := FILEMODE = 0444

all: $(FILES)

install: $(ROOTOPTPKG) $(DOCS)

clean lint clobber:

$(ROOTOPTPKG):
	$(INS.dir)

$(ROOTOPTPKG)/%: %
	$(INS.file)
