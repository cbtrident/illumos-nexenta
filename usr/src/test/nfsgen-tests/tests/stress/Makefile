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

#
# Tests not in shell
#
BINDIR = tests/stress
PROGS = stress_pos001 stress_pos002 stress_pos003

include ../../Makefile.src

TSDIR = $(TESTBIN)

STFDESC = stf_description STRESS.assertions stress.vars
SHS = mkassert stress_pos004 stress_pos005

DESC = $(STFDESC:%=$(TESTBIN)/%)
TS = $(SHS:%=$(TSDIR)/%)
$(TS) := FILEMODE = 0555
$(DESC) := FILEMODE = 0444

all install: $(TS) $(DESC)

$(DESC) : $(TESTBIN)
$(TS): $(TSDIR)

$(TSDIR)/%: %.ksh
	$(INS.rename)
