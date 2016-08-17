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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
#
include $(SRC)/lib/Makefile.lib

.SUFFIXES: .so

ROOTOPTPKG = $(ROOT)/opt/nfsgen-tests
TESTLIB = $(ROOTOPTPKG)/lib

SOBJ = libnfsgen.so
SHRLIB = $(SOBJ:%=$(TESTLIB)/%)
$(SHRLIB) := FILEMODE = 0555

CSRC = libnfsgen.c

NFSGENINC = ../include
CFLAGS = -erroff=%all 	# Ignore all lint msg now
CFLAGS += -I$(NFSGENINC)
LDLIBS += -lnsl -lsocket

.c.so:
	$(LINK.c) -Kpic -G -o $(@) $(<)
	$(POST_PROCESS)

all install: $(SHRLIB)

clobber clean:
	$(RM) $(SOBJ)
	
lint:
	$(LINT.c) $(CFLAGS) $(CSRC)

$(SHRLIB): $(TESTLIB)

$(TESTLIB):
	$(INS.dir)

$(TESTLIB)/%: %
	$(INS.file)
