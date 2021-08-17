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
# Copyright 2021 Tintri by DDN, Inc. All rights reserved.
#

MODULE=		fm_mod.so

OBJECTS=	init.o \
		module.o \
		problem.o \
		resource.o

MIBS=		SUN-FM-MIB.txt \
		SUN-IREPORT-MIB.txt

include		../Makefile.com

LDLIBS +=	-lnetsnmp -lnetsnmphelpers -lnetsnmpagent
LDLIBS +=	-luutil -lnvpair
LDLIBS +=	-L$(ROOT)/usr/lib/fm/$(MACH64) -R/usr/lib/fm/$(MACH64)
LDLIBS +=	-lfmd_adm -lfmevent -ltopo

.KEEP_STATE:

all:		$(DYNLIB)

install:	all $(ROOTMODULE) $(ROOTMIBS)

include		$(SRC)/lib/Makefile.targ
