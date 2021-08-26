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

MODULE=		fmnotify_mod.so

OBJECTS=	fmnotify.o

include		../Makefile.com

CSTD=		$(CSTD_GNU99)

CPPFLAGS +=	-I$(SRC)/cmd/snmp/modules/fm
CPPFLAGS +=	-I$(SRC)/lib/fm/libfmnotify/common

LDLIBS +=	-lnetsnmp -lnetsnmpagent -lnvpair
LDLIBS +=	-L$(ROOT)/usr/lib/fm/$(MACH64) -R/usr/lib/fm/$(MACH64)
LDLIBS +=	-lfmevent -lfmnotify -lfmd_msg

.KEEP_STATE:

all:		$(DYNLIB)

install:	all $(ROOTMODULE)

include		$(SRC)/lib/Makefile.targ
