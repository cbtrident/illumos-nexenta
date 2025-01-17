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
# Copyright 2020 Tintri by DDN, Inc. All rights reserved.
# Copyright 2017 RackTop Systems.
#

LIBRARY =	libfakekernel.a
VERS =		.1

COBJS = \
	audit.o \
	callout.o \
	clock.o \
	cond.o \
	copy.o \
	cred.o \
	cyclic.o \
	kiconv.o \
	kmem.o \
	kmisc.o \
	ksocket.o \
	kstat.o \
	mutex.o \
	printf.o \
	random.o \
	rwlock.o \
	sema.o \
	sid.o \
	strext.o \
	taskq.o \
	thread.o \
	uio.o

OBJECTS=	$(COBJS)

include ../../Makefile.lib

# libfakekernel must be installed in the root filesystem for libzpool
include ../../Makefile.rootfs

SRCDIR=		../common

LIBS =		$(DYNLIB) $(LINTLIB)
SRCS=   $(COBJS:%.o=$(SRCDIR)/%.c)

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

CSTD =       $(CSTD_GNU99)
C99LMODE =      -Xc99=%all

CFLAGS +=	$(CCVERBOSE)

# Note: need our sys includes _before_ ENVCPPFLAGS, proto etc.
# Also Note: intentionally override CPPFLAGS, not +=
CPPFLAGS.first += -I../common
CPPFLAGS= $(CPPFLAGS.first)

INCS += -I$(SRC)/uts/common -I $(SRC)/common

CPPFLAGS += $(INCS) -D_REENTRANT -D_FAKE_KERNEL
CPPFLAGS += -D_FILE_OFFSET_BITS=64

# Could make this $(NOT_RELEASE_BUILD) but as the main purpose of
# this library is for debugging, let's always define DEBUG here.
CPPFLAGS += -DDEBUG

LINTCHECKFLAGS += -erroff=E_INCONS_ARG_DECL2
LINTCHECKFLAGS += -erroff=E_INCONS_VAL_TYPE_DECL2
LINTCHECKFLAGS += -erroff=E_INCONS_VAL_TYPE_USED2

LDLIBS += -lumem -lcryptoutil -lsocket -lc -lavl

.KEEP_STATE:

all: $(LIBS)

$(SRCDIR)/sid.c: $(SRC)/uts/common/os/sid.c
	$(CP) $^ $@

lint: lintcheck

include ../../Makefile.targ
