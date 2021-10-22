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

SUBDIRS=	fen \
		fm \
		fmnotify \
		sysevent \
		zfs

all :=		TARGET=all
clean :=	TARGET=clean
clobber :=	TARGET=clobber
install :=	TARGET=install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

$(SUBDIRS):	FRC
		cd $@; pwd; $(MAKE) $(TARGET)

FRC:
