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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
#

DEFAULTFILES = nfs.dfl

include ../../../Makefile.cmd

ETCNFS= $(ROOTETC)/nfs
ETCCLUST= $(ROOTETC)/cluster
VARNFS= $(ROOT)/var/nfs
TXTS= nfssec.conf
NFSTXTS= nfslog.conf
NFSHA= nodeid
V4SSDIR= $(VARNFS)/v4_state $(VARNFS)/v4_oldstate

IETCFILES=			$(TXTS:%=$(ROOTETC)/%)
INFSETCFILES=			$(NFSTXTS:%=$(ROOTETC)/nfs/%)
NFSHAFILE=			$(NFSHA:%=$(ETCCLUST)/%)

FILEMODE= 0644

all: $(TXTS) $(NFSTXTS) $(NFSHA)

install: all $(IETCFILES) $(ETCNFS) $(INFSETCFILES) $(VARNFS) $(V4SSDIR) \
	 $(IDEFFILES) $(ROOTETCDEFAULTFILES) $(ETCCLUST) $(NFSHAFILE)

$(ROOTETC)/%: %
	$(INS.file)

$(ROOTETC)/nfs/%: %
	$(INS.file)

$(ETCCLUST):
	$(INS.dir)

$(ETCNFS):
	$(INS.dir)

$(VARNFS):
	$(INS.dir)

$(V4SSDIR):
	$(INS.dir)

$(ROOTETC)/cluster/%: %
	$(INS.file)

.KEEP_STATE:

clean clobber lint:
