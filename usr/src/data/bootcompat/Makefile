#
# Copyright 2019 Nexenta Systems, Inc.
#

# This is provided to keep backward compatibility for installboot.  Remove once
# all users are upgraded to past-May-2019 loader sync.

BOOTFILES=	bootia32.efi \
		bootx64.efi

include		$(SRC)/data/Makefile.data

FILEMODE=	0555

ROOTBOOTDIR=	$(ROOT)/boot

ROOTBOOTFILES=	$(BOOTFILES:%=$(ROOTBOOTDIR)/%)

.KEEP_STATE:

all:		$(BOOTFILES)

$(ROOTBOOTDIR):
		$(INS.dir)

$(ROOTBOOTDIR)/%: %
		$(INS.file)

install:	all $(ROOTBOOTDIR) $(ROOTBOOTFILES)

clean clobber:
