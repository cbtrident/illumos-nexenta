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
# Copyright 2011 EveryCity Ltd. All rights reserved.
# Copyright 2013 DEY Storage Systems, Inc.
# Copyright 2016 Joyent, Inc.
# Copyright 2019 Garrett D'Amore <garrett@damore.org>
#

include		$(SRC)/data/Makefile.data
include		Makefile.com

LOCNAMES=	$(LOCALES:%=%.UTF-8)
LOCDIRS=	$(LOCNAMES:%=locale/%)

STAMPFILES=	$(LOCDIRS:%=%/stamp)

CATDIRS=	$(LOCDIRS:%=%/LC_COLLATE) \
		$(LOCDIRS:%=%/LC_CTYPE) \
		$(LOCDIRS:%=%/LC_MESSAGES) \
		$(LOCDIRS:%=%/LC_MONETARY) \
		$(LOCDIRS:%=%/LC_NUMERIC) \
		$(LOCDIRS:%=%/LC_TIME)
DATA=		$(CATDIRS:%=%/LCL_DATA)

.PARALLEL:

DCOLL=		LC_COLLATE/LCL_DATA
DCTYPE=		LC_CTYPE/LCL_DATA
DMSGS=		LC_MESSAGES/LCL_DATA
DMON=		LC_MONETARY/LCL_DATA
DNUM=		LC_NUMERIC/LCL_DATA
DTIME=		LC_TIME/LCL_DATA

ROOTLOCDIRS=	$(LOCDIRS:%=$(ROOTLIB)/%)
ROOTCATDIRS=	$(CATDIRS:%=$(ROOTLIB)/%)
ROOTDATA=	$(DATA:%=$(ROOTLIB)/%)
$(ROOTDATA):=	FILEMODE=0444

TRANSDIR=	translations
TRANSMOS=	$(TRANSLOCS:%=$(TRANSDIR)/%.mo)
OSTMOFILE=	LC_MESSAGES/SUNW_OST_OSLIB.mo
PRIVFILE=	LC_MESSAGES/priv_names
ROOTTRANSLATIONS=$(TRANSLOCS:%=$(ROOTLIB)/locale/%/$(OSTMOFILE))
ROOTPRIVTRANS=	$(PRIVTRANSLOCS:%=$(ROOTLIB)/locale/%/$(PRIVFILE))

.KEEP_STATE:

all:		$(DATA)

clean:
		$(RM) $(CLEANFILES) $(STAMPFILES)

clobber:	clean
		$(RM) -r $(LOCDIRS)
		$(RM) $(TRANSMOS)

install:	all $(ROOTDATA) $(ROOTTRANSLATIONS) $(ROOTPRIVTRANS)

translate:	$(ROOTTRANSLATIONS) $(ROOTPRIVTRANS)

locale $(ROOTLOCDIRS) $(ROOTCATDIRS):
		$(INS.dir)

$(STAMPFILES):	locale

# Strip LC_CTYPE contents for UTF-8 locales and replace them
# with common LC_CTYPE definition.
locale/%.UTF-8/stamp: data/%.UTF-8.src data/UTF-8.cm data/common.UTF-8.src
		$(SED) \
		-e '/^LC_CTYPE/,/^END LC_CTYPE/d' \
		-e '$$r data/common.UTF-8.src' $< | \
		$(LCDEF) -U -w data/widths.txt -f data/UTF-8.cm $(@D)
		$(TOUCH) $@

# Special handling for zz_AA test locale
locale/zz_AA.UTF-8/stamp: data/en_US.UTF-8.src data/UTF-8.cm data/common.UTF-8.src
		$(SED) \
		-e '/^LC_CTYPE/,/^END LC_CTYPE/d' \
		-e '$$r data/common.UTF-8.src' data/en_US.UTF-8.src | \
		$(LCDEF) -U -w data/widths.txt -f data/UTF-8.cm $(@D)
		$(TOUCH) $@

locale/%/$(DCOLL): locale/%/stamp
locale/%/$(DCTYPE): locale/%/stamp
locale/%/$(DMSGS): locale/%/stamp
locale/%/$(DMON): locale/%/stamp
locale/%/$(DNUM): locale/%/stamp
locale/%/$(DTIME): locale/%/stamp

$(ROOTDATA):	$(ROOTLOCDIRS) $(ROOTCATDIRS) $(DATA)
		$(RM) $@
		if [[ -f $(@:$(ROOTLIB)/%=%) ]]; then \
			$(CP) $(@:$(ROOTLIB)/%=%) $@; \
			$(CHMOD) -f 0444 $@ ; \
		fi

%.mo:		%.po
		$(MSGFMT) -o $@ $<

$(ROOTLIB)/locale/%/$(OSTMOFILE): $(TRANSDIR)/%.mo
		$(INS.rename)
		$(CHMOD) 0444 $@

$(ROOTLIB)/locale/%/$(PRIVFILE): $(TRANSDIR)/%.priv
		$(INS.rename)
		$(CHMOD) 0444 $@
