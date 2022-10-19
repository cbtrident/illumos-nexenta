/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * sysevent module.
 *
 * The purpose of this module is to send SNMP traps on the events defined below.
 */

#include "sysevent_snmp.h"

const char *const modname = "sysevent";

static struct ssm_handler {
	const char *class;
	const char *subclass;
	void (*handler)(sysevent_t *ev);
	sysevent_handle_t *shp;
} ssm_handlers[] = {
	{ EC_DEV_ADD, ESC_DISK, ssm_disk_handler, NULL },
	{ EC_DEV_REMOVE, ESC_DISK, ssm_disk_handler, NULL },
	{ EC_DATALINK, ESC_DATALINK_LINK_STATE, ssm_datalink_handler, NULL },
	{ "", "", NULL, NULL }
};

void
init_sysevent(void)
{
	struct ssm_handler *ssmhp = ssm_handlers;
	const char *sc[1];

	ssm_disk_init();

	for (ssmhp = ssm_handlers; ssmhp->handler != NULL; ssmhp++) {
		VERIFY3P(ssmhp->shp, ==, NULL);
		ssmhp->shp = sysevent_bind_handle(ssmhp->handler);
		VERIFY3P(ssmhp->shp, !=, NULL);
		sc[0] = ssmhp->subclass;
		VERIFY3U(sysevent_subscribe_event(ssmhp->shp, ssmhp->class,
		    sc, 1), ==, 0);
		DEBUGMSGTL((modname, "subscribed to %s:%s\n", ssmhp->class,
		    ssmhp->subclass));
	}
}

void
deinit_sysevent(void)
{
	struct ssm_handler *ssmhp = ssm_handlers;

	for (ssmhp = ssm_handlers; ssmhp->handler != NULL; ssmhp++) {
		sysevent_unsubscribe_event(ssmhp->shp, ssmhp->class);
		sysevent_unbind_handle(ssmhp->shp);
		ssmhp->shp = NULL;
	}

	ssm_disk_fini();
}
