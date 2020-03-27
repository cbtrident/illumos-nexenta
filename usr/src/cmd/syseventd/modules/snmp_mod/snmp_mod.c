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
 * Copyright 2020 Nexenta by DDN, Inc.  All rights reserved.
 */

/*
 * SNMP syseventd module.
 *
 * The purpose of this module is to send SNMP traps on the events defined below.
 */

#include "snmp_mod.h"

char hostname[MAXHOSTNAMELEN + 1];

static struct ssm_handler {
	const char *class;
	const char *subclass;
	void (*handler)(sysevent_t *ev);
} ssm_handlers[] = {
	{ EC_DEV_ADD, ESC_DISK, ssm_disk_handler },
	{ EC_DEV_REMOVE, ESC_DISK, ssm_disk_handler },
	{ EC_DATALINK, ESC_DATALINK_LINK_STATE, ssm_datalink_handler },
	{ "", "", NULL }
};

static int
ssm_deliver_event(sysevent_t *ev, int unused)
{
	const char *class = sysevent_get_class_name(ev);
	const char *subclass = sysevent_get_subclass_name(ev);
	struct ssm_handler *ssmhp = ssm_handlers;

	for (ssmhp = ssm_handlers; ssmhp->handler != NULL; ssmhp++) {
		if (strcmp(class, ssmhp->class) == 0 &&
		    strcmp(subclass, ssmhp->subclass) == 0) {
			(*ssmhp->handler)(ev);
			break;
		}
	}

	return (0);
}

static struct slm_mod_ops snmp_mod_ops = {
	SE_MAJOR_VERSION,
	SE_MINOR_VERSION,
	10,
	ssm_deliver_event
};

struct slm_mod_ops *
slm_init(void)
{
	(void) gethostname(hostname, MAXHOSTNAMELEN + 1);

	/* Init SMA */
	snmp_disable_log();
	if (netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
	    NETSNMP_DS_AGENT_ROLE, 0) != SNMPERR_SUCCESS)
		return (NULL);
	init_agent_read_config("snmpd");
	if (netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
	    NETSNMP_DS_LIB_APPTYPE, SNMP_SUPPCONF) != SNMPERR_SUCCESS)
		return (NULL);
	if (register_app_config_handler("trapsink", snmpd_parse_config_trapsink,
	    snmpd_free_trapsinks, "host [community] [port]") == NULL)
		return (NULL);
	if (register_app_config_handler("trap2sink",
	    snmpd_parse_config_trap2sink, NULL,
	    "host [community] [port]") == NULL)
		return (NULL);
	if (register_app_config_handler("trapsess", snmpd_parse_config_trapsess,
	    NULL, "[snmpcmdargs] host") == NULL)
		return (NULL);
	init_traps();
	init_snmp(SNMP_SUPPCONF);

	/* Init handlers */
	ssm_disk_init();

	return (&snmp_mod_ops);
}

void
slm_fini(void)
{
	/* Shutdown handlers */
	ssm_disk_fini();

	/* Shutdown SNMP */
	snmp_store(SNMP_SUPPCONF);
	snmp_alarm_unregister_all();
	(void) snmp_close_sessions();
	shutdown_mib();
	unregister_all_config_handlers();
	netsnmp_ds_shutdown();
}
