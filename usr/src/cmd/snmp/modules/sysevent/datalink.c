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
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include "sysevent_snmp.h"

#include <sys/sysevent/datalink.h>

void
ssm_datalink_handler(sysevent_t *ev)
{
	static const oid ssm_datalink_trap_oid[] = { SSM_DATALINK_TRAP_OID };
	const size_t ssm_datalink_trap_len = OID_LENGTH(ssm_datalink_trap_oid);
	static const oid ssm_datalink_hostname_oid[] =
	    { SSM_DATALINK_HOSTNAME_OID };
	static const oid ssm_datalink_name_oid[] = { SSM_DATALINK_NAME_OID };
	static const oid ssm_datalink_state_oid[] = { SSM_DATALINK_STATE_OID };
	const size_t ssm_datalink_base_len =
	    OID_LENGTH(ssm_datalink_hostname_oid);
	size_t oid_len = ssm_datalink_base_len * sizeof (oid);
	size_t var_len = ssm_datalink_base_len + 1;
	oid var_name[MAX_OID_LEN] = { 0 };
	netsnmp_variable_list *notification_vars = NULL;
	nvlist_t *evnv;
	char *name;
	int32_t state;

	if (sysevent_get_attr_list(ev, &evnv) != 0 ||
	    nvlist_lookup_string(evnv, DATALINK_EV_LINK_NAME, &name) != 0 ||
	    nvlist_lookup_int32(evnv, DATALINK_EV_LINK_STATE, &state) != 0) {
		DEBUGMSGTL((modname, "%s: failed to parse attr nvlist\n",
		    __func__));
		return;
	}

	/* Hostname */
	(void) memcpy(var_name, ssm_datalink_hostname_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, hostname, strlen(hostname));
	/* Datalink name */
	(void) memcpy(var_name, ssm_datalink_name_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, name, strlen(name));
	/* Datalink state (0 - down, 1 - up) */
	(void) memcpy(var_name, ssm_datalink_state_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_INTEGER, &state, sizeof (state));

	/* Send the trap */
	send_enterprise_trap_vars(SNMP_TRAP_ENTERPRISESPECIFIC,
	    ssm_datalink_trap_oid[ssm_datalink_trap_len - 1],
	    (oid *)ssm_datalink_trap_oid,
	    ssm_datalink_trap_len - 2, notification_vars);
	snmp_free_varbind(notification_vars);
}
