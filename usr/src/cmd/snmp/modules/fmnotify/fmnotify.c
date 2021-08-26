/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/debug.h>

#include <sys/fm/protocol.h>

#include <fm/libfmevent.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <libfmnotify.h>

#include <netdb.h>
#include <strings.h>

#include "fm_snmp.h"

const char *const modname = "fmnotify";

typedef struct ireport_trap {
	long long tstamp;
	char *host;
	char *msgid;
	char *severity;
	char *desc;
	char *fmri;
	uint32_t from_state;
	uint32_t to_state;
	char *reason;
	boolean_t is_stn_event;
} ireport_trap_t;

typedef struct fmproblem_trap {
	char *uuid;
	char *host;
	char *code;
	char *type;
	char *severity;
	char *url;
	char *descr;
	char *fmri;
} fmproblem_trap_t;

static nd_hdl_t *nhdl;
static char hostname[MAXHOSTNAMELEN + 1];

static void
send_ireport_trap(ireport_trap_t *t)
{
	static const oid sunIreportTrap_oid[] =
	    { SUNIREPORTTRAP_OID };
	const size_t sunIreportTrap_len =
	    OID_LENGTH(sunIreportTrap_oid);

	static const oid sunIreportHostname_oid[] =
	    { SUNIREPORTHOSTNAME_OID };
	static const oid sunIreportMsgid_oid[] =
	    { SUNIREPORTMSGID_OID };
	static const oid sunIreportSeverity_oid[] =
	    { SUNIREPORTSEVERITY_OID };
	static const oid sunIreportDescription_oid[] =
	    { SUNIREPORTDESCRIPTION_OID };
	static const oid sunIreportTime_oid[] =
	    { SUNIREPORTTIME_OID };

	static const oid sunIreportSmfFmri_oid[] =
	    { SUNIREPORTSMFFMRI_OID };
	static const oid sunIreportSmfFromState_oid[] =
	    { SUNIREPORTSMFFROMSTATE_OID };
	static const oid sunIreportSmfToState_oid[] =
	    { SUNIREPORTSMFTOSTATE_OID };
	static const oid sunIreportSmfTransitionReason_oid[] =
	    { SUNIREPORTTRANSITIONREASON_OID };
	const size_t
	    sunIreport_base_len = OID_LENGTH(sunIreportHostname_oid);

	size_t oid_len = sunIreport_base_len * sizeof (oid);
	size_t var_len = sunIreport_base_len + 1;
	oid var_name[MAX_OID_LEN] = { 0 };

	netsnmp_variable_list *notification_vars = NULL;

	size_t dt_len;
	uchar_t dt[11], *tdt;
	time_t ts = t->tstamp;

	tdt = date_n_time(&ts, &dt_len);
	/*
	 * We know date_n_time is broken, it returns a buffer from
	 * its stack. So we copy before we step over it!
	 */
	for (int i = 0; i < dt_len; ++i)
		dt[i] = tdt[i];

	if (var_len > MAX_OID_LEN) {
		DEBUGMSGTL((modname, "var_len %ld > MAX_OID_LEN %d\n",
		    var_len, MAX_OID_LEN));
		return;
	}

	(void) memcpy(var_name, sunIreportHostname_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, (uchar_t *)t->host, strlen(t->host));

	(void) memcpy(var_name, sunIreportMsgid_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, (uchar_t *)t->msgid, strlen(t->msgid));

	(void) memcpy(var_name, sunIreportSeverity_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, (uchar_t *)t->severity,
	    strlen(t->severity));

	(void) memcpy(var_name, sunIreportDescription_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, (uchar_t *)t->desc, strlen(t->desc));

	(void) memcpy(var_name, sunIreportTime_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, dt, dt_len);

	if (t->is_stn_event) {
		(void) memcpy(var_name, sunIreportSmfFmri_oid, oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_OCTET_STR, (uchar_t *)t->fmri,
		    strlen(t->fmri));

		(void) memcpy(var_name, sunIreportSmfFromState_oid, oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_INTEGER, (uchar_t *)&t->from_state,
		    sizeof (uint32_t));

		(void) memcpy(var_name, sunIreportSmfToState_oid, oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_INTEGER, (uchar_t *)&t->to_state,
		    sizeof (uint32_t));

		(void) memcpy(var_name, sunIreportSmfTransitionReason_oid,
		    oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_OCTET_STR, (uchar_t *)t->reason,
		    strlen(t->reason));
	}

	/*
	 * This function is capable of sending both v1 and v2/v3 traps.
	 * Which is sent to a specific destination is determined by the
	 * configuration file(s).
	 */
	send_enterprise_trap_vars(SNMP_TRAP_ENTERPRISESPECIFIC,
	    sunIreportTrap_oid[sunIreportTrap_len - 1],
	    (oid *)sunIreportTrap_oid, sunIreportTrap_len - 2,
	    notification_vars);
	DEBUGMSGTL((modname, "sent SNMP trap for %s\n", t->msgid));

	snmp_free_varbind(notification_vars);
}

static void
send_fm_trap(fmproblem_trap_t *t)
{
	static const oid sunFmProblemTrap_oid[] = { SUNFMPROBLEMTRAP_OID };
	const size_t sunFmProblemTrap_len = OID_LENGTH(sunFmProblemTrap_oid);

	static const oid sunFmProblemUUID_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_UUID };
	static const oid sunFmProblemHostname_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_HOSTNAME };
	static const oid sunFmProblemCode_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_CODE };
	static const oid sunFmProblemType_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_TYPE };
	static const oid sunFmProblemSeverity_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_SEVERITY };
	static const oid sunFmProblemURL_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_URL };
	static const oid sunFmProblemDescr_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_DESC };
	static const oid sunFmProblemFMRI_oid[] =
	    { SUNFMPROBLEMTABLE_OID, 1, SUNFMPROBLEM_COL_FMRI };

	const size_t sunFmProblem_base_len = OID_LENGTH(sunFmProblemUUID_oid);

	size_t oid_len = sunFmProblem_base_len * sizeof (oid);
	size_t uuid_len = strlen(t->uuid);
	size_t var_len = sunFmProblem_base_len + 1 + uuid_len;
	oid var_name[MAX_OID_LEN];

	netsnmp_variable_list *notification_vars = NULL;

	/*
	 * The format of our trap varbinds' oids is as follows:
	 *
	 * +-----------------------+---+--------+----------+------+
	 * | SUNFMPROBLEMTABLE_OID | 1 | column | uuid_len | uuid |
	 * +-----------------------+---+--------+----------+------+
	 *					 \---- index ----/
	 *
	 * A common mistake here is to send the trap with varbinds that
	 * do not contain the index.  All the indices are the same, and
	 * all the oids are the same length, so the only thing we need to
	 * do for each varbind is set the table and column parts of the
	 * variable name.
	 */

	if (var_len > MAX_OID_LEN)
		return;

	var_name[sunFmProblem_base_len] = (oid)uuid_len;
	for (int i = 0; i < uuid_len; i++)
		var_name[i + sunFmProblem_base_len + 1] = (oid)t->uuid[i];

	/*
	 * Ordinarily, we would need to add the OID of the trap itself
	 * to the head of the variable list; this is required by SNMP v2.
	 * However, send_enterprise_trap_vars does this for us as a part
	 * of converting between v1 and v2 traps, so we skip directly to
	 * the objects we're sending.
	 */

	(void) memcpy(var_name, sunFmProblemUUID_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)t->uuid, strlen(t->uuid));

	(void) memcpy(var_name, sunFmProblemHostname_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)t->host, strlen(t->host));

	(void) memcpy(var_name, sunFmProblemCode_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)t->code, strlen(t->code));

	(void) memcpy(var_name, sunFmProblemType_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)t->type, strlen(t->type));

	(void) memcpy(var_name, sunFmProblemSeverity_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)t->severity, strlen(t->severity));

	(void) memcpy(var_name, sunFmProblemURL_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)t->url, strlen(t->url));

	(void) memcpy(var_name, sunFmProblemDescr_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name, var_len,
	    ASN_OCTET_STR, (uchar_t *)t->descr, strlen(t->descr));

	if (strcmp(t->fmri, ND_UNKNOWN) != 0) {
		(void) memcpy(var_name, sunFmProblemFMRI_oid, oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_OCTET_STR, (uchar_t *)t->fmri,
		    strlen(t->fmri));
	}

	/*
	 * This function is capable of sending both v1 and v2/v3 traps.
	 * Which is sent to a specific destination is determined by the
	 * configuration file(s).
	 */
	send_enterprise_trap_vars(SNMP_TRAP_ENTERPRISESPECIFIC,
	    sunFmProblemTrap_oid[sunFmProblemTrap_len - 1],
	    (oid *)sunFmProblemTrap_oid, sunFmProblemTrap_len - 2,
	    notification_vars);
	DEBUGMSGTL((modname, "sent SNMP trap for %s\n", t->code));

	snmp_free_varbind(notification_vars);
}

/*
 * The SUN-IREPORT-MIB declares the following enum to represent SMF service
 * states.
 *
 * offline(0), online(1), degraded(2), disabled(3), maintenance(4),
 * uninitialized(5)
 *
 * This function converts a string representation of an SMF service state
 * to its corresponding enum val.
 */
static int
state_to_val(char *statestr, uint32_t *stateval)
{
	if (strcmp(statestr, "offline") == 0)
		*stateval = 0;
	else if (strcmp(statestr, "online") == 0)
		*stateval = 1;
	else if (strcmp(statestr, "degraded") == 0)
		*stateval = 2;
	else if (strcmp(statestr, "disabled") == 0)
		*stateval = 3;
	else if (strcmp(statestr, "maintenance") == 0)
		*stateval = 4;
	else if (strcmp(statestr, "uninitialized") == 0)
		*stateval = 5;
	else
		return (-1);
	return (0);
}

static void
ireport_cb(fmev_t ev, const char *class, nvlist_t *nvl, void *arg)
{
	nd_ev_info_t *ev_info = NULL;
	ireport_trap_t swtrap;

	DEBUGMSGTL((modname, "received event of class %s\n", class));

	if (nd_get_event_info(nhdl, class, ev, &ev_info) != 0)
		goto irpt_done;

	swtrap.host = hostname;
	swtrap.msgid = ev_info->ei_diagcode;
	swtrap.severity = ev_info->ei_severity;
	swtrap.desc = ev_info->ei_descr;
	swtrap.tstamp = (time_t)fmev_time_sec(ev);

	if (strncmp(class, "ireport.os.smf", 14) == 0) {
		swtrap.fmri = ev_info->ei_fmri;
		if (state_to_val(ev_info->ei_from_state, &swtrap.from_state)
		    < 0 ||
		    state_to_val(ev_info->ei_to_state, &swtrap.to_state) < 0) {
			DEBUGMSGTL((modname,
			    "malformed event - invalid svc state\n"));
			goto irpt_done;
		}
		swtrap.reason = ev_info->ei_reason;
		swtrap.is_stn_event = B_TRUE;
	}
	send_ireport_trap(&swtrap);

irpt_done:
	if (ev_info != NULL)
		nd_free_event_info(ev_info);
}

static void
list_cb(fmev_t ev, const char *class, nvlist_t *nvl, void *arg)
{
	uint8_t version;
	nd_ev_info_t *ev_info = NULL;
	fmproblem_trap_t fmtrap;
	boolean_t domsg;

	DEBUGMSGTL((modname, "received event of class %s\n", class));

	if (nd_get_event_info(nhdl, class, ev, &ev_info) != 0)
		goto listcb_done;

	/*
	 * If the message payload member is set to 0, then it's an event we
	 * typically suppress messaging on, so we won't send a trap for it.
	 */
	if (nvlist_lookup_boolean_value(ev_info->ei_payload, FM_SUSPECT_MESSAGE,
	    &domsg) == 0 && !domsg) {
		DEBUGMSGTL((modname,
		    "messaging suppressed for this event\n"));
		goto listcb_done;
	}

	if (nvlist_lookup_uint8(ev_info->ei_payload, FM_VERSION,
	    &version) != 0 || version > FM_SUSPECT_VERSION) {
		DEBUGMSGTL((modname, "invalid event version: %u\n", version));
		goto listcb_done;
	}

	fmtrap.uuid = ev_info->ei_uuid;
	fmtrap.host = hostname;
	fmtrap.code = ev_info->ei_diagcode;
	fmtrap.type = ev_info->ei_type;
	fmtrap.severity = ev_info->ei_severity;
	fmtrap.url = ev_info->ei_url;
	fmtrap.descr = ev_info->ei_descr;
	fmtrap.fmri = ev_info->ei_fmri;

	send_fm_trap(&fmtrap);

listcb_done:
	if (ev_info != NULL)
		nd_free_event_info(ev_info);
}

void
init_fmnotify(void)
{
	(void) gethostname(hostname, sizeof (hostname));

	VERIFY3P(nhdl, ==, NULL);
	nhdl = calloc(1, sizeof (nd_hdl_t));
	VERIFY3P(nhdl, !=, NULL);

	nhdl->nh_evhdl = fmev_shdl_init(LIBFMEVENT_VERSION_2, NULL, NULL, NULL);
	VERIFY3P(nhdl->nh_evhdl, !=, NULL);
	nhdl->nh_rootdir = "";
	nhdl->nh_msghdl = fmd_msg_init(nhdl->nh_rootdir, FMD_MSG_VERSION);
	VERIFY3P(nhdl->nh_msghdl, !=, NULL);

	/* Set up our event subscriptions */
	DEBUGMSGTL((modname, "subscribing to ireport.os.smf.* events\n"));
	VERIFY3U(fmev_shdl_subscribe(nhdl->nh_evhdl, "ireport.os.smf.*",
	    ireport_cb, NULL), ==, FMEV_SUCCESS);

	DEBUGMSGTL((modname, "subscribing to list.* events\n"));
	VERIFY3U(fmev_shdl_subscribe(nhdl->nh_evhdl, "list.*", list_cb, NULL),
	    ==, FMEV_SUCCESS);
}

void
deinit_fmnotify(void)
{
	(void) fmev_shdl_unsubscribe(nhdl->nh_evhdl, "ireport.os.smf.*");
	(void) fmev_shdl_unsubscribe(nhdl->nh_evhdl, "list.*");
	(void) fmev_shdl_fini(nhdl->nh_evhdl);
	(void) fmd_msg_fini(nhdl->nh_msghdl);
	free(nhdl);
	nhdl = NULL;
}
