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

#include <sys/avl.h>
#include <sys/fm/protocol.h>

#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <fm/topo_list.h>

#include <pthread.h>
#include <unistd.h>

static avl_tree_t ssm_disk_tree;
static pthread_mutex_t ssm_disk_tree_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct ssm_disk {
	avl_node_t ssm_disk_avl;
	char *devname;
	char *encid;
	int32_t slotid;
	char *encname;
	char *slotname;
} ssm_disk_t;

static ssm_disk_t *
ssm_disk_create(const char *devname)
{
	ssm_disk_t *sdp;

	if ((sdp = calloc(1, sizeof (ssm_disk_t))) == NULL ||
	    (devname != NULL && (sdp->devname = strdup(devname)) == NULL))
		return (NULL);

	return (sdp);
}

static void
ssm_disk_free(ssm_disk_t *sdp)
{
	free(sdp->devname);
	free(sdp->encid);
	free(sdp->encname);
	free(sdp->slotname);
	free(sdp);
}

static int
ssm_disk_compare(const void *l, const void *r)
{
	const ssm_disk_t *ld = l;
	const ssm_disk_t *rd = r;
	int cmp = strcasecmp(ld->devname, rd->devname);

	if (cmp < 0)
		return (-1);
	else if (cmp > 0)
		return (1);
	else
		return (0);
}

static int
ssm_disk_walker(topo_hdl_t *thp, tnode_t *np, void *arg)
{
	ssm_disk_t *sdp, *tsdp;
	char *ndevname = arg;
	char *devname = NULL;
	char *encid;
	char *encname;
	char *slotname;
	tnode_t *pnp;
	int err;

	if (strcmp(topo_node_name(np), DISK) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_prop_get_string(np, "storage", "logical-disk",
	    &devname, &err) != 0 ||
	    (ndevname != NULL && strcasecmp(ndevname, devname) != 0))
		return (TOPO_WALK_NEXT);

	if (ndevname == NULL)
		ndevname = devname;

	if ((sdp = ssm_disk_create(ndevname)) == NULL)
		return (TOPO_WALK_ERR);

	if (topo_prop_get_string(np, "authority", "chassis-id",
	    &encid, &err) == 0)
		sdp->encid = strdup(encid);
	else
		sdp->encid = strdup("-");
	if (sdp->encid == NULL)
		goto fail;

	if (topo_prop_get_string(np, "authority", "product-id",
	    &encname, &err) == 0)
		sdp->encname = strdup(encname);
	else
		sdp->encname = strdup("-");
	if (sdp->encname == NULL)
		goto fail;

	pnp = topo_node_parent(np);
	if (strcmp(topo_node_name(pnp), BAY) == 0 &&
	    topo_prop_get_string(pnp, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_LABEL, &slotname, &err) == 0) {
		sdp->slotid = topo_node_instance(pnp);
		sdp->slotname = strdup(slotname);
	} else {
		sdp->slotname = strdup("-");
	}
	if (sdp->slotname == NULL)
		goto fail;

	/*
	 * Safeguard against possible replay of events pointing to the already
	 * added disk.
	 */
	if ((tsdp = avl_find(&ssm_disk_tree, sdp, NULL)) != NULL) {
		DEBUGMSGTL((modname, "duplicate entry %s\n",
		    tsdp->devname));
		avl_remove(&ssm_disk_tree, tsdp);
		ssm_disk_free(tsdp);
	}
	avl_add(&ssm_disk_tree, sdp);
	DEBUGMSGTL((modname, "added %s: %s:%d %s:%s\n", ndevname,
	    sdp->encid, sdp->slotid, sdp->encname, sdp->slotname));

	return (TOPO_WALK_TERMINATE);

fail:
	ssm_disk_free(sdp);
	return (TOPO_WALK_ERR);
}

static ssm_disk_t *
ssm_disk_add(char *devname)
{
	ssm_disk_t sdp, *ret = NULL;
	topo_hdl_t *thp;
	topo_walk_t *wp = NULL;
	char *uuid = NULL;
	int err = 0;

	(void) pthread_mutex_lock(&ssm_disk_tree_lock);
	if ((thp = topo_open(TOPO_VERSION, NULL, &err)) == NULL ||
	    (uuid = topo_snap_hold(thp, NULL, &err)) == NULL || err != 0)
		goto fail;

	if ((wp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, ssm_disk_walker,
	    devname, &err)) == NULL)
		goto fail;

	if (topo_walk_step(wp, TOPO_WALK_CHILD) == TOPO_WALK_ERR)
		goto fail;

	if (devname != NULL) {
		if ((sdp.devname = strdup(devname)) == NULL)
			goto fail;
		ret = avl_find(&ssm_disk_tree, &sdp, NULL);
		free(sdp.devname);
	}

fail:
	topo_walk_fini(wp);
	topo_hdl_strfree(thp, uuid);
	topo_snap_release(thp);
	topo_close(thp);
	(void) pthread_mutex_unlock(&ssm_disk_tree_lock);
	return (ret);
}

static ssm_disk_t *
ssm_disk_remove(char *devname)
{
	ssm_disk_t sdp, *ret;

	if ((sdp.devname = strdup(devname)) == NULL)
		return (NULL);
	(void) pthread_mutex_lock(&ssm_disk_tree_lock);
	if ((ret = avl_find(&ssm_disk_tree, &sdp, NULL)) != NULL) {
		avl_remove(&ssm_disk_tree, ret);
		DEBUGMSGTL((modname, "removed %s\n", devname));
	}
	(void) pthread_mutex_unlock(&ssm_disk_tree_lock);
	free(sdp.devname);

	return (ret);
}

void
ssm_disk_handler(sysevent_t *ev)
{
	static const oid ssm_disk_trap_oid[] = { SSM_DISK_TRAP_OID };
	const size_t ssm_disk_trap_len = OID_LENGTH(ssm_disk_trap_oid);
	static const oid ssm_disk_hostname_oid[] = { SSM_DISK_HOSTNAME_OID };
	static const oid ssm_disk_action_oid[] = { SSM_DISK_ACTION_OID };
	static const oid ssm_disk_devname_oid[] = { SSM_DISK_DEVNAME_OID };
	static const oid ssm_disk_encid_oid[] = { SSM_DISK_ENCID_OID };
	static const oid ssm_disk_slotid_oid[] = { SSM_DISK_SLOTID_OID };
	static const oid ssm_disk_encname_oid[] = { SSM_DISK_ENCNAME_OID };
	static const oid ssm_disk_slotname_oid[] = { SSM_DISK_SLOTNAME_OID };
	const size_t ssm_disk_base_len = OID_LENGTH(ssm_disk_action_oid);
	size_t oid_len = ssm_disk_base_len * sizeof (oid);
	size_t var_len = ssm_disk_base_len + 1;
	oid var_name[MAX_OID_LEN] = { 0 };
	netsnmp_variable_list *notification_vars = NULL;
	nvlist_t *evnv;
	char *devname;
	int32_t action;
	char *c;
	ssm_disk_t *sdp;

	if (sysevent_get_attr_list(ev, &evnv) != 0 ||
	    nvlist_lookup_string(evnv, "dev_name", &devname) != 0) {
		DEBUGMSGTL((modname, "%s: failed to parse attr nvlist\n",
		    __func__));
		return;
	}

	/* Strip /dev/dsk and possible slice */
	if ((c = strrchr(devname, '/')) != NULL)
		devname = ++c;
	if ((c = strchr(devname, 's')) != NULL)
		*c = '\0';

	if (strcmp(sysevent_get_class_name(ev), EC_DEV_ADD) == 0) {
		/* Add the disk to the cache */
		action = 0;
		sdp = ssm_disk_add(devname);
	} else {
		/* Remove the disk from the cache */
		action = 1;
		sdp = ssm_disk_remove(devname);
	}

	/* Hostname */
	(void) memcpy(var_name, ssm_disk_hostname_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, hostname, strlen(hostname));
	/* Disk action (0 - add, 1 - remove) */
	(void) memcpy(var_name, ssm_disk_action_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_INTEGER, &action, sizeof (action));
	/* Short disk name */
	(void) memcpy(var_name, ssm_disk_devname_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, devname, strlen(devname));

	if (sdp != NULL) {
		/* Enclosure chassis ID */
		(void) memcpy(var_name, ssm_disk_encid_oid, oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_OCTET_STR, sdp->encid, strlen(sdp->encid));
		/* Enclosure slot ID */
		(void) memcpy(var_name, ssm_disk_slotid_oid, oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_INTEGER, &sdp->slotid, sizeof (sdp->slotid));
		/* Enclosure product name */
		(void) memcpy(var_name, ssm_disk_encname_oid, oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_OCTET_STR, sdp->encname, strlen(sdp->encname));
		/* Enclosure slot name */
		(void) memcpy(var_name, ssm_disk_slotname_oid, oid_len);
		(void) snmp_varlist_add_variable(&notification_vars, var_name,
		    var_len, ASN_OCTET_STR, sdp->slotname,
		    strlen(sdp->slotname));

		if (action == 1)
			ssm_disk_free(sdp);
	}

	/* Send the trap */
	send_enterprise_trap_vars(SNMP_TRAP_ENTERPRISESPECIFIC,
	    ssm_disk_trap_oid[ssm_disk_trap_len - 1], (oid *)ssm_disk_trap_oid,
	    ssm_disk_trap_len - 2, notification_vars);
	DEBUGMSGTL((modname, "sent trap for %s\n", devname));
	snmp_free_varbind(notification_vars);
}

void *
ssm_disk_init_thread(void *arg)
{
	(void) ssm_disk_add(NULL);

	return (NULL);
}

void
ssm_disk_init(void)
{
	pthread_t utid;

	avl_create(&ssm_disk_tree, ssm_disk_compare, sizeof (ssm_disk_t),
	    offsetof(ssm_disk_t, ssm_disk_avl));

	/* Do initial update in separate thread */
	(void) pthread_create(&utid, NULL, ssm_disk_init_thread, 0);
}

void
ssm_disk_fini(void)
{
	ssm_disk_t *sdp;
	void *c = NULL;

	(void) pthread_mutex_lock(&ssm_disk_tree_lock);
	while ((sdp = avl_destroy_nodes(&ssm_disk_tree, &c)) != NULL)
		ssm_disk_free(sdp);
	avl_destroy(&ssm_disk_tree);
	(void) pthread_mutex_unlock(&ssm_disk_tree_lock);
}
