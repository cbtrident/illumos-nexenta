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

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <port.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#define	CONFPATH	"/etc/net-snmp/snmp/fen.conf"

/* nexenta-core-storage-fen-mib OID */
#define	FEN_OID	1, 3, 6, 1, 4, 1, 40045, 1, 1, 3, 1
/* notification trap definitions */
#define	FEN_TRAP_OID		FEN_OID, 1
/* notification object definitions */
#define	FEN_OBJECTS_OID		FEN_OID, 2
/* fen trap payload */
#define	FEN_HOSTNAME_OID	FEN_OBJECTS_OID, 1
#define	FEN_ACTION_OID		FEN_OBJECTS_OID, 2
#define	FEN_PATH_OID		FEN_OBJECTS_OID, 3

static const char *const modname = "fen";
static char hostname[MAXHOSTNAMELEN + 1];
static pthread_t event_tid;
static int port;

typedef enum {
	FEN_CREATE,
	FEN_MODIFY,
	FEN_RENAME,
	FEN_DELETE
} fen_action_t;

struct fdwatch {
	file_obj_t fo;
	bool isdir;
	bool exists;
	STAILQ_ENTRY(fdwatch) fdwatches;
};
STAILQ_HEAD(fdwhead, fdwatch) fdwhead;

static char *
sdirname(char *path)
{
	char *dpath;

	dpath = strdup(path);
	VERIFY3P(dpath, !=, NULL);
	return (dirname(dpath));
}

static void
free_wdir(struct fdwatch *fdw)
{
	VERIFY(fdw->isdir);
	STAILQ_REMOVE(&fdwhead, fdw, fdwatch, fdwatches);
	free(fdw->fo.fo_name);
	free(fdw);
}

static int
add_watch(struct fdwatch *fdw)
{
	struct stat sb;
	file_obj_t *fop;
	int events;
	int rc;

	fop = &fdw->fo;
	rc = stat(fop->fo_name, &sb);
	if ((!fdw->isdir && !fdw->exists) || rc == -1) {
		struct fdwatch *nfdw;
		char *dpath;

		if (fdw->isdir) {
			/*
			 * We got a file to watch without parent directory, too
			 * bad, but there's nothing we can do.
			 */
			DEBUGMSGTL((modname, "%s missing parent directory\n",
			    fop->fo_name));
			rc = 1;
			goto out;
		}
		/* File does not exist */
		fdw->exists = false;
		/* Check if there is already a watch for this directory */
		dpath = sdirname(fop->fo_name);
		STAILQ_FOREACH(nfdw, &fdwhead, fdwatches) {
			if (strcmp(dpath, nfdw->fo.fo_name) == 0) {
				DEBUGMSGTL((modname,
				    "file %s missing, dwatch exists\n",
				    fop->fo_name));
				free(dpath);
				return (0);
			}
		}
		/* Create new directory watch */
		DEBUGMSGTL((modname, "file %s missing, adding dwatch\n",
		    fop->fo_name));
		nfdw = calloc(1, sizeof (*nfdw));
		VERIFY3P(nfdw, !=, NULL);
		nfdw->fo.fo_name = strdup(dpath);
		VERIFY3P(nfdw->fo.fo_name, !=, NULL);
		free(dpath);
		nfdw->isdir = true;
		STAILQ_INSERT_TAIL(&fdwhead, nfdw, fdwatches);
		return (add_watch(nfdw));
	}

	events = FILE_MODIFIED;
	if (!fdw->isdir) {
		if ((sb.st_mode & S_IFMT) == S_IFDIR) {
			/* Requested to watch a directory via conf file */
			DEBUGMSGTL((modname, "dir %s can't watch directories\n",
			    fop->fo_name));
			return (1);
		}
		fdw->exists = true;
	} else {
		events |= FILE_ATTRIB|FILE_TRUNC;
	}

	fop->fo_ctime = sb.st_ctim;
	fop->fo_atime = sb.st_atim;
	fop->fo_mtime = sb.st_mtim;
	rc = port_associate(port, PORT_SOURCE_FILE, (uintptr_t)fop,
	    events, (void *)fdw);
	if (rc == 0) {
		DEBUGMSGTL((modname, "added watch on %s %s\n",
		    fdw->isdir ? "dir" : "file",
		    fop->fo_name));
	}
out:
	if (rc != 0 && fdw->isdir)
		free_wdir(fdw);
	return (rc);
}

static void
send_trap(const char *path, fen_action_t action)
{
	static const oid fen_trap_oid[] = { FEN_TRAP_OID };
	const size_t fen_trap_len = OID_LENGTH(fen_trap_oid);
	static const oid fen_hostname_oid[] = { FEN_HOSTNAME_OID };
	static const oid fen_action_oid[] = { FEN_ACTION_OID };
	static const oid fen_path_oid[] = { FEN_PATH_OID };
	const size_t fen_base_len = OID_LENGTH(fen_action_oid);
	size_t oid_len = fen_base_len * sizeof (oid);
	size_t var_len = fen_base_len + 1;
	oid var_name[MAX_OID_LEN] = { 0 };
	netsnmp_variable_list *notification_vars = NULL;

	/* Hostname */
	(void) memcpy(var_name, fen_hostname_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, hostname, strlen(hostname));
	/* File action */
	(void) memcpy(var_name, fen_action_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_INTEGER, &action, sizeof (action));
	/* File path */
	(void) memcpy(var_name, fen_path_oid, oid_len);
	(void) snmp_varlist_add_variable(&notification_vars, var_name,
	    var_len, ASN_OCTET_STR, path, strlen(path));

	/* Send the trap */
	send_enterprise_trap_vars(SNMP_TRAP_ENTERPRISESPECIFIC,
	    fen_trap_oid[fen_trap_len - 1], (oid *)fen_trap_oid,
	    fen_trap_len - 2, notification_vars);
	DEBUGMSGTL((modname, "sent trap for %s\n", path));
	snmp_free_varbind(notification_vars);
}

static void *
event_thread(void *arg __unused)
{
	port_event_t pe;
	struct fdwatch *fdw;
	file_obj_t *fop;

	DEBUGMSGTL((modname, "event thread starting\n"));

	for (;;) {
		if (port_get(port, &pe, NULL) != 0)
			break;

		/* Just in case */
		if (pe.portev_source != PORT_SOURCE_FILE)
			continue;

		fdw = (struct fdwatch *)pe.portev_user;
		fop = &fdw->fo;

		if (fdw->isdir) {
			struct fdwatch *nfdw;
			bool dwatch = false;

			/*
			 * This is based on the events specified in
			 * port_fop_vnevent():
			 *
			 * VE_CREATE		MODIFIED|ATTRIB|TRUNC
			 * VE_RENAME_DEST_DIR	MODIFIED|ATTRIB
			 */
			if (pe.portev_events !=
			    (FILE_MODIFIED|FILE_ATTRIB|FILE_TRUNC) &&
			    pe.portev_events !=
			    (FILE_MODIFIED|FILE_ATTRIB)) {
				/* Add the watch back */
				DEBUGMSGTL((modname, "events=0x%x\n",
				    pe.portev_events));
				(void) add_watch(fdw);
				continue;
			}

			/* Directory file create event */
			STAILQ_FOREACH(nfdw, &fdwhead, fdwatches) {
				struct stat sb;
				char *dpath;

				if (nfdw->isdir)
					continue;

				if (!nfdw->exists &&
				    stat(nfdw->fo.fo_name, &sb) == 0) {
					fen_action_t action = FEN_CREATE;

					DEBUGMSGTL((modname,
					    "file %s (re)created\n",
					    nfdw->fo.fo_name));
					send_trap(nfdw->fo.fo_name, action);
					nfdw->exists = true;
					(void) add_watch(nfdw);
					continue;
				}
				if (nfdw->exists || dwatch)
					continue;
				dpath = sdirname(nfdw->fo.fo_name);
				if (strcmp(dpath, fop->fo_name) == 0)
					dwatch = true;
				free(dpath);
			}
			if (dwatch) {
				/*
				 * Some files in the same directory still
				 * missing; add it back to watch list.
				 */
				(void) add_watch(fdw);
			} else {
				/* Directory watch object not needed anymore */
				free_wdir(fdw);
			}
			continue;
		}

		if (pe.portev_events == FILE_RENAME_TO ||
		    pe.portev_events == FILE_MODIFIED) {
			DEBUGMSGTL((modname, "file %s modified\n",
			    fop->fo_name));
			send_trap(fop->fo_name, FEN_MODIFY);
		} else if (pe.portev_events == FILE_RENAME_FROM) {
			DEBUGMSGTL((modname, "file %s renamed\n",
			    fop->fo_name));
			fdw->exists = false;
			send_trap(fop->fo_name, FEN_RENAME);
		} else if (pe.portev_events == FILE_DELETE) {
			DEBUGMSGTL((modname, "file %s deleted\n",
			    fop->fo_name));
			fdw->exists = false;
			send_trap(fop->fo_name, FEN_DELETE);
		}

		(void) add_watch(fdw);
	}

	DEBUGMSGTL((modname, "event thread exiting\n"));

	return (NULL);
}

void
init_fen(void)
{
	FILE *conf;
	char *ptr = NULL;
	size_t cap = 0;

	(void) gethostname(hostname, MAXHOSTNAMELEN + 1);

	if ((conf = fopen(CONFPATH, "r")) == NULL) {
		DEBUGMSGTL((modname, "config file %s missing, exiting\n",
			CONFPATH));
		return;
	}

	port = port_create();
	VERIFY3S(port, >, 0);

	STAILQ_INIT(&fdwhead);
	while (getline(&ptr, &cap, conf) != -1) {
		struct fdwatch *fdw;
		char *nl;

		if (*ptr == '#')
			continue;
		if ((nl = strrchr(ptr, '\n')) != NULL)
			*nl = '\0';

		fdw = calloc(1, sizeof (*fdw));
		VERIFY3P(fdw, !=, NULL);
		fdw->fo.fo_name = strdup(ptr);
		VERIFY3P(fdw->fo.fo_name, !=, NULL);
		fdw->isdir = false;
		fdw->exists = true;

		if (add_watch(fdw) == 0)
			STAILQ_INSERT_TAIL(&fdwhead, fdw, fdwatches);
	}
	free(ptr);

	if (STAILQ_EMPTY(&fdwhead)) {
		DEBUGMSGTL((modname, "no valid file entries found, exiting\n"));
		return;
	}

	pthread_create(&event_tid, NULL, event_thread, NULL);
	pthread_detach(event_tid);
}

void
deinit_fen(void)
{
	close(port);
}
