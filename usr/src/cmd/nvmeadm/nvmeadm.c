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
 * Copyright 2016 Nexenta Systems, Inc.
 */

/*
 * nvmeadm -- NVMe administration utility
 *
 * nvmeadm [-v] [-d] [-h] <command> [<controller>[/<namespace>]] [args]
 * commands:	list
 *		identify
 *		get-logpage <logpage name>
 *		get-feature <feature>
 *		get-features
 *		create-namespace ...
 *		destroy-namespace ...
 *		get-param ...
 *		set-param ...
 *		load-firmware ...
 *		activate-firmware ...
 *		write-uncorrectable ...
 *		secure-erase ...
 *		crypto-erase ...
 *		compare ...
 *		compare-and-write ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <err.h>
#include <sys/sunddi.h>
#include <libdevinfo.h>

#include <sys/nvme.h>

#include "nvmeadm.h"

typedef struct nvme_process_arg nvme_process_arg_t;
typedef struct nvme_feature nvme_feature_t;
typedef struct nvmeadm_cmd nvmeadm_cmd_t;

struct nvme_process_arg {
	int npa_argc;
	char **npa_argv;
	char *npa_name;
	uint32_t npa_nsid;
	boolean_t npa_isns;
	const nvmeadm_cmd_t *npa_cmd;
	di_node_t npa_node;
	di_minor_t npa_minor;
	nvme_identify_ctrl_t *npa_idctl;
	nvme_identify_nsid_t *npa_idns;
	nvme_version_t *npa_version;
};

struct nvme_feature {
	char *f_name;
	char *f_short;
	uint8_t f_feature;
	size_t f_bufsize;
	uint_t f_getflags;
	int (*f_get)(int, const nvme_feature_t *, nvme_identify_ctrl_t *);
	void (*f_print)(uint64_t, void *, size_t, nvme_identify_ctrl_t *);
};

#define	NVMEADM_CTRL	1
#define	NVMEADM_NS	2
#define	NVMEADM_BOTH	(NVMEADM_CTRL | NVMEADM_NS)

struct nvmeadm_cmd {
	char *c_name;
	char *c_desc;
	int (*c_func)(int, const nvme_process_arg_t *);
};


static void usage(const nvmeadm_cmd_t *);
static void nvme_walk(nvme_process_arg_t *);
static boolean_t nvme_match(nvme_process_arg_t *);

static int nvme_process(di_node_t, di_minor_t, void *);

static int do_list(int, const nvme_process_arg_t *);
static int do_identify(int, const nvme_process_arg_t *);
static int do_get_logpage_error(int, uint32_t, nvme_identify_ctrl_t *);
static int do_get_logpage_health(int, uint32_t, nvme_identify_ctrl_t *);
static int do_get_logpage_fwslot(int, uint32_t);
static int do_get_logpage(int, const nvme_process_arg_t *);
static int do_get_feat_common(int, const nvme_feature_t *,
    nvme_identify_ctrl_t *);
static int do_get_feat_intr_vect(int, const nvme_feature_t *,
    nvme_identify_ctrl_t *);
static int do_get_feature(int, const nvme_process_arg_t *);
static int do_get_features(int, const nvme_process_arg_t *);

int verbose;
int debug;
int found;
static int exitcode;

static const nvmeadm_cmd_t nvmeadm_cmds[] = {
	{ "list", "list controllers and namespaces",
	    do_list },
	{ "identify", "identify controller or namespace",
	    do_identify },
	{ "get-logpage", "get a log page from controller or namespace",
	    do_get_logpage },
	{ "get-feature", "get feature from controller or namespace",
	    do_get_feature },
	{ "get-features", "get all features from controller or namespace",
	    do_get_features},
	{ NULL, NULL, NULL }
};

static const nvme_feature_t features[] = {
	{ "Arbitration", "",
	    NVME_FEAT_ARBITRATION, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_arbitration },
	{ "Power Management", "",
	    NVME_FEAT_POWER_MGMT, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_power_mgmt },
	{ "LBA Range Type", "range",
	    NVME_FEAT_LBA_RANGE, NVME_LBA_RANGE_BUFSIZE, NVMEADM_NS,
	    do_get_feat_common, nvme_print_feat_lba_range },
	{ "Temperature Threshold", "",
	    NVME_FEAT_TEMPERATURE, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_temperature },
	{ "Error Recovery", "",
	    NVME_FEAT_ERROR, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_error },
	{ "Volatile Write Cache", "cache",
	    NVME_FEAT_WRITE_CACHE, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_write_cache },
	{ "Number of Queues", "queues",
	    NVME_FEAT_NQUEUES, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_nqueues },
	{ "Interrupt Coalescing", "coalescing",
	    NVME_FEAT_INTR_COAL, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_intr_coal },
	{ "Interrupt Vector Configuration", "vector",
	    NVME_FEAT_INTR_VECT, 0, NVMEADM_CTRL,
	    do_get_feat_intr_vect, nvme_print_feat_intr_vect },
	{ "Write Atomicity", "atomicity",
	    NVME_FEAT_WRITE_ATOM, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_write_atom },
	{ "Asynchronous Event Configuration", "event",
	    NVME_FEAT_ASYNC_EVENT, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_async_event },
	{ "Autonomous Power State Transition", "",
	    NVME_FEAT_AUTO_PST, NVME_AUTO_PST_BUFSIZE, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_auto_pst },
	{ "Software Progress Marker", "progress",
	    NVME_FEAT_PROGRESS, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_progress },
	{ NULL, NULL, 0, 0, B_FALSE, NULL }
};


int
main(int argc, char **argv)
{
	int c;
	extern int optind;
	const nvmeadm_cmd_t *cmd;
	nvme_process_arg_t npa = { 0 };
	int help = 0;
	char *tmp;

	while ((c = getopt(argc, argv, "dhv")) != -1) {
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
			help++;
			break;
		case '?':
			usage(NULL);
			exit(-1);
		}
	}

	if (optind == argc) {
		usage(NULL);
		if (help)
			exit(0);
		else
			exit(-1);
	}

	/* Look up the specified command in the command table. */
	for (cmd = &nvmeadm_cmds[0]; cmd->c_name != NULL; cmd++)
		if (strcmp(cmd->c_name, argv[optind]) == 0)
			break;

	if (cmd->c_name == NULL) {
		usage(NULL);
		exit(-1);
	}

	if (help) {
		usage(cmd);
		exit(0);
	}

	npa.npa_cmd = cmd;

	optind++;

	/*
	 * Store the controller name and try to parse the namespace id,
	 * if one was specified.
	 */
	if (optind != argc && (strncmp(argv[optind], "nvme", 4) == 0)) {
		npa.npa_name = argv[optind++];

		tmp = strchr(npa.npa_name, '/');
		if (tmp != NULL) {
			*tmp++ = '\0';
			errno = 0;
			npa.npa_nsid = strtoul(tmp, NULL, 10);
			if (errno != 0)
				err(-1, "invalid namespace %s", tmp);
			if (npa.npa_nsid == 0)
				errx(-1, "invalid namespace %s", tmp);
			npa.npa_isns = B_TRUE;
		}
	} else {
		/*
		 * All commands but "list" require a ctrl/nsid argument.
		 */
		if (cmd->c_func != do_list) {
			warnx("missing controller/namespace name");
			usage(cmd);
			exit(-1);
		}
	}

	/* Store the remaining arguments for use by the command. */
	npa.npa_argc = argc - optind;
	npa.npa_argv = &argv[optind];

	nvme_walk(&npa);

	if (found == 0) {
		if (npa.npa_name != NULL) {
			errx(-1, "%s%.*s%.*d: no such controller or namespace",
			    npa.npa_name, npa.npa_nsid > 0 ? 1 : 0, "/",
			    npa.npa_nsid > 0 ?
			    snprintf(NULL, 0, "%d", npa.npa_nsid) :
			    0, npa.npa_nsid);
		} else {
			errx(-1, "no controllers found");
		}
	}

	exit(exitcode);
}

static void
usage(const nvmeadm_cmd_t *cmd)
{
	(void) fprintf(stderr, "usage:\t%s -h %s\n", getprogname(),
	    cmd != NULL ? cmd->c_name : "[<command>]");
	(void) fprintf(stderr, "\t%s [-dv] ", getprogname());

	if (cmd != NULL) {
		cmd->c_func(0, NULL);
	} else {
		(void) fprintf(stderr,
		    "<command> <controller>[/<namespace>] [<args>]\n");
		(void) fprintf(stderr,
		    "  Manage NVMe controllers and namespaces.\n");
		(void) fprintf(stderr, "commands:\n");

		for (cmd = &nvmeadm_cmds[0]; cmd->c_name != NULL; cmd++)
			(void) fprintf(stderr, "  %-15s - %s\n",
			    cmd->c_name, cmd->c_desc);
	}
	(void) fprintf(stderr, "parameters:\n"
	    "  -h  print usage information\n"
	    "  -d  print information useful for debugging %s\n"
	    "  -v  print verbose information\n", getprogname());
}

static boolean_t
nvme_match(nvme_process_arg_t *npa)
{
	char *name;
	uint32_t nsid = 0;

	if (npa->npa_name == NULL)
		return (B_TRUE);

	if (asprintf(&name, "%s%d", di_driver_name(npa->npa_node),
	    di_instance(npa->npa_node)) < 0)
		err(-1, "nvme_match()");

	if (strcmp(name, npa->npa_name) != 0) {
		free(name);
		return (B_FALSE);
	}

	free(name);

	if (npa->npa_isns) {
		if (npa->npa_nsid == 0)
			return (B_TRUE);
		nsid = strtoul(di_minor_name(npa->npa_minor), NULL, 10);
	}

	if (npa->npa_isns && npa->npa_nsid != nsid)
		return (B_FALSE);

	return (B_TRUE);
}


static int
nvme_process(di_node_t node, di_minor_t minor, void *arg)
{
	nvme_process_arg_t *npa = arg;
	int fd;

	npa->npa_node = node;
	npa->npa_minor = minor;

	if (!nvme_match(npa))
		return (DI_WALK_CONTINUE);

	if ((fd = nvme_open(minor)) < 0)
		return (DI_WALK_TERMINATE);

	found++;

	npa->npa_idctl = nvme_identify_ctrl(fd);
	npa->npa_version = nvme_version(fd);

	if (npa->npa_idctl == NULL)
		return (DI_WALK_TERMINATE);

	if (npa->npa_isns) {
		npa->npa_idns = nvme_identify_nsid(fd);

		if (npa->npa_idns == NULL)
			return (DI_WALK_TERMINATE);
	}

	exitcode += npa->npa_cmd->c_func(fd, npa);

	free(npa->npa_version);
	free(npa->npa_idctl);
	if (npa->npa_nsid)
		free(npa->npa_idns);

	nvme_close(fd);

	return (DI_WALK_CONTINUE);
}

static void
nvme_walk(nvme_process_arg_t *npa)
{
	di_node_t node;
	char *minor_nodetype = DDI_NT_NVME_NEXUS;

	if ((node = di_init("/", DINFOSUBTREE | DINFOMINOR)) == NULL)
		err(-1, "nvme_walk()");

	if (npa->npa_isns)
		minor_nodetype = DDI_NT_NVME_ATTACHMENT_POINT;

	(void) di_walk_minor(node, minor_nodetype, 0, npa, nvme_process);
	di_fini(node);
}

static int
do_list_nsid(int fd, const nvme_process_arg_t *npa)
{
	_NOTE(ARGUNUSED(fd));

	(void) printf("  %s/%s: ",
	    npa->npa_name, di_minor_name(npa->npa_minor));
	nvme_print_nsid_summary(npa->npa_idns);

	return (0);
}

static int
do_list(int fd, const nvme_process_arg_t *npa)
{
	_NOTE(ARGUNUSED(fd));

	nvme_process_arg_t ns_npa = { 0 };
	nvmeadm_cmd_t cmd = { 0 };
	char *name;

	if (npa == NULL) {
		(void) fprintf(stderr,
		    "list [<controller>[/<namespace>]]\n"
		    "  List NVMe controllers and their namespaces. If no "
		    "controller or namespace is\n  specified, all controllers "
		    "and namespaces in the system will be listed.\n");
		return (0);
	}

	if (asprintf(&name, "%s%d", di_driver_name(npa->npa_node),
	    di_instance(npa->npa_node)) < 0)
		err(-1, "do_list()");

	(void) printf("%s: ", name);
	nvme_print_ctrl_summary(npa->npa_idctl, npa->npa_version);

	ns_npa.npa_name = name;
	ns_npa.npa_isns = B_TRUE;
	cmd = *(npa->npa_cmd);
	cmd.c_func = do_list_nsid;
	ns_npa.npa_cmd = &cmd;

	nvme_walk(&ns_npa);

	return (exitcode);
}

static int
do_identify(int fd, const nvme_process_arg_t *npa)
{
	if (npa == NULL) {
		(void) fprintf(stderr,
		    "identify <controller>[/<namespace>]\n"
		    "  Print detailed information about a NVMe controller or "
		    "a namespace of a NVMe\n  controller.\n");
		return (0);
	}

	if (npa->npa_nsid == 0) {
		nvme_capabilities_t *cap;

		cap = nvme_capabilities(fd);
		if (cap == NULL)
			return (-1);

		nvme_print_identify_ctrl(npa->npa_idctl, cap, npa->npa_version);

		free(cap);
	} else {
		nvme_print_identify_nsid(npa->npa_idns, npa->npa_version);
	}

	return (0);
}

static int
do_get_logpage_error(int fd, uint32_t nsid, nvme_identify_ctrl_t *idctl)
{
	int nlog = idctl->id_elpe + 1;
	size_t bufsize = sizeof (nvme_error_log_entry_t) * nlog;
	nvme_error_log_entry_t *elog;

	if (nsid != 0)
		errx(-1, "Error Log not available on a per-namespace basis");

	elog = nvme_get_logpage(fd, NVME_LOGPAGE_ERROR, &bufsize);

	if (elog == NULL)
		return (-1);

	nlog = bufsize / sizeof (nvme_error_log_entry_t);

	nvme_print_error_log(nlog, elog);

	free(elog);

	return (0);
}

static int
do_get_logpage_health(int fd, uint32_t nsid, nvme_identify_ctrl_t *idctl)
{
	size_t bufsize = sizeof (nvme_health_log_t);
	nvme_health_log_t *hlog;

	if (nsid != 0)
		if (idctl->id_lpa.lp_smart == 0)
			errx(-1, "SMART/Health information not available "
			    "on a per-namespace basis on this controller");

	hlog = nvme_get_logpage(fd, NVME_LOGPAGE_HEALTH, &bufsize);

	if (hlog == NULL)
		return (-1);

	nvme_print_health_log(hlog, idctl);

	free(hlog);

	return (0);
}

static int
do_get_logpage_fwslot(int fd, uint32_t nsid)
{
	size_t bufsize = sizeof (nvme_fwslot_log_t);
	nvme_fwslot_log_t *fwlog;

	if (nsid != 0)
		errx(-1, "Firmware Slot information not available on a "
		    "per-namespace basis");

	fwlog = nvme_get_logpage(fd, NVME_LOGPAGE_FWSLOT, &bufsize);

	if (fwlog == NULL)
		return (-1);

	nvme_print_fwslot_log(fwlog);

	free(fwlog);

	return (0);
}

static int
do_get_logpage(int fd, const nvme_process_arg_t *npa)
{
	int ret = 0;

	if (npa == NULL) {
		(void) fprintf(stderr,
		    "get-logpage <controller>[/<namespace>] <logpage>\n"
		    "  Print the specified log page of a NVMe controller. "
		    "Supported log pages are:\n"
		    "  error, health, and firmware\n");
		return (0);
	}

	if (npa->npa_argc < 1) {
		warnx("missing logpage name");
		usage(npa->npa_cmd);
		exit(-1);
	}

	if (strcmp(npa->npa_argv[0], "error") == 0)
		ret = do_get_logpage_error(fd, npa->npa_nsid, npa->npa_idctl);
	else if (strcmp(npa->npa_argv[0], "health") == 0)
		ret = do_get_logpage_health(fd, npa->npa_nsid, npa->npa_idctl);
	else if (strcmp(npa->npa_argv[0], "firmware") == 0)
		ret = do_get_logpage_fwslot(fd, npa->npa_nsid);
	else
		errx(-1, "invalid log page: %s", npa->npa_argv[0]);

	return (ret);
}

static int
do_get_feat_common(int fd, const nvme_feature_t *feat,
    nvme_identify_ctrl_t *idctl)
{
	void *buf = NULL;
	size_t bufsize = feat->f_bufsize;
	uint64_t res;

	if (nvme_get_feature(fd, feat->f_feature, 0, &res, &bufsize, &buf)
	    == B_FALSE)
		return (EINVAL);

	nvme_print(0, feat->f_name, 0, NULL);
	feat->f_print(res, buf, bufsize, idctl);
	free(buf);

	return (0);
}

static int
do_get_feat_intr_vect(int fd, const nvme_feature_t *feat,
    nvme_identify_ctrl_t *idctl)
{
	uint64_t res;
	uint64_t arg;
	int intr_cnt;

	nvme_print(0, feat->f_name, 0, NULL);

	intr_cnt = nvme_intr_cnt(fd);

	if (intr_cnt == -1)
		return (EINVAL);

	for (arg = 0; arg < intr_cnt; arg++) {
		if (nvme_get_feature(fd, feat->f_feature, arg, &res, NULL, NULL)
		    == B_FALSE)
			return (EINVAL);

		feat->f_print(res, NULL, 0, idctl);
	}

	return (0);
}

static int
do_get_feature(int fd, const nvme_process_arg_t *npa)
{
	const nvme_feature_t *feat;

	if (npa == NULL) {
		(void) fprintf(stderr,
		    "get-feature <controller>[/<namespace>] <feature>\n"
		    "  Print the specified feature of a NVMe controller or a "
		    "namespace. Supported\n  features are:\n");
		(void) fprintf(stderr, "    %-35s %-14s %s\n",
		    "FEATURE NAME", "SHORT NAME", "CONTROLLER/NAMESPACE");
		for (feat = &features[0]; feat->f_feature != 0; feat++) {
			char *type;

			if ((feat->f_getflags & NVMEADM_BOTH) == NVMEADM_BOTH)
				type = "both";
			else if ((feat->f_getflags & NVMEADM_CTRL) != 0)
				type = "controller only";
			else
				type = "namespace only";

			(void) fprintf(stderr, "    %-35s %-14s %s\n",
			    feat->f_name, feat->f_short, type);
		}

		return (0);
	}

	if (npa->npa_argc < 1) {
		warnx("missing feature name");
		usage(npa->npa_cmd);
		exit(-1);
	}

	for (feat = &features[0]; feat->f_feature != 0; feat++) {
		if (strncasecmp(feat->f_name, npa->npa_argv[0],
		    strlen(npa->npa_argv[0])) == 0 ||
		    strncasecmp(feat->f_short, npa->npa_argv[0],
		    strlen(npa->npa_argv[0])) == 0)
			break;
	}

	if (feat->f_feature == 0)
		errx(-1, "unknown feature %s", npa->npa_argv[0]);

	if ((npa->npa_nsid != 0 && (feat->f_getflags & NVMEADM_NS) == 0) ||
	    (npa->npa_nsid == 0 && (feat->f_getflags & NVMEADM_CTRL) == 0))
		errx(-1, "feature %s %s supported for "
		    "namespaces", feat->f_name,
		    (feat->f_getflags & NVMEADM_NS) != 0 ? "only" : "not");

	if (feat->f_get(fd, feat, npa->npa_idctl) != 0)
		errx(-1, "unsupported feature: %s", feat->f_name);

	return (0);
}

static int
do_get_features(int fd, const nvme_process_arg_t *npa)
{
	const nvme_feature_t *feat;

	if (npa == NULL) {
		(void) fprintf(stderr,
		    "get-features <controller>[/<namespace>]\n"
		    "  Print all supported features of a NVMe "
		    "controller or a namespace.\n");
		return (0);
	}

	if (npa->npa_argc > 0)
		errx(-1, "unexpected arguments");

	for (feat = &features[0]; feat->f_feature != 0; feat++) {
		if ((npa->npa_nsid != 0 &&
		    (feat->f_getflags & NVMEADM_NS) == 0) ||
		    (npa->npa_nsid == 0 &&
		    (feat->f_getflags & NVMEADM_CTRL) == 0))
			continue;

		(void) feat->f_get(fd, feat, npa->npa_idctl);
	}

	return (0);
}
