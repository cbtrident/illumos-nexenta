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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/modctl.h>
#include <sys/vnode.h>
#include <sys/sysmacros.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/kobj.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cladm.h>

/*
 * The module reads the content of /etc/cluster/nodeid
 * and returns the node id in the cluster environment.
 *
 * The delivered /etc/cluster/nodeid file has the following as
 * the first line:
 * "# Used by NFS HA system.  Do not edit by hand." and will be
 * skipped when read.  Module expects to read the nodeid after
 * the header line.
 */
#define CL_MAX_NODEID	2
#define CL_NODEID_FILE	"/etc/cluster/nodeid"
#define CL_FILE_HDR_LEN	47

static nodeid_t	nid;

static struct modlmisc modlmisc = {
	&mod_miscops, "NFSv4 HA Module"
};

static struct modlinkage modlink = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
clboot_modload(struct modctl *mp)
{
	/*
	 * Return mod id for now
	 */
	return (mp->mod_id);
}

int
clboot_loadrootmodules(void)
{
	return (0);
}

int
clboot_rootconf(void)
{
	return (0);
}

void
clboot_mountroot(void)
{
	return;
}

void
clconf_init(void)
{
	return;
}

/*
 * Called by NFS HA 
 */
nodeid_t
clconf_get_nodeid(void)
{
	return (nid);
}

nodeid_t
clconf_maximum_nodeid(void)
{
	return (CL_MAX_NODEID);
}

void
cluster(void)
{
	return;
}

int
_init(void) {
	int	e;
	int	idx;
	char	*buf = NULL;
	struct _buf	*f;
	uint64_t	fsz;
	int	rc = 0;
	int	rdsz, hdr = CL_FILE_HDR_LEN;

	if ((e = mod_install(&modlink))){
		return (e);
	}

	if ((f = kobj_open_file(CL_NODEID_FILE)) == (struct _buf *)-1 ) {
		cmn_err(CE_WARN, "Fail to open %s", CL_NODEID_FILE);
		return (ENOENT);
	}

	/*
	 * Check file size
	 */
	if ((kobj_get_filesize(f, &fsz) != 0) || fsz == 0) {
		cmn_err(CE_WARN, "Fails to retrieve the file size for %s", CL_NODEID_FILE);
		kobj_close_file(f);
		return (EINVAL);
	}

	/*
	 * We expect node id follows the file header
	 */
	if ((rdsz = ((int)fsz - hdr)) <= 0) {
		cmn_err(CE_WARN, "The node id is not correctly configured");
		kobj_close_file(f);
		return (ENOENT);	
	}

	/*
	 * Assume we have a node id
	 */
	buf = kmem_alloc(rdsz, KM_SLEEP);

	/*
	 * Read in node id
	 */
	if (kobj_read_file(f, buf, rdsz, hdr) < 0) {
		cmn_err(CE_WARN, "Fail to read %s", CL_NODEID_FILE);
		rc = EIO;
		goto out;
	}

	/*
	 * Check for any invalid char
	 */
	for (idx = 0; idx < (rdsz - 1); idx++) {
		if (buf[idx] >= '0' && buf[idx] <= '9') {
			continue;
		} else {
			cmn_err(CE_WARN, "Invalid node id detected");
			rc = EINVAL;
			goto out;
		}
	}

	/*
	 * Set the global node id base 10
	 */
	if (ddi_strtoul(buf, NULL, 10, (ulong_t *)&nid) != 0) {
		cmn_err(CE_WARN, "Fail to get cluster node id");
		rc = EFAULT;	
		goto out;
	}

	/*
	 * Is node id out of range?
	 */
	if (nid > CL_MAX_NODEID || nid == 0) {
		cmn_err(CE_NOTE, "Node ID is out of range");
		rc = EFAULT;	
		goto out;
	}
	
	cluster_bootflags |= CLUSTER_CONFIGURED;

out:
	kmem_free(buf, rdsz);
	(void) kobj_close_file(f);
	return (rc);
}

/*
 * _info function
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlink, modinfop));
}
