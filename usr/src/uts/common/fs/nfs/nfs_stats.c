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
 * Copyright 2020 Nexenta by DDN Inc.  All rights reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/zone.h>
#include <sys/kmem.h>
#include <sys/systm.h>

#include <nfs/nfs.h>
#include <nfs/nfs4_kprot.h>

/*
 * Key to retrieve per-zone data corresponding to NFS kstats consumed by
 * nfsstat(1m).  These is only used for the client-side stats.
 */
zone_key_t nfsstat_zone_key;

/*
 * Convenience routine to create a named kstat associated with zoneid, named
 * module:0:name:"misc", using the provided template to initialize the names
 * and values of the stats.
 */
static kstat_named_t *
nfsstat_zone_init_common(zoneid_t zoneid, const char *module, int vers,
    const char *name, const kstat_named_t *template,
    size_t template_size)
{
	kstat_t *ksp;
	kstat_named_t *ks_data;

	ks_data = kmem_alloc(template_size, KM_SLEEP);
	bcopy(template, ks_data, template_size);
	if ((ksp = kstat_create_zone(module, vers, name, "misc",
	    KSTAT_TYPE_NAMED, template_size / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE, zoneid)) != NULL) {
		ksp->ks_data = ks_data;
		kstat_install(ksp);
	}
	return (ks_data);
}

/*
 * Convenience routine to remove a kstat in specified zone with name
 * module:0:name.
 */
static void
nfsstat_zone_fini_common(zoneid_t zoneid, const char *module, int vers,
    const char *name)
{
	kstat_delete_byname_zone(module, vers, name, zoneid);
}

/*
 * Server statistics.  These are defined here, rather than in the server
 * code, so that they can be referenced before the nfssrv kmod is loaded.
 *
 * The "calls" counter is a Contract Private interface covered by
 * PSARC/2001/357.  Please contact contract-2001-357-01@eng.sun.com before
 * making any changes.
 */

static const kstat_named_t svstat_tmpl[] = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "referrals",	KSTAT_DATA_UINT64 },
	{ "referlinks",	KSTAT_DATA_UINT64 },
};

static void
nfsstat_zone_init_server(zoneid_t zoneid, kstat_named_t *svstatp[])
{
	int vers;

	for (vers = NFS_VERSION; vers <= NFS_V4; vers++) {
		svstatp[vers] = nfsstat_zone_init_common(zoneid, "nfs", vers,
		    "nfs_server", svstat_tmpl, sizeof (svstat_tmpl));
	}
}

static void
nfsstat_zone_fini_server(zoneid_t zoneid, kstat_named_t *svstatp[])
{
	int vers;
	for (vers = NFS_VERSION; vers <= NFS_V4; vers++) {
		nfsstat_zone_fini_common(zoneid, "nfs", vers, "nfs_server");
		kmem_free(svstatp[vers], sizeof (svstat_tmpl));
	}
}

/*
 * Support functions for the kstat_io alloc/free
 */
static kstat_t **
rfs_kstat_io_init(zoneid_t zoneid, const char *module, int instance,
    const char *name, const char *class, const kstat_named_t *tmpl, int count,
    kmutex_t *lock)
{
	int i;
	kstat_t **ret = kmem_alloc(count * sizeof (*ret), KM_SLEEP);

	for (i = 0; i < count; i++) {
		char namebuf[KSTAT_STRLEN];

		(void) snprintf(namebuf, sizeof (namebuf), "%s_%s", name,
		    tmpl[i].name);
		ret[i] = kstat_create_zone(module, instance, namebuf, class,
		    KSTAT_TYPE_IO, 1, 0, zoneid);
		if (ret[i] != NULL) {
			ret[i]->ks_lock = lock;
			kstat_install(ret[i]);
		}
	}

	return (ret);
}

static void
rfs_kstat_io_delete(kstat_t **ks, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (ks[i] != NULL) {
			kstat_delete(ks[i]);
			ks[i] = NULL;
		}
	}
}

static void
rfs_kstat_io_free(kstat_t **ks, int count)
{
	rfs_kstat_io_delete(ks, count);
	kmem_free(ks, count * sizeof (*ks));
}

/*
 * NFSv2 client stats
 */
static const kstat_named_t rfsreqcnt_v2_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getattr",	KSTAT_DATA_UINT64 },
	{ "setattr",	KSTAT_DATA_UINT64 },
	{ "root",	KSTAT_DATA_UINT64 },
	{ "lookup",	KSTAT_DATA_UINT64 },
	{ "readlink",	KSTAT_DATA_UINT64 },
	{ "read",	KSTAT_DATA_UINT64 },
	{ "wrcache",	KSTAT_DATA_UINT64 },
	{ "write",	KSTAT_DATA_UINT64 },
	{ "create",	KSTAT_DATA_UINT64 },
	{ "remove",	KSTAT_DATA_UINT64 },
	{ "rename",	KSTAT_DATA_UINT64 },
	{ "link",	KSTAT_DATA_UINT64 },
	{ "symlink",	KSTAT_DATA_UINT64 },
	{ "mkdir",	KSTAT_DATA_UINT64 },
	{ "rmdir",	KSTAT_DATA_UINT64 },
	{ "readdir",	KSTAT_DATA_UINT64 },
	{ "statfs",	KSTAT_DATA_UINT64 }
};

static void
nfsstat_zone_init_rfsreq_v2(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	statsp->rfsreqcnt_ptr = nfsstat_zone_init_common(zoneid, "nfs", 0,
	    "rfsreqcnt_v2", rfsreqcnt_v2_tmpl, sizeof (rfsreqcnt_v2_tmpl));
}

static void
nfsstat_zone_fini_rfsreq_v2(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	nfsstat_zone_fini_common(zoneid, "nfs", 0, "rfsreqcnt_v2");
	kmem_free(statsp->rfsreqcnt_ptr, sizeof (rfsreqcnt_v2_tmpl));
}

/*
 * NFSv2 server stats
 */
static const kstat_named_t rfsproccnt_v2_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getattr",	KSTAT_DATA_UINT64 },
	{ "setattr",	KSTAT_DATA_UINT64 },
	{ "root",	KSTAT_DATA_UINT64 },
	{ "lookup",	KSTAT_DATA_UINT64 },
	{ "readlink",	KSTAT_DATA_UINT64 },
	{ "read",	KSTAT_DATA_UINT64 },
	{ "wrcache",	KSTAT_DATA_UINT64 },
	{ "write",	KSTAT_DATA_UINT64 },
	{ "create",	KSTAT_DATA_UINT64 },
	{ "remove",	KSTAT_DATA_UINT64 },
	{ "rename",	KSTAT_DATA_UINT64 },
	{ "link",	KSTAT_DATA_UINT64 },
	{ "symlink",	KSTAT_DATA_UINT64 },
	{ "mkdir",	KSTAT_DATA_UINT64 },
	{ "rmdir",	KSTAT_DATA_UINT64 },
	{ "readdir",	KSTAT_DATA_UINT64 },
	{ "statfs",	KSTAT_DATA_UINT64 }
};

/*
 * NFSv2 client ACL stats
 */
static const kstat_named_t aclreqcnt_v2_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getacl",	KSTAT_DATA_UINT64 },
	{ "setacl",	KSTAT_DATA_UINT64 },
	{ "getattr",	KSTAT_DATA_UINT64 },
	{ "access",	KSTAT_DATA_UINT64 },
	{ "getxattrdir",	KSTAT_DATA_UINT64 }
};

static void
nfsstat_zone_init_aclreq_v2(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	statsp->aclreqcnt_ptr = nfsstat_zone_init_common(zoneid, "nfs_acl", 0,
	    "aclreqcnt_v2", aclreqcnt_v2_tmpl, sizeof (aclreqcnt_v2_tmpl));
}

static void
nfsstat_zone_fini_aclreq_v2(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	nfsstat_zone_fini_common(zoneid, "nfs_acl", 0, "aclreqcnt_v2");
	kmem_free(statsp->aclreqcnt_ptr, sizeof (aclreqcnt_v2_tmpl));
}

/*
 * NFSv2 server ACL stats
 */
static const kstat_named_t aclproccnt_v2_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getacl",	KSTAT_DATA_UINT64 },
	{ "setacl",	KSTAT_DATA_UINT64 },
	{ "getattr",	KSTAT_DATA_UINT64 },
	{ "access",	KSTAT_DATA_UINT64 },
	{ "getxattrdir",	KSTAT_DATA_UINT64 }
};

/*
 * NFSv3 client stats
 */
static const kstat_named_t rfsreqcnt_v3_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getattr",	KSTAT_DATA_UINT64 },
	{ "setattr",	KSTAT_DATA_UINT64 },
	{ "lookup",	KSTAT_DATA_UINT64 },
	{ "access",	KSTAT_DATA_UINT64 },
	{ "readlink",	KSTAT_DATA_UINT64 },
	{ "read",	KSTAT_DATA_UINT64 },
	{ "write",	KSTAT_DATA_UINT64 },
	{ "create",	KSTAT_DATA_UINT64 },
	{ "mkdir",	KSTAT_DATA_UINT64 },
	{ "symlink",	KSTAT_DATA_UINT64 },
	{ "mknod",	KSTAT_DATA_UINT64 },
	{ "remove",	KSTAT_DATA_UINT64 },
	{ "rmdir",	KSTAT_DATA_UINT64 },
	{ "rename",	KSTAT_DATA_UINT64 },
	{ "link",	KSTAT_DATA_UINT64 },
	{ "readdir",	KSTAT_DATA_UINT64 },
	{ "readdirplus", KSTAT_DATA_UINT64 },
	{ "fsstat",	KSTAT_DATA_UINT64 },
	{ "fsinfo",	KSTAT_DATA_UINT64 },
	{ "pathconf",	KSTAT_DATA_UINT64 },
	{ "commit",	KSTAT_DATA_UINT64 }
};

static void
nfsstat_zone_init_rfsreq_v3(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	statsp->rfsreqcnt_ptr = nfsstat_zone_init_common(zoneid, "nfs", 0,
	    "rfsreqcnt_v3", rfsreqcnt_v3_tmpl, sizeof (rfsreqcnt_v3_tmpl));
}

static void
nfsstat_zone_fini_rfsreq_v3(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	nfsstat_zone_fini_common(zoneid, "nfs", 0, "rfsreqcnt_v3");
	kmem_free(statsp->rfsreqcnt_ptr, sizeof (rfsreqcnt_v3_tmpl));
}

/*
 * NFSv3 server stats
 */
static const kstat_named_t rfsproccnt_v3_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getattr",	KSTAT_DATA_UINT64 },
	{ "setattr",	KSTAT_DATA_UINT64 },
	{ "lookup",	KSTAT_DATA_UINT64 },
	{ "access",	KSTAT_DATA_UINT64 },
	{ "readlink",	KSTAT_DATA_UINT64 },
	{ "read",	KSTAT_DATA_UINT64 },
	{ "write",	KSTAT_DATA_UINT64 },
	{ "create",	KSTAT_DATA_UINT64 },
	{ "mkdir",	KSTAT_DATA_UINT64 },
	{ "symlink",	KSTAT_DATA_UINT64 },
	{ "mknod",	KSTAT_DATA_UINT64 },
	{ "remove",	KSTAT_DATA_UINT64 },
	{ "rmdir",	KSTAT_DATA_UINT64 },
	{ "rename",	KSTAT_DATA_UINT64 },
	{ "link",	KSTAT_DATA_UINT64 },
	{ "readdir",	KSTAT_DATA_UINT64 },
	{ "readdirplus", KSTAT_DATA_UINT64 },
	{ "fsstat",	KSTAT_DATA_UINT64 },
	{ "fsinfo",	KSTAT_DATA_UINT64 },
	{ "pathconf",	KSTAT_DATA_UINT64 },
	{ "commit",	KSTAT_DATA_UINT64 }
};

/*
 * NFSv3 client ACL stats
 */
static const kstat_named_t aclreqcnt_v3_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getacl",	KSTAT_DATA_UINT64 },
	{ "setacl",	KSTAT_DATA_UINT64 },
	{ "getxattrdir",	KSTAT_DATA_UINT64 }
};

static void
nfsstat_zone_init_aclreq_v3(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	statsp->aclreqcnt_ptr = nfsstat_zone_init_common(zoneid, "nfs_acl", 0,
	    "aclreqcnt_v3", aclreqcnt_v3_tmpl, sizeof (aclreqcnt_v3_tmpl));
}

static void
nfsstat_zone_fini_aclreq_v3(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	nfsstat_zone_fini_common(zoneid, "nfs_acl", 0, "aclreqcnt_v3");
	kmem_free(statsp->aclreqcnt_ptr, sizeof (aclreqcnt_v3_tmpl));
}

/*
 * NFSv3 server ACL stats
 */
static const kstat_named_t aclproccnt_v3_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getacl",	KSTAT_DATA_UINT64 },
	{ "setacl",	KSTAT_DATA_UINT64 },
	{ "getxattrdir",	KSTAT_DATA_UINT64 }
};

/*
 * NFSv4 client stats
 */
static const kstat_named_t rfsreqcnt_v4_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "compound",	KSTAT_DATA_UINT64 },
	{ "reserved",	KSTAT_DATA_UINT64 },
	{ "access",	KSTAT_DATA_UINT64 },
	{ "close",	KSTAT_DATA_UINT64 },
	{ "commit",	KSTAT_DATA_UINT64 },
	{ "create",	KSTAT_DATA_UINT64 },
	{ "delegpurge",	KSTAT_DATA_UINT64 },
	{ "delegreturn",	KSTAT_DATA_UINT64 },
	{ "getattr",	KSTAT_DATA_UINT64 },
	{ "getfh",	KSTAT_DATA_UINT64 },
	{ "link",	KSTAT_DATA_UINT64 },
	{ "lock",	KSTAT_DATA_UINT64 },
	{ "lockt",	KSTAT_DATA_UINT64 },
	{ "locku",	KSTAT_DATA_UINT64 },
	{ "lookup",	KSTAT_DATA_UINT64 },
	{ "lookupp",	KSTAT_DATA_UINT64 },
	{ "nverify",	KSTAT_DATA_UINT64 },
	{ "open",	KSTAT_DATA_UINT64 },
	{ "openattr",	KSTAT_DATA_UINT64 },
	{ "open_confirm",	KSTAT_DATA_UINT64 },
	{ "open_downgrade",	KSTAT_DATA_UINT64 },
	{ "putfh",	KSTAT_DATA_UINT64 },
	{ "putpubfh",	KSTAT_DATA_UINT64 },
	{ "putrootfh",	KSTAT_DATA_UINT64 },
	{ "read",	KSTAT_DATA_UINT64 },
	{ "readdir",	KSTAT_DATA_UINT64 },
	{ "readlink",	KSTAT_DATA_UINT64 },
	{ "remove",	KSTAT_DATA_UINT64 },
	{ "rename",	KSTAT_DATA_UINT64 },
	{ "renew",	KSTAT_DATA_UINT64 },
	{ "restorefh",	KSTAT_DATA_UINT64 },
	{ "savefh",	KSTAT_DATA_UINT64 },
	{ "secinfo",	KSTAT_DATA_UINT64 },
	{ "setattr",	KSTAT_DATA_UINT64 },
	{ "setclientid",	KSTAT_DATA_UINT64 },
	{ "setclientid_confirm",	KSTAT_DATA_UINT64 },
	{ "verify", KSTAT_DATA_UINT64 },
	{ "write",	KSTAT_DATA_UINT64 }
};

static void
nfsstat_zone_init_rfsreq_v4(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	statsp->rfsreqcnt_ptr = nfsstat_zone_init_common(zoneid, "nfs", 0,
	    "rfsreqcnt_v4", rfsreqcnt_v4_tmpl, sizeof (rfsreqcnt_v4_tmpl));
}

static void
nfsstat_zone_fini_rfsreq_v4(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	nfsstat_zone_fini_common(zoneid, "nfs", 0, "rfsreqcnt_v4");
	kmem_free(statsp->rfsreqcnt_ptr, sizeof (rfsreqcnt_v4_tmpl));
}

/*
 * NFSv4 server stats
 */
static const kstat_named_t rfsproccnt_v4_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "compound",	KSTAT_DATA_UINT64 },
	{ "reserved",	KSTAT_DATA_UINT64 },
	{ "access",	KSTAT_DATA_UINT64 },
	{ "close",	KSTAT_DATA_UINT64 },
	{ "commit",	KSTAT_DATA_UINT64 },
	{ "create",	KSTAT_DATA_UINT64 },
	{ "delegpurge",	KSTAT_DATA_UINT64 },
	{ "delegreturn",	KSTAT_DATA_UINT64 },
	{ "getattr",	KSTAT_DATA_UINT64 },
	{ "getfh",	KSTAT_DATA_UINT64 },
	{ "link",	KSTAT_DATA_UINT64 },
	{ "lock",	KSTAT_DATA_UINT64 },
	{ "lockt",	KSTAT_DATA_UINT64 },
	{ "locku",	KSTAT_DATA_UINT64 },
	{ "lookup",	KSTAT_DATA_UINT64 },
	{ "lookupp",	KSTAT_DATA_UINT64 },
	{ "nverify",	KSTAT_DATA_UINT64 },
	{ "open",	KSTAT_DATA_UINT64 },
	{ "openattr",	KSTAT_DATA_UINT64 },
	{ "open_confirm",	KSTAT_DATA_UINT64 },
	{ "open_downgrade",	KSTAT_DATA_UINT64 },
	{ "putfh",	KSTAT_DATA_UINT64 },
	{ "putpubfh",	KSTAT_DATA_UINT64 },
	{ "putrootfh",	KSTAT_DATA_UINT64 },
	{ "read",	KSTAT_DATA_UINT64 },
	{ "readdir",	KSTAT_DATA_UINT64 },
	{ "readlink",	KSTAT_DATA_UINT64 },
	{ "remove",	KSTAT_DATA_UINT64 },
	{ "rename",	KSTAT_DATA_UINT64 },
	{ "renew",	KSTAT_DATA_UINT64 },
	{ "restorefh",	KSTAT_DATA_UINT64 },
	{ "savefh",	KSTAT_DATA_UINT64 },
	{ "secinfo",	KSTAT_DATA_UINT64 },
	{ "setattr",	KSTAT_DATA_UINT64 },
	{ "setclientid",	KSTAT_DATA_UINT64 },
	{ "setclientid_confirm",	KSTAT_DATA_UINT64 },
	{ "verify",	KSTAT_DATA_UINT64 },
	{ "write",	KSTAT_DATA_UINT64 },
	{ "release_lockowner",	KSTAT_DATA_UINT64 },
	{ "illegal",	KSTAT_DATA_UINT64 },
};

/*
 * NFSv4 client ACL stats
 */
static const kstat_named_t aclreqcnt_v4_tmpl[] = {
	{ "null",	KSTAT_DATA_UINT64 },
	{ "getacl",	KSTAT_DATA_UINT64 },
	{ "setacl",	KSTAT_DATA_UINT64 },
};

static void
nfsstat_zone_init_aclreq_v4(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	statsp->aclreqcnt_ptr = nfsstat_zone_init_common(zoneid, "nfs_acl", 0,
	    "aclreqcnt_v4", aclreqcnt_v4_tmpl, sizeof (aclreqcnt_v4_tmpl));
}

static void
nfsstat_zone_fini_aclreq_v4(zoneid_t zoneid, struct nfs_version_stats *statsp)
{
	nfsstat_zone_fini_common(zoneid, "nfs_acl", 0, "aclreqcnt_v4");
	kmem_free(statsp->aclreqcnt_ptr, sizeof (aclreqcnt_v4_tmpl));
}


/*
 * NFS server per share kstats (exp_kstats)
 * kstats are collected per share for NFSv3 & NFSv4 read and write operations.
 */
#define	NFSSRV_SHR_READ		0
#define	NFSSRV_SHR_WRITE	1

static const kstat_named_t rfsshr_tmpl[] = {
	{ "read",	KSTAT_DATA_UINT64 },	/* NFSSRV_SHR_READ */
	{ "write",	KSTAT_DATA_UINT64 }	/* NFSSRV_SHR_WRITE */
};
#define	RFSSHARE_COUNT	\
	(sizeof (rfsshr_tmpl) / sizeof (rfsshr_tmpl[0]))

/*
 * Zone initializer callback to setup the client kstats.
 * See nfs_common.c client _init code.
 */
void *
nfsstat_zone_init(zoneid_t zoneid)
{
	struct nfs_stats *nfs_stats_ptr;

	nfs_stats_ptr = kmem_zalloc(sizeof (*nfs_stats_ptr), KM_SLEEP);

	/*
	 * Initialize v2 stats
	 */
	nfsstat_zone_init_rfsreq_v2(zoneid, &nfs_stats_ptr->nfs_stats_v2);
	nfsstat_zone_init_aclreq_v2(zoneid, &nfs_stats_ptr->nfs_stats_v2);
	/*
	 * Initialize v3 stats
	 */
	nfsstat_zone_init_rfsreq_v3(zoneid, &nfs_stats_ptr->nfs_stats_v3);
	nfsstat_zone_init_aclreq_v3(zoneid, &nfs_stats_ptr->nfs_stats_v3);
	/*
	 * Initialize v4 stats
	 */
	nfsstat_zone_init_rfsreq_v4(zoneid, &nfs_stats_ptr->nfs_stats_v4);
	nfsstat_zone_init_aclreq_v4(zoneid, &nfs_stats_ptr->nfs_stats_v4);

	return (nfs_stats_ptr);
}

/*
 * Zone destructor callback to tear down the client kstats.
 * See nfs_common.c client _fini code.
 */
void
nfsstat_zone_fini(zoneid_t zoneid, void *data)
{
	struct nfs_stats *nfs_stats_ptr = data;

	/*
	 * Free v2 stats
	 */
	nfsstat_zone_fini_rfsreq_v2(zoneid, &nfs_stats_ptr->nfs_stats_v2);
	nfsstat_zone_fini_aclreq_v2(zoneid, &nfs_stats_ptr->nfs_stats_v2);
	/*
	 * Free v3 stats
	 */
	nfsstat_zone_fini_rfsreq_v3(zoneid, &nfs_stats_ptr->nfs_stats_v3);
	nfsstat_zone_fini_aclreq_v3(zoneid, &nfs_stats_ptr->nfs_stats_v3);
	/*
	 * Free v4 stats
	 */
	nfsstat_zone_fini_rfsreq_v4(zoneid, &nfs_stats_ptr->nfs_stats_v4);
	nfsstat_zone_fini_aclreq_v4(zoneid, &nfs_stats_ptr->nfs_stats_v4);

	kmem_free(nfs_stats_ptr, sizeof (*nfs_stats_ptr));
}

/*
 * Support for exp_kstats initialization and tear down
 */
struct exp_kstats *
exp_kstats_init(zoneid_t zoneid, int instance, const char *path, size_t len,
    bool_t pseudo)
{
	struct exp_kstats *exp_kstats;

	exp_kstats = kmem_alloc(sizeof (*exp_kstats), KM_SLEEP);

	mutex_init(&exp_kstats->procio_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Generic share kstat.
	 */
	exp_kstats->share_kstat = kstat_create_zone("nfs", instance, "share",
	    "misc", KSTAT_TYPE_NAMED,
	    sizeof (exp_kstats->share_kstat_data) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_VAR_SIZE, zoneid);
	if (exp_kstats->share_kstat != NULL) {
		len = strnlen(path, len);
		exp_kstats->share_path = kmem_alloc(len + 1, KM_SLEEP);
		bcopy(path, exp_kstats->share_path, len);
		exp_kstats->share_path[len] = '\0';

		exp_kstats->share_kstat->ks_data =
		    &exp_kstats->share_kstat_data;

		kstat_named_init(&exp_kstats->share_kstat_data.path, "path",
		    KSTAT_DATA_STRING);
		kstat_named_setstr(&exp_kstats->share_kstat_data.path,
		    exp_kstats->share_path);

		kstat_named_init(&exp_kstats->share_kstat_data.filesystem,
		    "filesystem", KSTAT_DATA_STRING);
		kstat_named_setstr(&exp_kstats->share_kstat_data.filesystem,
		    pseudo ? "pseudo" : "real");

		exp_kstats->share_kstat->ks_lock = &exp_kstats->procio_lock;
		kstat_install(exp_kstats->share_kstat);
	}

	/* NFS version 3 */
	exp_kstats->rfsshr_v3_ptr = rfs_kstat_io_init(zoneid, "nfs",
	    instance, "share_v3", "rfsprocio_v3", rfsshr_tmpl,
	    RFSSHARE_COUNT, &exp_kstats->procio_lock);

	/* NFS version 4 */
	exp_kstats->rfsshr_v4_ptr = rfs_kstat_io_init(zoneid, "nfs",
	    instance, "share_v4", "rfsprocio_v4", rfsshr_tmpl,
	    RFSSHARE_COUNT, &exp_kstats->procio_lock);

	return (exp_kstats);
}

void
exp_kstats_delete(struct exp_kstats *exp_kstats)
{
	if (exp_kstats == NULL)
		return;

	/* Generic share kstat */
	if (exp_kstats->share_kstat != NULL) {
		kstat_delete(exp_kstats->share_kstat);
		exp_kstats->share_kstat = NULL;
		strfree(exp_kstats->share_path);
	}

	rfs_kstat_io_delete(exp_kstats->rfsshr_v3_ptr, RFSSHARE_COUNT);
	rfs_kstat_io_delete(exp_kstats->rfsshr_v4_ptr, RFSSHARE_COUNT);

}

void
exp_kstats_fini(struct exp_kstats *exp_kstats)
{
	if (exp_kstats == NULL)
		return;

	/* Generic share kstat */
	if (exp_kstats->share_kstat != NULL) {
		kstat_delete(exp_kstats->share_kstat);
		strfree(exp_kstats->share_path);
	}

	rfs_kstat_io_free(exp_kstats->rfsshr_v3_ptr, RFSSHARE_COUNT);
	rfs_kstat_io_free(exp_kstats->rfsshr_v4_ptr, RFSSHARE_COUNT);

	mutex_destroy(&exp_kstats->procio_lock);

	kmem_free(exp_kstats, sizeof (*exp_kstats));
}

void
exp_kstats_reset(struct exp_kstats *exp_kstats, const char *path, size_t len,
    bool_t pseudo)
{
	char *old;
	char *new;

	if ((exp_kstats == NULL) || (exp_kstats->share_kstat == NULL))
		return;

	len = strnlen(path, len);
	new = kmem_alloc(len + 1, KM_SLEEP);
	bcopy(path, new, len);
	new[len] = '\0';

	mutex_enter(exp_kstats->share_kstat->ks_lock);
	old = exp_kstats->share_path;
	exp_kstats->share_path = new;
	kstat_named_setstr(&exp_kstats->share_kstat_data.path,
	    exp_kstats->share_path);
	kstat_named_setstr(&exp_kstats->share_kstat_data.filesystem,
	    pseudo ? "pseudo" : "real");
	mutex_exit(exp_kstats->share_kstat->ks_lock);

	strfree(old);
}

kstat_t *
/* LINTED E_FUNC_ARG_UNUSED */
exp_kstats_v2(struct exp_kstats *exp_kstats, uint_t op)
{
	/* No NFS v2 per-share kstats */
	return (NULL);
}

kstat_t *
exp_kstats_v3(struct exp_kstats *exp_kstats, uint_t op)
{
	if (exp_kstats == NULL)
		return (NULL);

	/* per share kstats for selected operations (read, write) only */
	switch (op) {
	case NFSPROC3_READ:
		return (exp_kstats->rfsshr_v3_ptr[NFSSRV_SHR_READ]);
	case NFSPROC3_WRITE:
		return (exp_kstats->rfsshr_v3_ptr[NFSSRV_SHR_WRITE]);
	default:
		return (NULL);
	}
}

kstat_t *
exp_kstats_v4(struct exp_kstats *exp_kstats, uint_t op)
{
	if (exp_kstats == NULL)
		return (NULL);

	/* per share kstats for selected operations (read, write) only */
	switch (op) {
	case OP_READ:
		return (exp_kstats->rfsshr_v4_ptr[NFSSRV_SHR_READ]);
	case OP_WRITE:
		return (exp_kstats->rfsshr_v4_ptr[NFSSRV_SHR_WRITE]);
	default:
		return (NULL);
	}
}

void
nfsstat_zone_init_procio(nfs_globals_t *ng, const char *module, int vers,
	const char *name, const kstat_named_t *tmpl, size_t tmpl_size)
{
	kstat_t **kspp;
	kmutex_t *lk;
	uint_t cnt = tmpl_size / sizeof (*tmpl);
	uint_t i;

	ASSERT(vers <= NFS_VERSMAX);

	/* Should be able to leave these "lock-less"! */
	lk = &ng->rfsprociolk[vers];
	mutex_init(lk, NULL, MUTEX_DEFAULT, NULL);

	kspp = rfs_kstat_io_init(ng->nfs_zoneid, module, vers,
	    name, name, tmpl, cnt, lk);
	ng->rfsprociop[vers] = kspp;
}

void
nfsstat_zone_fini_procio(nfs_globals_t *ng, int vers,
	const kstat_named_t *tmpl, size_t tmpl_size)
{
	kstat_t **kspp;
	uint_t cnt = tmpl_size / sizeof (*tmpl);

	ASSERT(vers <= NFS_VERSMAX);

	kspp = ng->rfsprociop[vers];
	ng->rfsprociop[vers] = NULL;

	if (kspp != NULL) {
		rfs_kstat_io_free(kspp, cnt);
	}
	mutex_destroy(&ng->rfsprociolk[vers]);
}

/*
 * Server side per-zone stat init
 */
void
rfs_stat_zone_init(nfs_globals_t *ng)
{
	zoneid_t zoneid = ng->nfs_zoneid;

	/* Initialize all versions of the nfs_server */
	nfsstat_zone_init_server(zoneid, ng->svstat);

	/* NFS proc counts */
	ng->rfsproccnt[NFS_V2] = nfsstat_zone_init_common(zoneid, "nfs", 0,
	    "rfsproccnt_v2", rfsproccnt_v2_tmpl, sizeof (rfsproccnt_v2_tmpl));

	ng->rfsproccnt[NFS_V3] = nfsstat_zone_init_common(zoneid, "nfs", 0,
	    "rfsproccnt_v3", rfsproccnt_v3_tmpl, sizeof (rfsproccnt_v3_tmpl));

	ng->rfsproccnt[NFS_V4] = nfsstat_zone_init_common(zoneid, "nfs", 0,
	    "rfsproccnt_v4", rfsproccnt_v4_tmpl, sizeof (rfsproccnt_v4_tmpl));

	/* ACL proc counts */
	ng->aclproccnt[NFS_V2] = nfsstat_zone_init_common(zoneid, "nfs_acl", 0,
	    "aclproccnt_v2", aclproccnt_v2_tmpl, sizeof (aclproccnt_v2_tmpl));

	ng->aclproccnt[NFS_V3] = nfsstat_zone_init_common(zoneid, "nfs_acl", 0,
	    "aclproccnt_v3", aclproccnt_v3_tmpl, sizeof (aclproccnt_v3_tmpl));

	/* NFS proc IO */
	nfsstat_zone_init_procio(ng, "nfs", NFS_V2,
	    "rfsprocio_v2", rfsproccnt_v2_tmpl, sizeof (rfsproccnt_v2_tmpl));

	nfsstat_zone_init_procio(ng, "nfs", NFS_V3,
	    "rfsprocio_v3", rfsproccnt_v3_tmpl, sizeof (rfsproccnt_v3_tmpl));

	nfsstat_zone_init_procio(ng, "nfs", NFS_V4,
	    "rfsprocio_v4", rfsproccnt_v4_tmpl, sizeof (rfsproccnt_v4_tmpl));
}

/*
 * Server side per-zone stat fini
 */
void
rfs_stat_zone_fini(nfs_globals_t *ng)
{
	zoneid_t zoneid = ng->nfs_zoneid;

	/* Free nfs:x:nfs_server stats */
	nfsstat_zone_fini_server(zoneid, ng->svstat);

	/* NFS proc counts */
	nfsstat_zone_fini_common(zoneid, "nfs", 0, "rfsproccnt_v2");
	kmem_free(ng->rfsproccnt[NFS_V2], sizeof (rfsproccnt_v2_tmpl));

	nfsstat_zone_fini_common(zoneid, "nfs", 0, "rfsproccnt_v3");
	kmem_free(ng->rfsproccnt[NFS_V3], sizeof (rfsproccnt_v3_tmpl));

	nfsstat_zone_fini_common(zoneid, "nfs", 0, "rfsproccnt_v4");
	kmem_free(ng->rfsproccnt[NFS_V4], sizeof (rfsproccnt_v4_tmpl));

	/* ACL proc counts */
	nfsstat_zone_fini_common(zoneid, "nfs_acl", 0, "aclproccnt_v2");
	kmem_free(ng->aclproccnt[NFS_V2], sizeof (aclproccnt_v2_tmpl));

	nfsstat_zone_fini_common(zoneid, "nfs_acl", 0, "aclproccnt_v3");
	kmem_free(ng->aclproccnt[NFS_V3], sizeof (aclproccnt_v3_tmpl));

	/* NFS proc IO */
	nfsstat_zone_fini_procio(ng, NFS_V2,
	    rfsproccnt_v2_tmpl, sizeof (rfsproccnt_v2_tmpl));

	nfsstat_zone_fini_procio(ng, NFS_V3,
	    rfsproccnt_v3_tmpl, sizeof (rfsproccnt_v3_tmpl));

	nfsstat_zone_fini_procio(ng, NFS_V4,
	    rfsproccnt_v4_tmpl, sizeof (rfsproccnt_v4_tmpl));
}
