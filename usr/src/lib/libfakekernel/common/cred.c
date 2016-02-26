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


#include <sys/types.h>
#include <sys/time.h>
#include <sys/thread.h>
#include <sys/cred.h>
#include <sys/sid.h>
#include <strings.h>

struct cred {
	uint32_t	pad[100];
};

cred_t cred0;
cred_t *kcred = &cred0;
ksiddomain_t ksdom0 = {0, 0, "public", {0}};
ksid_t ksid0 = {0, 0, 0, &ksdom0};

cred_t *
_curcred(void)
{
	/* Thread-specific data? */
	return (&cred0);
}

/*ARGSUSED*/
void
crfree(cred_t *cr)
{
}

/*ARGSUSED*/
void
crhold(cred_t *cr)
{
}

/*ARGSUSED*/
uid_t
crgetuid(const cred_t *cr)
{
	return (0);
}

cred_t *
zone_kcred(void)
{
	return (kcred);
}

/*ARGSUSED*/
ksid_t *
crgetsid(const cred_t *cr, int i)
{
	return (&ksid0);
}
