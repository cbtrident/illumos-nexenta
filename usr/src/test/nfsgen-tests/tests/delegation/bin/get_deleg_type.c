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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* get_deleg_type.c part of Delegation C testcases */

#include <stdio.h>
#include <fcntl.h>
#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>

extern int	_nfssys(int, void *);

int
main(int argc, char **argv)
{
	int fd;
	struct nfs4_svc_args nsa;
	int dt;

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		perror("open failed");
		return (-1);
	}

	nsa.fd = fd;
	nsa.cmd = NFS4_DQUERY;
	nsa.netid = (char *)&dt;

	if (_nfssys(NFS4_SVC, &nsa)) {
		perror("nfssys NFS4_SVC");
		return (-1);
	} else
		printf("%d\n", dt);
	return (dt);
}
