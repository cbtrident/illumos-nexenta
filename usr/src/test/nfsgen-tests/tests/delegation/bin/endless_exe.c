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

/* endless_exe.c part of delegation C testcases */

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>

extern int	_nfssys(int, void *);

#define	OK	0

/*
 * Main test loop.
 */

int
main(int argc, char **argv)
{
	int i = 0;
	int j = 0;
	int delay = 1;
	int fd;
	struct nfs4_svc_args nsa;

	if (argc > 1)
		delay = atoi(argv[1]);

	if ((fd = open(argv[0], O_RDONLY)) < 0) {
		perror("open() failed");
		i = -1;
	} else {
		nsa.fd = fd;
		nsa.cmd = NFS4_DQUERY;
		nsa.netid = (char *)&i;

		if (_nfssys(NFS4_SVC, &nsa)) {
			perror("ERROR: nfssys NFS4_SVC");
			i = -1;
		} else {
			printf("delegation type granted: <%d>\n", i);
			fflush(stdout);
			close(1);
		}
	}

	if (i > 0)
		while (j++ < delay)
			sleep(1);

	return (i);
}
