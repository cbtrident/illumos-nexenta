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

/*
 * This proram is used by open_downgrade.ksh script to generate a scenario
 * where OPEN_DOWNGRADE operation is performed on a stale file handler.
 *
 * In the comments on 6282664, Eric suggested a way to generate the scenario:
 *
 *     1) client# mount server:/expor
 *     2) client# fd1 = open(file, RD_ONLY)
 *     3) client# fd2 = open(file, WR_ONLY)
 *     4) server# rm /export/file
 *     5) server# unshare /export
 *     6) server# share /export
 *     7) client# close(fd1)
 *
 * This program does step 2, 3, and 7. open_downgrade.ksh does step 1, 4, 5,
 * and 6.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

int fd1, fd2;

void
handler(int sig)
{
	switch (sig) {
	case SIGUSR1:
		/* close fd1 */
		if (close(fd1) < 0 && errno == ESTALE) {
			printf("Received NFS4ERR_STALE on close(fd1)\n");
			fflush(stdout);
		}
		fd1 = 0;

		break;
	case SIGUSR2:
		/* close fd2 */
		if (close(fd2) < 0 && errno == ESTALE) {
			printf("Received NFS4ERR_STALE on close(fd2)\n");
			fflush(stdout);
		}
		fd2 = 0;

		break;
	default:
		/* shouldn't be reached */
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: %s <filename>\n", argv[0]);
		exit(1);
	}

	(void) signal(SIGUSR1, handler);
	(void) signal(SIGUSR2, handler);

	/* open file with O_RDONLY */
	fd1 = open(argv[1], O_RDONLY);

	if (fd1 < 0) {
		perror("open(file, O_RDONLY)");
		exit(1);
	}

	/* open the same file with O_WRONLY */
	fd2 = open(argv[1], O_WRONLY);

	if (fd2 < 0) {
		perror("open(file, O_WRONLY)");
		exit(1);
	}

	printf("fd1 and fd2 were opened.\n");
	fflush(stdout);

	/* sleep until further notification */
	while (fd1 != 0 || fd2 != 0) {
		pause();
	}

	return (errno);
}
