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
 * a program to open/create a named attribute file, write some data;
 * then wait for recovery to continue reading back the written data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/errno.h>

#define	BUFSIZE	1024

extern int errno;

void prnusage();
void cleanup();

int
main(int argc, char **argv)
{
	char	*filename = NULL;
	char	*donefile = NULL;
	char	*attrfile = "attribute";
	char	*wbuf = NULL;
	char	*rbuf = NULL;
	int	fd = -1;
	int	afd = -1;
	int	jfd = -1;
	int	i, c;

	while ((c = getopt(argc, argv, "f:u:")) != EOF) {
		switch (c) {
		case 'f':
			filename = optarg;
			break;
		case 'u':
			donefile = optarg;
			break;
		case '?':
		default:
			prnusage(argv[0]);
		}
	}

	if ((filename == NULL) || (*filename == '\0')) {
		(void) fprintf(stderr,
		    "%s: No test filename specified\n", argv[0]);
		prnusage(argv[0]);
	}

	if ((donefile == NULL) || (*donefile == '\0')) {
		(void) fprintf(stderr,
		    "%s: No DONE filename specified\n", argv[0]);
		prnusage(argv[0]);
	}

	(void) fprintf(stdout, "Testing starts: filename=%s, donefile=%s\n",
	    filename, donefile);

	if ((fd = open(filename, O_CREAT|O_RDWR, 0777)) < 0) {
		(void) fprintf(stderr,
		    "Failed to open file: <%s>", filename);
		perror(" ");
		exit(errno);
	}
	(void) fprintf(stdout, "  open(%s) OK\n", filename);

	/* build the write buffer for the file */
	if ((wbuf = malloc(sizeof (char) * BUFSIZE)) == NULL) {
		perror("malloc(wbuf)");
		cleanup(fd, afd, wbuf, errno);
	}
	for (i = 0; i < BUFSIZE; i++)
		wbuf[i] = (i % 26) + 'a';

	if (write(fd, wbuf, BUFSIZE) < BUFSIZE) {
		(void) fprintf(stderr,
		    "Failed to write to file: <%s>", filename);
		perror(" ");
		cleanup(fd, afd, wbuf, 2);
	}
	(void) fprintf(stdout, "  write(%s) OK\n", filename);

	afd = openat(fd, attrfile, O_CREAT | O_RDWR | O_XATTR, 0777);
	if (afd < 0) {
		(void) fprintf(stderr,
		    "Failed to openat <%s>\n, attrfile");
		perror("openat(fd, \"attribute\", O_CREAT | O_RDWR | O_XATTR, "
		    "0777))");
		cleanup(fd, afd, wbuf, errno);
	}
	(void) fprintf(stdout, "  openat(%s) OK\n", attrfile);

	if ((c = write(afd, wbuf, BUFSIZE)) < BUFSIZE) {
		(void) fprintf(stderr,
		    "Failed to write to <%s> file", attrfile);
		perror(" ");
		cleanup(fd, afd, wbuf, 3);
	}
	(void) fprintf(stdout, "  write(%s) OK\n", attrfile);

	/* just to make sure data are written to be read */
	if ((fsync(afd)) < 0) {
		(void) fprintf(stderr,
		    "Failed to write to <%s> file", attrfile);
		perror(" ");
		cleanup(fd, afd, wbuf, 3);
	}
	(void) fprintf(stdout, "  fsync(%s) OK\n", attrfile);

	/* now let's wait for the recovery, and break after 5 min */
	c = 0;
	while ((jfd = open(donefile, O_RDONLY)) < 0) {
		sleep(1);
		c++;
		if (c > 300) {
			(void) fprintf(stdout,
			"  Failed to open(%s)\n", donefile);
			(void) fprintf(stdout,
			"  problem with client recovery.\n");
			exit(6);
		}
	}
	if (jfd > 0)
		close(jfd);
	(void) fprintf(stdout, "  open(%s) OK, server came back.\n", donefile);

	/* and try to read-back the file data after we recovered */
	if ((lseek(afd, 0, SEEK_SET)) < 0) {
		(void) fprintf(stderr, "lseek(0) failed");
		perror(" ");
		cleanup(fd, afd, wbuf, 5);
	}
	(void) fprintf(stdout, "  lseek(%s) OK\n", attrfile);

	if ((rbuf = malloc(sizeof (char) * BUFSIZE)) == NULL) {
		perror("malloc(rbuf)");
		cleanup(fd, afd, wbuf, errno);
	}

	if ((c = read(afd, rbuf, BUFSIZE)) != BUFSIZE) {
		(void) fprintf(stderr,
		    "Failed to read to attribute file after we are recover");
		perror(" ");
		(void) fprintf(stderr, "Only %d bytes read\n", c);
		cleanup(fd, afd, wbuf, 2);
	}
	(void) fprintf(stdout, "  read(%s) OK, read %d bytes\n", attrfile, c);

	for (i = 0; i < BUFSIZE; i++) {
		if (rbuf[i] != wbuf[i]) {
			(void) fprintf(stderr,
			    "Failed to read the right pattern at %d; ", i);
			(void) fprintf(stderr,
			    "expected=(%ll), got=(%ll)\n", wbuf[i], rbuf[i]);
			if (rbuf != NULL)
				free(rbuf);
			cleanup(fd, afd, wbuf, i);
		}
	}
	(void) fprintf(stdout, "  comparing data OK, i=%d\n", i);
	(void) fprintf(stdout, "GOOD, testing is successful.\n");

	if (rbuf != NULL)
		free(rbuf);

	cleanup(fd, afd, wbuf, 0);

	return (0);
}

void
prnusage(char *pname)
{
	(void) fprintf(stderr,
	    "Usage: %s -f <filename> -u <DONE_reboot|DONE_reset file>\n",
	    pname);
	exit(99);
}

void
cleanup(int fd, int afd, char *bufp, int exitcode)
{
	if (fd != -1)
		(void) close(fd);
	if (afd != -1)
		(void) close(afd);
	if (bufp != NULL)
		free(bufp);

	exit(exitcode);
}
