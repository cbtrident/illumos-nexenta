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

#include "nfsgen.h"

char	*testname;

#define	TESTCASE "Stress create, write, close, sleep, open, and delete\n\t "
#define	BUFF_32k 32*1024

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

void usage(int);
void fill_buffer(char *, int);
int  mk_file(char *, int, char *, int);
void ck_file(int, int, char *);
void ck_locking(int, int);

/*
 * Prints out the usage message and exits with the
 * passed in exit code "ec"
 */
void
usage(int ec)
{
	printf("\t Test UNINITIATED: ");

	printf("usage: %s -u <u.g>  -d <dbg> -b <base_dir> -s <fsize> \n"
	    "          -n <ocnt> -l -v -W <tc_nap>\n", testname);
	puts("\t -u <u.g>      Uid (u) & Gid (g) to become (numeric value)\n");
	puts("\t -d <dbg>      Information level: 0 - none \n"
	    "\t                                  1 - errors \n"
	    "\t                                  2 - errors and debug\n");
	puts("\t -b <base_dir> The directory under which to create files\n");
	puts("\t -s <fsize>    The size to make the files created\n");
	puts("\t -n <ocnt>     Number of files to create and open\n");
	puts("\t -l            Skip the locking test\n");
	puts("\t -v            Skip the file content validation test\n");
	puts("\t -W <tc_nap>   Pause period (in seconds) between \n"
	    "\t               create/clsoe and open/lock/validate/unlink\n");
	exit(ec);
}

/*
 * Given a buffer pointer "ptr" fill it with a numerically
 * increasing byte value for its "size"
 */
void
fill_buffer(char *ptr, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		ptr[i] = (i & 0xff);
	}
}

/*
 * Create a file using "path" and "file_flags" then write
 * the data described by "buf" and size.
 *
 * Returns: Open file descritor.
 */
int
mk_file(char *path, int file_flags, char *buf, int size)
{
	int fd, rc;

	/*
	 * create and open a file
	 */
	if ((fd = open_file(path, file_flags, 0777)) < 0) {
		printf("\t Test UNINITIATED: open_file() failed\n");
		return (NOOK);
	}

	if ((rc = write(fd, buf, size)) != size) {
		printf("\t Test UNINITIATED: ");
		eprint("error on write (%d)\n", errno);
		close_file(fd, path);
		return (NOOK);
	}
	return (fd);
}

/*
 * The intent is to verify that the file "fd" still matches
 * "buffy" which is a 32k buffer setup by fill_buffer for
 * the size of the file "file_size".
 */
void
ck_file(int fd, int file_size, char *buffy)
{
	int  blk = 0, rc, wc, fs = file_size;
	char yffub[BUFF_32k];


	do {
		/*
		 * compare in 32k blocks.
		 */
		wc = MIN(fs, BUFF_32k);

		if ((rc = read(fd, yffub, wc)) != wc) {
			fprintf(stderr, "\t Test FAIL: ");
			Perror("read():");
			exit(NOOK);
		}

		if ((rc = memcmp(buffy, yffub, wc)) != 0) {
			fprintf(stderr, "\t Test FAIL: ");
			eprint("(rc=%d) written != read "
			    " in 32k blk @offset %d\n",
			    rc, blk);
			exit(NOOK);
		}
		blk += wc;
		fs -= wc;
	} while (fs);
}

/*
 * First accuire a write lock on "fd" for the entire file.
 * Then fork a child to hammer away attempting to accuire
 * a write lock on thte same file. In the meantime the
 * parent sleeps for 5 seconds
 */
void
ck_locking(int fd, int mand)
{
	int  stat, s;
	pid_t kid;

	/* parent will lock file first.. */
	if (lock_reg(fd, mand,  F_WRLCK, 0, 0, 0) != OK) {
		/* error */
		fprintf(stderr, "\t Test FAIL: ");
		eprint("lock: not acquired\n");
		return;
	}

	if ((kid = fork()) == 0) {		/* child.. */
		/* try not to print the conflict lock error on debug=1 */
		s = showerror;
		if (debug == 0)
			showerror = 0;
		/* try conflict lock until parent release the lock */
		while (lock_reg(fd, mand, F_WRLCK, 0, 0, 0) != OK) {
			if (errno != EAGAIN) {
				fprintf(stderr, "\t Test FAIL: ");
				Perror("Child: WRLCK");
			}
		}
		showerror = s;

		if (lock_reg(fd, mand, F_UNLCK, 0, 0, 0) != OK) {
			fprintf(stderr, "\t Test FAIL: ");
			eprint("Child: unlock failed\n");
		}
		exit(0);
	} else {				/* parent.. */
		sleep(5);
		if (lock_reg(fd, mand, F_UNLCK, 0, 0, 0) != OK) {
			fprintf(stderr, "\t Test FAIL: ");
			eprint("unlock failed\n");
		}
		/* hang about for the kid .. */
		wait(&stat);
	}
}



/*
 * Main test loop.
 */
int
main(int argc, char *argv[])
{
	extern int  optind;
	extern char *optarg;

	char  buffy[BUFF_32k];
	char  fileGumbo[25];

	char  *buf, *base_dir = NULL;

	int   *fds, c;

	int   do_lock_checking = 1, do_content_validation = 1, nap_time = 30;

	int   file_opens = 250;
	int   file_size  = BUFF_32k;
	int   file_flags = (O_CREAT|O_TRUNC|O_RDWR);
	int   mand = 0;

	struct rlimit rlp;

	testname = argv[0];
	printf("\n %s: ", testname);
	starttime(TESTCASE);

	while ((c = getopt(argc, argv, "W:d:b:s:n:lv")) != -1) {

		switch (c) {
		/* Skip the lock checks */
		case 'l':
			do_lock_checking = 0;
			break;
		/* Skip the content validation */
		case 'v':
			do_content_validation = 0;
			break;
		/* number of files to open */
		case 'n':
			file_opens = atoi(optarg);
			break;
		/* the size of a file */
		case 's':
			file_size = atoi(optarg);
			break;
		/* base directory into which chdir and create files */
		case 'b':
			base_dir = optarg;
			break;
		/*
		 * debug flags treated as bit flags for
		 * debug and showerror
		 */
		case 'd':
			switch (atoi(optarg)) {
			case 0:
				debug = 0;
				showerror = 0;
				break;
			case 1:
				debug = 0;
				showerror = 1;
				break;
			case 2:
				debug = 1;
				showerror = 1;
				break;
			default:
				usage(-1);
			}
			break;

		/* the user wants me to nap... */
		case 'W':
			nap_time = atoi(optarg);
			break;
		default:
			usage(-1);
		}
	}

	if (base_dir == NULL) {
		fprintf(stderr, "\t Test  UNINITIATED: ");
		printf(" specify base directory via -b\n");
		usage(-1);
	}

	if (getrlimit(RLIMIT_NOFILE, &rlp) < 0) {
		fprintf(stderr, "\t Test  UNINITIATED: ");
		eprint("getrlimit() for RLIMIT_NOFILE failed\n");
		Perror(":-(");
		return (-1);
	}

	dprint("RLMIT_NOFILE is cur=%d / max=%d\n", rlp.rlim_cur, rlp.rlim_max);

	/*
	 * The user has specified a number of files to open.
	 * We may have to increase the process limit for MAX
	 * open files.  We also need to account for the fact
	 * that the process already has 3 open file descriptors
	 * for std{in,our,err}.
	 */
	if (file_opens+3 > rlp.rlim_cur) {
		rlp.rlim_cur = MIN(rlp.rlim_max, file_opens+3);
		if (rlp.rlim_cur <= file_opens)
			file_opens = rlp.rlim_cur-3;

		if (setrlimit(RLIMIT_NOFILE, &rlp) < 0) {
			eprint("setrlimit() for RLIMIT_NOFILE failed\n");
			Perror(":-/");
			return (-1);
		}
	}

	fill_buffer(buffy, BUFF_32k);

	if (chdir(base_dir) != 0) {
		fprintf(stderr, "\t Test  UNINITIATED: ");
		eprint("chdir() to %s failed\n", base_dir);
		Perror("chdir()");
		return (-1);
	}

	if ((fds = malloc(sizeof (int)*file_opens)) == NULL) {
		fprintf(stderr, "\t Test  UNINITIATED: ");
		eprint("malloc for RLIMIT_NOFILE fds failed\n");
		Perror(":-(");
		return (-1);
	}

	/*
	 * generate file names and files.
	 */
	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		fds[c] = mk_file(fileGumbo, file_flags, buffy, BUFF_32k);
	}

	/*
	 * Close all the files.
	 */
	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		close_file(fds[c], fileGumbo);
	}

	/*
	 * Take a nap if the user wants ya to..
	 */
	if (nap_time) {
		sleep(nap_time);
	}

	/*
	 * Now re-open the files and check the contents.
	 */
	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		fds[c] = open_file(fileGumbo, O_RDWR, 0);
		if (fds[c] < 0) {
			eprint("EEK!.. open failed");
		} else {
			/*
			 *  Optionally perform some locking checks.
			 */
			if (do_lock_checking) {
				ck_locking(fds[c], mand);
			}
			/*
			 * Do optional content validation
			 */
			if (do_content_validation) {
				ck_file(fds[c], file_size, &buffy[0]);
			}
		}
		/* and now.. delete it without clsoe (it a test) */
		unlink(fileGumbo);
	}

	printf("\t ==> Going to create and open %d files.\n", file_opens);

	printf("\t Test PASS: ");
	printf("%s completed execution runs.\n", testname);
	endtime("         ");

	return (0);
}
