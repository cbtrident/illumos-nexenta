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

#define	BUFF_32k 32*1024

#define	MIN(a, b) ((a) < (b) ? (a) : (b))

void usage(int);
void fill_buffer(char *, int);
void mk_file(char *, int, char *, int);
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
	puts("\t -u <u.g>       Uid(u) and Gid(g) to become (numeric value)\n");
	puts("\t -d <dbg>       Information level: 0 - none \n"
	    "\t                                  1 - errors \n"
	    "\t                                  2 - errors and debug\n");
	puts("\t -b <base_dir>  The directory under which to create files\n");
	puts("\t -s <fsize>     The size to make the files created\n");
	puts("\t -n <ocnt>      Number of files to create and open\n");
	puts("\t -l             Skip the locking test\n");
	puts("\t -v             Skip the file content validation test\n");
	puts("\t -W <tc_nap>    Pause period (in seconds)  \n"
	    "\t -S <num>       Scenario number \n");
	exit(ec);
}

/*
 * For a buffer "ptr" fill it with a numerically
 * increasing byte value for the entire "size"
 * of the buffer.
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
 * the data described by "buf" and size then close the file.
 */
void
mk_file(char *path, int file_flags, char *buf, int size)
{
	int fd, rc;

	/*
	 * create and open a file
	 */
	if ((fd = open_file(path, file_flags, 0777)) < 0) {
		fprintf(stderr, "\t Test  UNINITIATED: ");
		exit(NOOK);
	}

	if ((rc = write(fd, buf, size)) != size) {
		fprintf(stderr, "\t Test UNINITIATED: ");
		fprintf(stderr, "error on write (%d)\n", errno);
		close_file(fd, path);
		exit(NOOK);
	}
	close(fd);
}

/*
 * Close all the files.
 */
void
cls_file(int fds[], int file_opens)
{
	int c;
	char  fileGumbo[25];

	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		close_file(fds[c], fileGumbo);
	}
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
 * For each "file_opens" file descriptors in array "fds"
 * open the file, acquire a write lock then fork a child
 * that hammers to get a write lock, in the meantime the
 * parent sleeps for "parent_sleep" time, wakes up and
 * releases the initial write lock and waits for the
 * child to exit.
 */
int
s1(int *fds, int file_opens, int parent_sleep, char *buffy)
{
	char fileGumbo[35];
	int  stat;
	pid_t kid;
	int   c, s;

	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		fds[c] = open_file(fileGumbo, O_RDWR, 0);
		if (fds[c] < 0) {
			fprintf(stderr, "\t Test FAIL: ");
			eprint("EEK!.. open failed");
			return (-1);
		} else {
			/* parent will lock file first.. */
			if (lock_reg(fds[c], 0,  F_WRLCK, 0, 0, 0) != OK) {
				/* error */
				fprintf(stderr, "\t Test FAIL: ");
				eprint("lock: not acquired\n");
				return (-1);
			}

			if ((kid = fork()) == 0) {
				/*
				 * kid spins till parent sleep time
				 * exhaused..
				 * but try not to print the conflict lock error.
				 */
				s = showerror;
				if (debug == 0)
					showerror = 0;
				while (lock_reg(fds[c], 0, F_WRLCK,
				    0, 0, 0) != OK) {
					if (errno != EAGAIN) {
						fprintf(stderr,
						    "\t Test FAIL: ");
						Perror("Child: WRLCK");
						exit(1);
					}
				}
				showerror = s;

				if (lock_reg(fds[c], 0, F_UNLCK, 0, 0,
				    0) != OK) {
					fprintf(stderr, "\t Test FAIL: ");
					eprint("Child: unlock failed\n");
					exit(2);
				}
				/* kid delete it */
				unlink(fileGumbo);
				exit(0);
			} else {
				/* parent.. */

				sleep(parent_sleep);
				if (lock_reg(fds[c], 0, F_UNLCK, 0, 0,
				    0) != OK) {
					fprintf(stderr, "\t Test FAIL: ");
					eprint("unlock failed\n");
				}
				/* hang about for the kid .. */
				wait(&stat);
			}
		}
		/* and now.. parent deletes it */
		unlink(fileGumbo);
	}
	printf("\t Test PASS: successfully completed execution runs.\n");

	return (0);
}

/*
 * For "file_opens" file descriptors in "fds" open the file
 * read donly, close it and open it write only, close it and
 * then open it read only finally close and unlink it.
 */
void
s2(int *fds, int file_opens)
{
	int c;
	char fileGumbo[35];

	dprint("Opening files O_RDONLY: ");
	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		fds[c] = open_file(fileGumbo, O_RDONLY, 0);
		if (fds[c] < 0) {
			fprintf(stderr, "\t Test FAIL: ");
			eprint("0001 EEK!.. open failed (%s)\n",
			    fileGumbo);
		}
	}
	dprint("OK\n");

	cls_file(fds, file_opens);

	dprint("Reopening files O_WRONLY: ");
	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		fds[c] = open_file(fileGumbo, O_WRONLY, 0);
		if (fds[c] < 0) {
			fprintf(stderr, "\t Test FAIL: ");
			eprint("0002 EEK!.. open(O_WRONLY) failed (%s)\n",
			    fileGumbo);
		}
	}
	dprint("OK\n");

	cls_file(fds, file_opens);

	dprint("Reopening files O_RDONLY: ");
	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		fds[c] = open_file(fileGumbo, O_RDONLY, 0);
		if (fds[c] < 0) {
			fprintf(stderr, "\t Test FAIL: ");
			eprint("0003 EEK!.. open(O_RDONLY) failed (%s)\n",
			    fileGumbo);
		}
	}
	dprint("OK\n");

	dprint("Close and unlink files: ");
	for (c = 0; c < file_opens; c++) {
		close(fds[c]);
		sprintf(fileGumbo, "F%06d", c);
		unlink(fileGumbo);
	}
	dprint("OK\n");

	printf("\t Test PASS: successfully completed execution runs.\n");
}

/*
 * For "file_opens" file descriptors in "fds" open the file
 * read/write read_lock the entire file, write_lock the
 * first anad last 1024 bytes, release the 1st read_lock,
 * get a write_lock on thte rest of thte file (middle bit)
 * unlock everythihng and delete file.
 *
 */
void
s3(int *fds, int file_opens)
{
	int c;
	char fileGumbo[35];

	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		fds[c] = open_file(fileGumbo, O_RDWR, 0);
		if (fds[c] < 0) {
			fprintf(stderr, "\t Test FAIL: ");
			eprint("0001 EEK!.. open failed (%s)\n",
			    fileGumbo);
		}
	}

	for (c = 0; c < file_opens; c++) {
		/* Get a read lock for the entire file. */
		if (lock_reg(fds[c], 0, F_RDLCK, 0, 0, 0) != OK) {
			/* error */
			fprintf(stderr, "\t Test FAIL: ");
			eprint("read lock not acquired (F%06d)\n", c);
			return;
		}
		/* now write lock for last 1024 bytes of the file */
		if (lock_reg(fds[c], 0,  F_WRLCK, 0, SEEK_END, -1024) != OK) {
			/* error */
			fprintf(stderr, "\t Test FAIL: ");
			eprint("wrirte lock last 1k not acquired (F%06d)\n", c);
			return;
		}

		/* now a write lock for first 1024 bytes. */
		if (lock_reg(fds[c], 0,  F_WRLCK, 0, SEEK_SET, 1024) != OK) {
			/* error */
			fprintf(stderr, "\t Test FAIL: ");
			eprint("write lock first 1k not acquired (F%06d)\n", c);
			return;
		}

		/* release thte read lock */
		if (lock_reg(fds[c], 0,  F_UNLCK, 0, 0, 0) != OK) {
			/* error */
			fprintf(stderr, "\t Test FAIL: ");
			eprint("unlock failed (F%06d) for read lock\n", c);
			return;
		}

		/* get a write lock for the middle of the file.. */
		if (lock_reg(fds[c], 0,  F_WRLCK, 1024+1, SEEK_SET,
		    (BUFF_32k-(2048+1))) != OK) {
			/* error */
			fprintf(stderr, "\t Test FAIL: ");
			eprint("write lock middle chunk not "
			    "acquired (F%06d)\n", c);
			return;
		}
		if (lock_reg(fds[c], 0,  F_UNLCK, 0, SEEK_END, -1024) != OK) {
			/* error */
			fprintf(stderr, "\t Test FAIL: ");
			eprint("wrirte lock last 1k not acquired (F%06d)\n", c);
			return;
		}

		/* now a write lock for first 1024 bytes. */
		if (lock_reg(fds[c], 0,  F_UNLCK, 0, SEEK_SET, 1024) != OK) {
			/* error */
			fprintf(stderr, "\t Test FAIL: ");
			eprint("write lock first 1k not acquired (F%06d)\n", c);
			return;
		}
		/* get a write lock for the middle of the file.. */
		if (lock_reg(fds[c], 0, F_UNLCK, 1024+1, SEEK_SET,
		    (BUFF_32k-(2048+1))) != OK) {
			/* error */
			fprintf(stderr, "\t Test FAIL: ");
			eprint("write lock middle chunk not "
			    "acquired (F%06d)\n", c);
			return;
		}
		close(fds[c]);
	}
	/* now run 'n delete 'em.. */
	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		unlink(fileGumbo);
	}

	printf("\t Test PASS: successfully completed execution runs.\n");
}
/*
 * For each "file_opens" file descriptors in array "fds"
 * open the file, acquire a write lock then unlink the
 * file _without_ a close.
 */
void
s4(int *fds, int file_opens)
{
	char fileGumbo[35];
	int c;

	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		fds[c] = open_file(fileGumbo, O_RDWR, 0);
		if (fds[c] < 0) {
			fprintf(stderr, "\t Test FAIL: ");
			printf("EEK!.. open failed");
		} else {
			/*  lock file  */
			if (lock_reg(fds[c], 0, F_WRLCK, 0, 0, 0) != OK) {
				/* error */
				fprintf(stderr, "\t Test FAIL: ");
				eprint("lock: not acquired\n");
			}
			/* yank out thte file without a close() */
			unlink(fileGumbo);
		}
	}
	printf("\t Test PASS: successfully completed execution runs.\n");
}

/*
 * Main test loop.
 */
int
main(int  argc, char *argv[])
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
	int   stressTest = 0;

	struct rlimit rlp;

	testname = argv[0];

	while ((c = getopt(argc, argv, "S:d:b:s:n:hW:lv")) != -1) {

		switch (c) {
		/* sez which stress test to do.. */
		case 'S':
			stressTest = atoi(optarg);
			break;
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
		 * debug flags treated as bit field for
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
		case 'h':
			usage(0);
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

	dprint("RLMIT_NOFILE is cur=%d / max=%d\n",
	    rlp.rlim_cur, rlp.rlim_max);

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
			file_opens =  rlp.rlim_cur-3;

		if (setrlimit(RLIMIT_NOFILE, &rlp) < 0) {
			fprintf(stderr, "\t Test  UNINITIATED: ");
			eprint("setrlimit() for RLIMIT_NOFILE failed\n");
			Perror(":-/");
			return (-1);
		}
	}

	fill_buffer(buffy, BUFF_32k);

	if (chdir(base_dir) != 0) {
		fprintf(stderr, "\t Test  UNINITIATED: ");
		eprint("chdir() to %s failed\n");
		Perror("chdir()");
		return (-1);
	}

	/*
	 * generate file names and files.
	 */
	dprint("Generating files: ");
	for (c = 0; c < file_opens; c++) {
		sprintf(fileGumbo, "F%06d", c);
		mk_file(fileGumbo, file_flags, buffy, BUFF_32k);
	}
	dprint("OK.\n");

	if ((fds = malloc(sizeof (int)*file_opens)) == NULL) {
		printf("\t Test UNRESOLVED: ");
		eprint("malloc for RLIMIT_NOFILE fds failed\n");
		Perror(":-(");
		return (-1);
	}

	switch (stressTest) {
	case 1:
		starttime(
		    "\n st_0003{a}: stress conflict lock until "
		    "child gets the lock\n\t ");
		s1(fds, file_opens, nap_time, buffy);
		printf("\t ==> Going to create and open %d files with "
		    "%d processes.\n", file_opens, file_opens);
		endtime("         ");
		break;
	case 2:
		starttime(
		    "\n st_0003{b}: stress open/close files with "
		    "RDONLY and WRONLY\n\t ");
		printf("\t ==> Going to create and open %d files.\n",
		    file_opens);
		s2(fds, file_opens);
		endtime("         ");
		break;
	case 3:
		starttime(
		    "\n st_0003{d}: stress read/write lock with "
		    "different boundary\n\t ");
		printf("\t ==> Going to create and open %d files.\n",
		    file_opens);
		s3(fds, file_opens);
		endtime("         ");
		break;
	case 4:
		starttime(
		    "\n st_0003{c}: stress unlink WRLCK files "
		    "without a close\n\t ");
		printf("\t ==> Going to create and open %d files.\n",
		    file_opens);
		s4(fds, file_opens);
		endtime("         ");
		break;
	}

	return (0);
}
