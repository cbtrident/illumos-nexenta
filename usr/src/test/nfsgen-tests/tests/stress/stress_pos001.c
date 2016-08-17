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

#define	TESTCASE "Stress test open(), write(), read() unlink()\n\t "
#define	MIN(a, b) ((a) < (b) ? (a) : (b))
#define	BUFF_32k  (1024*32)

void usage(int);
void fill_buffer(char *, int);


/*
 * Prints out the usage message and exits with the
 * passed in exit code "ec"
 */
void
usage(int ec)
{
	printf("\t Test UNINITIATED: ");
	printf("usage: %s -F -T <tc_run> -Q <tc_nap> -I <tc_iter> \n"
	    "\t  -d <dbg>  -f <filenamae>  -s <fsize>\n", testname);
	puts("\t -F            Turn on O_SYNC flag.\n");
	puts("\t -T <tc_run>   Number of testcase runs to execute\n");
	puts("\t -Q <tc_nap>   Inter-testcase run sleep period \n");
	puts("\t -I <tc_iter>  Total number of tests per run to execute\n");
	puts("\t -d <dbg>      Information level: 0 - none \n"
	    "\t                                  1 - errors \n"
	    "\t                                  2 - errors and debug\n");
	puts("\t -f <filename> The filename to use for testing\n");
	puts("\t -s <fsize>    Size of file to create\n");

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
 * Main test loop.
 */
int
main(int  argc, char *argv[])
{
	extern int  optind;
	extern char *optarg;

	char  buffy[BUFF_32k];
	char  yffub[BUFF_32k];

	char  *buf, *filename = NULL;
	int   c, active_iter = 0, nap_time = 0, runs = 0, total_runs = 0;
	int   file_size = BUFF_32k;
	int   file_flags = (O_CREAT|O_TRUNC|O_RDWR);

	testname = argv[0];
	printf("\n %s: ", testname);
	while ((c = getopt(argc, argv, "FT:Q:I:u:d:f:s:")) != -1) {
		switch (c) {

		/* number of testcase runs to perform */
		case 'T':
			runs = atoi(optarg);
			break;

		/* time in seconds to nap in between runs */
		case 'Q':
			nap_time = atoi(optarg);
			break;

		/* number of testcase runs before we nap */
		case 'I':
			active_iter = atoi(optarg);
			break;

		case 's':
			file_size = atoi(optarg);
			break;

		case 'f':
			filename = optarg;
			break;

		case 'F':
			file_flags |= O_SYNC;
			break;

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

		case 'h':
			usage(0);
			break;
		default:
			usage(-1);
		}
	}

	if (filename == NULL) {
		usage(-1);
	}

	fill_buffer(buffy, BUFF_32k);

	starttime(TESTCASE);

	/*
	 * For "total_runs" do "active_iter" iterations of the
	 * testcase with a potential "nap_time" in-between.
	 */
	do {
		c = active_iter;
		do {
			int fd, blk, rc, wc, fs = file_size;

			/*
			 * create and open a file
			 */
			if ((fd = open_file(filename, file_flags, 0777)) < 0) {
				return (NOOK);
			}

			/*
			 * now wack out "file_size" bytes from buffy
			 * to the file
			 */
			do {
				wc = MIN(fs, BUFF_32k);
				if ((rc = write(fd, buffy, wc)) != wc) {
					fprintf(stderr, "\t Test FAIL: ");
					Perror("write():");
					close_file(fd, filename);
					return (NOOK);
				}
				fs -= wc;
			} while (fs);

			/*
			 * invalidate the client pages
			 */
			if (dirtyfile(fd, filename, file_size) != OK) {
				fprintf(stderr,
				    "\t Test FAIL: dirtyfile() failed");
				close_file(fd, filename);
				return (NOOK);
			}

			/*
			 * read the file back from
			 * the server and validate
			 */
			fs = file_size;
			blk = 0;

			if (pos_file(fd, 0) != 0) {
				fprintf(stderr, "\t Test FAIL: ");
				eprint("file rewind filed\n");
				close_file(fd, filename);
				return (NOOK);
			}

			do {
				/*
				 * compare in 32k blocks.
				 */
				wc = MIN(fs, BUFF_32k);

				if ((rc = read(fd, yffub, wc)) != wc) {
					fprintf(stderr, "\t Test FAIL: ");
					Perror("read():");
					close_file(fd, filename);
					return (NOOK);
				}

				if ((rc = memcmp(buffy, yffub, wc)) != 0) {
					fprintf(stderr, "\t Test FAIL: ");
					eprint("written != read in blk @ %d\n",
					    rc, blk);
					close_file(fd, filename);
					return (NOOK);
				}
				blk += wc;
				fs -= wc;
			} while (fs);

			close_file(fd, filename);
			unlink_file(filename);
			total_runs++;
		} while (--c > 0);

		/* Lets take a nap if user sez so.. */
		if (nap_time)
			sleep(nap_time);
	} while (--runs > 0);

	printf("\t Test PASS: ");
	printf("%s completed %d execution runs.\n", testname, total_runs);
	endtime("         ");

	return (OK);
}
