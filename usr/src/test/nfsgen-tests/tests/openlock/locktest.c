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

/* Lock operation C testcase */

#include "nfsgen.h"

#define	READ_FAIL	1
#define	WRITE_FAIL	2

/* Functions */
int scenarioA(int mode, int oflag, int expect[]);
int scenarioB(int mode, int oflag, int expect[]);
int scenarioC(int mode, int oflag, int expect[]);

/* Globals */

static char	*filename = NULL;
char		*buf = NULL;
int		N = 100;		/* used for scenario C loops */

/*
 * Main test loop.
 */

int
main(int argc, char **argv)
{
	int		i, j;
	int		ret = OK;
	char		*deleg, *scen, *mode_index, *oflag_index;
	static int	mode_set[] = {0600, 0400, 0200, 000},
			oflag_set[] = {O_EXCL|O_RDWR, O_RDWR, O_WRONLY,
					O_RDONLY};
	static int	expect[4][4][6] =
	{
	{	{OK,		OK,	OK,	OK,	EAGAIN,	EAGAIN},
		{OK,		OK,	OK,	OK,	EAGAIN,	EAGAIN},
		{OK,		OK,	EBADF,	OK,	EBADF,	EAGAIN},
		{OK,		OK,	OK,	EBADF,	EAGAIN,	EBADF}},
	{	{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF},
		{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF},
		{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF},
		{OK,		OK,	OK,	EBADF,	EAGAIN,	EBADF}},
	{	{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF},
		{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF},
		{OK,		OK,	EBADF,	OK,	EBADF,	EAGAIN},
		{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF}},
	{	{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF},
		{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF},
		{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF},
		{EACCES,	EBADF,	EBADF,	EBADF,	EBADF,	EBADF}}
	};

	if ((buf = malloc(256)) == NULL) {
		perror("main()- malloc() for buf");
		return (NOOK);
	}

	parse_args(argc, argv);

	filename = lfilename;

	dprint("Try to remove test files, to avoid errors.\n");
	unlink_file(filename);
	unlink_file("linkfile.txt");

	/* modify name to include delgation policy */
	if ((deleg = getenv("DELG")) != NULL) {
		if (strcasecmp(deleg, "on") == 0) {
			strcat(Testname, "_Deleg");
		}
		if (strcasecmp(deleg, "off") == 0) {
			strcat(Testname, "_NoDeleg");
		}
	}

	scen = getenv("SCENARIO");
	if (!scen) {
		printf("The scenario was not specified");
		return (NOOK);
	}

	if ((mode_index = getenv("MODE_INDEX")) != NULL) {
		i = atoi(mode_index);
		if ((i > 3) && (strcmp(scen, "C") != 0)) {
			printf("The mode index(%d) is more than 3 "\
			    "with scenario %s", i, scen);
			return (NOOK);
		} else if (i > 6) {
			printf("The mode index(%d) is more than 6 "\
			    "with scenario %s", i, scen);
			return (NOOK);
		}
	}

	if ((oflag_index = getenv("OFLAG_INDEX")) != NULL) {
		j = atoi(oflag_index);
		if (j > 3) {
			printf("The oflag index(%d) is more than 3 "\
			    "with scenario %s", i, scen);
			return (NOOK);
		}
	}


	/* run tests */
	switch (*scen) {
	case 'A':
		ret = scenarioA(mode_set[i], oflag_set[j], expect[i][j]);
		break;
	case 'B':
		ret = scenarioB(mode_set[i], oflag_set[j], expect[i][j]);
		break;
	case 'C':
		scenarioC(0600, O_CREAT|O_TRUNC|O_RDWR, expect[0][1]);
		break;
	default:
		printf("Set invalid scenario(%s)", scen);
		return (NOOK);
	}

	if (buf != NULL)
		free(buf);
	if (GLOBdata != NULL)
		free(GLOBdata);

	exit_test(ret);
	return (OK);	/* unreachable, used to quiet lint */
}

int
scenarioA(int mode, int oflag, int expect[])
{
	int	fd1, fd2;
	char	*DD;
	int	flg = 0;
	int	expt;
	int	ret = OK;

	scen = "ScenA";
	scen_mode = mode;
	scen_flag = oflag;
	expecterr = expect[0];

	fprintf(stdout, "\n\nExecuting Scenario A, with mode = 0%o and "\
	    "oflag = %s\n\n", mode, oflagstr(oflag));

	DD = strbackup("#123456789");

	if (create_10K_test_data_file(filename, mode) ||
	    link_file(filename, "linkfile.txt")) {
		printf("The scenario initialization failed, "\
		    "and other subassertions won't run.\n\n");
		exit_test(NOOK);
	}

	print("open a file on file desc fd1 and a hardlink to it on fd2.\n");

	fd1 = open_file(filename, oflag, mode);
	fd2 = open_file("linkfile.txt", oflag, mode);
	if ((fd1 < 0) || (fd2 < 0)) {
		if (expect[0] == OK) {
			printf("scenarioA{rest}: open call\n");
			printf("\t Test OTHER: unexpected open failure\n");
			ret = NOOK;
		}
		print("Scenario A, skipping rest of scenario.\n");
		goto clean_up;
	}

	/* initialize pipes and create the child */
	initialize();

	if (me == PARENT) {
/* assertion a) */
		waitp();
		assertion("a", "Parent read lock the file using fd2",
		    errtostr(expect[2]));
		read_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		if (errno != OK) {
			flg |= READ_FAIL;
		}
		tresult(expect[2], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
		contp();
		waitch();

/* assertion b) */
		assertion("b", "Child read lock the file using fd1 & fd2,\n"
		    "then tries write lock using both fd1 & fd2",
		    "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		if (errno != OK) {
			flg |= READ_FAIL;
		}
		tresult(expect[2], errno);

		read_file(fd1, filename, buf, 0, 10);
		tresult(expect[2], errno);
		read_file(fd2, "linkfile.txt", buf, 0, 10);
		tresult(expect[2], errno);

		write_file(fd1, filename, DD, 0, 10);
		tresult(expect[3], errno);
		write_file(fd2, "linkfile.txt", DD, 0, 10);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion c) */
		expt = expect[5];
		if ((flg & READ_FAIL) != 0) {
			expt = (expt == EAGAIN) ? OK : expt;
		}
		assertion("c", "Parent tries to write lock first 1 KB using "
		    "both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expt, errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expt, errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion d) */
		assertion("d", "Child unlocks first 1 KB using both fd1 & fd2",
		    "multiple");
		un_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[1], errno);
		un_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion e) */
		assertion("e", "Parent retries write lock first 1 KB using "
		    "fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[3], errno);
		admerrors(ASSERT);

/* assertion f) */
		assertion("f", "Parent tries to read/write first 10 bytes "
		    "using both fd1 & fd2", "multiple");
		read_file(fd1, filename, buf, 0, 10);
		tresult(expect[2], errno);
		read_file(fd2, "linkfile.txt", buf, 0, 10);
		tresult(expect[2], errno);

		write_file(fd1, filename, DD, 0, 10);
		tresult(expect[3], errno);
		write_file(fd2, "linkfile.txt", DD, 0, 10);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion g) */
		expt = expect[4];
		if (oflag == O_RDONLY) {
			expt = (expt == EAGAIN) ? OK : expt;
		}
		assertion("g", "Child read lock first 1 KB using both "
		    "fd1 & fd2", "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expt, errno);
		read_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expt, errno);
		admerrors(ASSERT);

/* assertion h) */
		assertion("h", "Child tries to write lock first 1 KB using "
		    "both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[5], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[5], errno);
		admerrors(ASSERT);

/* assertion i) */
		expt = expect[5];
		if ((flg & READ_FAIL) != 0) {
			expt = (expt == EAGAIN) ? OK : expt;
		}
		assertion("i", "Child tries to write lock area from 1 KB + 1 to"
		    "2 KB using both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expt, errno);
		write_lock(fd2, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expt, errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion j) */
		assertion("j", "Parent tries to unlock area from 1 KB + 1 to "
		    "EOF using both fd1 & fd2", "multiple");
		un_lock(fd1, MAND_NO, 1024+1, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		un_lock(fd2, MAND_NO, 1024+1, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion k) */
		assertion("k", "Child tries to read lock area from 1 KB + 1 to "
		    "2 KB using both fd1 & fd2", "multiple");
		read_lock(fd1, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expect[2], errno);
		read_lock(fd2, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expect[2], errno);
		admerrors(ASSERT);

/* assertion l) */
		assertion("l", "Child tries to write lock area from 1 KB + 1 "
		    "to 2 KB using both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion m) */
		assertion("m", "Parent tries to read lock first 1 KB using "
		    "both fd1 & fd2", "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[2], errno);
		read_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[2], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion n) */
		assertion("n", "Child tries to write lock the file using "
		    "both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[5], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[5], errno);
		admerrors(ASSERT);

/* assertion o) */
		assertion("o", "Child tries to read lock the file using "
		    "both fd1 & fd2", "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[2], errno);
		read_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[2], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion p) */
		assertion("p", "Parent unlocks the file using fd1 & fd2",
		    "multiple");
		un_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		un_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion q) */
		assertion("q", "Child tries to write lock the file using both "
		    "fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contp();
		wait_send_cresult();

		while (1)
			sleep(1);
	}

	if (me == PARENT) {
/* assertion r) */
		assertion("r", "Parent tries to write lock the file using both "
		    "fd1 & fd2,\n\tand kills the child process",
		    "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[5], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[5], errno);
		admerrors(ASSERT);

		if (wait_get_cresult())
			ret = NOOK;
		kill_child(OK);

/* assertion s) */
		assertion("s", "Parent tries to write lock the file using both "
		    "fd1 & fd2,\n\tand closes both files", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);

		close_file(fd1, filename);
		tresult(expect[1], errno);
		close_file(fd2, "linkfile.txt");
		tresult(expect[1], errno);
		admerrors(ASSERT);

/* assertion t) */
		assertion("t", "Parent reopens both files and tries to write "
		    "lock both using fd1 & fd2", "multiple");
		fd1 = open_file(filename, oflag, mode);
		tresult(expect[0], errno);
		fd2 = open_file("linkfile.txt", oflag, mode);
		tresult(expect[0], errno);

		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		admerrors(ASSERT);

/* assertion u) */
		assertion("u", "Parent unlocks both files and closes them",
		    "multiple");
		un_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		un_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);

		close_file(fd1, filename);
		tresult(expect[1], errno);
		close_file(fd2, "linkfile.txt");
		tresult(expect[1], errno);
		admerrors(ASSERT);
		goto clean_up;
	}

	if (me == CHILD) {
		print("ERROR: child should be dead. Quitting ...\n");
		exit_test(NOOK);
	}

clean_up:
	unlink_file(filename);
	unlink_file("linkfile.txt");

	ret = admerrors(SCENARIO);
	print("Scenario A finished.\n\n\n");
	return (ret);
}

int
scenarioB(int mode, int oflag, int expect[])
{
	int	fd1, fd2, fd3;
	char	*DD;
	int	flg = 0;
	int	expt;
	char	tmp[512];
	int	ret = OK;

	scen = "ScenB";
	scen_mode = mode;
	scen_flag = oflag;
	expecterr = expect[0];

	fprintf(stdout, "\n\nExecuting Scenario B, with mode = 0%o and "\
	    "oflag = %s\n\n", mode, oflagstr(oflag));

	DD = strbackup("#123456789");

	if (create_10K_test_data_file(filename, mode) ||
	    link_file(filename, "linkfile.txt")) {
		printf("The scenario initialization failed, "\
		    "and other subassertions won't run.\n\n");
		exit_test(NOOK);
	}

	print("open a file on file desc fd1 and a hardlink to it on fd2.\n");

	fd1 = open_file(filename, oflag, mode);
	fd2 = open_file("linkfile.txt", oflag, mode);
	if ((fd1 < 0) || (fd2 < 0)) {
		if (expect[0] == OK) {
			printf("scenarioB{rest}: open call\n");
			printf("\t Test OTHER: unexpected open failure\n");
			ret = NOOK;
		}
		print("Scenario B, skipping rest of scenario.\n");
		goto clean_up;
	}

	/* initialize pipes and create the child */
	initialize();

	if (me == PARENT) {
/* assertion a) */
		waitp();
		assertion("a", "Parent read lock the file using fd2",
		    errtostr(expect[2]));
		read_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		if (errno != OK) {
			flg |= READ_FAIL;
		}
		tresult(expect[2], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion b) */
		sprintf(tmp, "Child chages credentials to user %ld and group "
		    "%ld,\n\tthen read lock the file using fd1, and tries"
		    "to read/write first 10 bytes\n\tusing both fd1 & fd2",
		    uid2, gid2);
		/*
		 * Mark the start of the assertion in debug mode, in a way that
		 * won't interfere with the summary gathering script
		 */
		dprint("%s_%s_0%o_%s{%s}: %s, expect %s.\n", Testname, scen,
		    scen_mode, oflagstr(scen_flag), "b", tmp, "multiple");
		if (Seteuid(0) < 0) {
			print("Scenario B, seteuid(root) failed, skipping"\
			    " rest of scenario ...\n");
			goto child_end;
		}
		if (Setegid(gid2) < 0) {
			print("Scenario B, setegid(%d) failed, skipping"\
			    "rest of scenario ...\n", gid2);
			goto child_end;
		}

		{
		gid_t gid = gid2;

		if (Setgroups(1, &gid) < 0) {
			print("Scenario B, setgroups(1, %d) failed, "\
			    "skipping rest of scenario ...\n", gid);
			goto child_end;
		}

		}
		if (Seteuid(uid2) < 0) {
			print("Scenario B, seteuid(%d) failed, skipping"\
			    " rest of scenario ...\n", uid2);
			goto child_end;
		}
		contp();
		waitch();

		/* Now the real assertion message */
		assertion("b", tmp, "multiple");

		read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		if (errno != OK) {
			flg |= READ_FAIL;
		}
		tresult(expect[2], errno);

		read_file(fd1, filename, buf, 0, 10);
		tresult(expect[2], errno);
		read_file(fd2, "linkfile.txt", buf, 0, 10);
		tresult(expect[2], errno);

		write_file(fd1, filename, DD, 0, 10);
		tresult(expect[3], errno);
		write_file(fd2, "linkfile.txt", DD, 0, 10);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion c) */
		expt = expect[5];
		if ((flg & READ_FAIL) != 0) {
			expt = (expt == EAGAIN) ? OK : expt;
		}
		assertion("c", "Parent tries to write lock first 1 KB using "
		    "both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expt, errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expt, errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion d) */
		assertion("d", "Child unlock first 1 KB using both fd1 & fd2",
		    "multiple");
		un_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[1], errno);
		un_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion e) */
		assertion("e", "Parent retries write lock first 1 KB using "
		    "fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[3], errno);
		admerrors(ASSERT);

/* assertion f) */
		assertion("f", "Parent tries to read/write first 10 bytes "
		    "using both fd1 & fd2", "multiple");
		read_file(fd1, filename, buf, 0, 10);
		tresult(expect[2], errno);
		read_file(fd2, "linkfile.txt", buf, 0, 10);
		tresult(expect[2], errno);

		write_file(fd1, filename, DD, 0, 10);
		tresult(expect[3], errno);
		write_file(fd2, "linkfile.txt", DD, 0, 10);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion g) */
		expt = expect[4];
		if (oflag == O_RDONLY) {
			expt = (expt == EAGAIN) ? OK : expt;
		}
		assertion("g", "Child read lock first 1 KB using both "
		    "fd1 & fd2", "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expt, errno);
		read_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expt, errno);
		admerrors(ASSERT);

/* assertion h) */
		assertion("h", "Child tries to write lock first 1 KB using "
		    "both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[5], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[5], errno);
		admerrors(ASSERT);

/* assertion i) */
		expt = expect[5];
		if ((flg & READ_FAIL) != 0) {
			expt = (expt == EAGAIN) ? OK : expt;
		}
		assertion("i", "Child tries to write lock area from 1 KB + 1 to"
		    "2 KB using both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expt, errno);
		write_lock(fd2, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expt, errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion j) */
		assertion("j", "Parent tries to unlock area from 1 KB + 1 to "
		    "EOF using both fd1 & fd2", "multiple");
		un_lock(fd1, MAND_NO, 1024+1, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		un_lock(fd2, MAND_NO, 1024+1, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion k) */
		assertion("k", "Child tries to read lock area from 1 KB + 1 to "
		    "2 KB using both fd1 & fd2", "multiple");
		read_lock(fd1, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expect[2], errno);
		read_lock(fd2, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expect[2], errno);
		admerrors(ASSERT);

/* assertion l) */
		assertion("l", "Child tries to write lock area from 1 KB + 1 "
		    "to 2 KB using both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 1024+1, SEEK_SET, 2048);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion m) */
		assertion("m", "Parent tries to read lock first 1 KB using "
		    "both fd1 & fd2", "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[2], errno);
		read_lock(fd2, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[2], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion n) */
		assertion("n", "Child tries to write lock the file using "
		    "both fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[5], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[5], errno);
		admerrors(ASSERT);

/* assertion o) */
		assertion("o", "Child tries to read lock the file using "
		    "both fd1 & fd2", "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[2], errno);
		read_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[2], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion p) */
		assertion("p", "Parent unlocks the file using fd1 & fd2",
		    "multiple");
		un_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		un_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion q) */
		assertion("q", "Child tries to write lock the file using both "
		    "fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion r) */
		assertion("r", "Parent tries to write lock the file using both "
		    "fd1 & fd2", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[5], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[5], errno);
		admerrors(ASSERT);
		contch();
		waitp();
		}

	if (me == CHILD) {
/* assertion r1) */
		assertion("r1", "Child closes both files", "multiple");
		close_file(fd1, filename);
		tresult(expect[1], errno);
		close_file(fd2, "linkfile.txt");
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contp();
		wait_send_cresult();

		while (1)
			sleep(1);
		}

	if (me == PARENT) {
/* assertion s) */
		assertion("s", "Parent tries to write lock the file using both "
		    "fd1 & fd2,\n\tcloses both files and kills the child"
		    " process", "multiple");
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		write_lock(fd2, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);

		close_file(fd1, filename);
		tresult(expect[1], errno);
		close_file(fd2, "linkfile.txt");
		tresult(expect[1], errno);
		admerrors(ASSERT);

		if (wait_get_cresult())
			ret = NOOK;
		kill_child(OK);

		goto clean_up;
		}

	if (me == CHILD) {
		print("ERROR: child should be dead. Quitting ...\n");
		exit_test(NOOK);
	}

child_end:
	contp();
	wait_send_cresult();
	while (1)
		sleep(1);

clean_up:
	if (Seteuid(0) < 0) {
		dprint("Scenario B, seteuid(root) failed\n");
	}
	unlink_file(filename);
	unlink_file("linkfile.txt");
	unlink_file("testfile2.txt");
	if (Seteuid(uid) < 0) {
		dprint("Scenario B, seteuid(%d) failed\n", uid);
	}

	ret = admerrors(SCENARIO);
	print("Scenario B finished.\n\n\n");
	return (ret);
}

int
scenarioC(int mode, int oflag, int expect[])
{
	int	fd1;
	int	i;
	char	*DD;
	char	tmp[512];
	int	ret = OK;

	scen = "ScenC";
	scen_mode = mode;
	scen_flag = oflag;
	expecterr = expect[0];

	fprintf(stdout, "\n\nExecuting Scenario C, with mode = 0%o and "\
	    "oflag = %s\n\n", mode, oflagstr(oflag));

	DD = strbackup("#123456789");

	if (create_10K_test_data_file(filename, mode)) {
		printf("The scenario initialization failed, "\
		    "and other subassertions won't run.\n\n");
		exit_test(NOOK);
	}

	print("open a file on file desc fd.\n");

	fd1 = open_file(filename, oflag, mode);
	if (fd1 < 0) {
		if (expect[0] == OK) {
			printf("scenarioC{rest}: open call\n");
			printf("\t Test OTHER: unexpected open failure\n");
			ret = NOOK;
		}
		print("Scenario C, skipping rest of scenario.\n");
		goto clean_up;
	}

	/* initialize pipes and create the child */
	initialize();

	if (me == PARENT) {
		sleep(1);	/* let child start */
		contch();
		waitp();
	}

	if (me == CHILD) {
		waitch();
		contp();
/* assertion a) */
		sprintf(tmp, "Child read lock and unlock the file %d times"
		    "concurrently with next assertion",
		    N);
		/*
		 * Mark the start of the assertion in debug mode, in a way that
		 * won't interfere with the summary gathering script
		 */
		dprint("%s_%s_0%o_%s{%s}: %s, expect %s.\n", Testname, scen,
		    scen_mode, oflagstr(scen_flag), "a", tmp, "multiple");
		for (i = 0; i < N; i++) {
			read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
			tresult(expect[2], errno);
			un_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
			tresult(expect[1], errno);
		}
		/* now the real assertion message */
		assertion("a", tmp, "multiple");
		admerrors(ASSERT);
		/* print parent assertion message and result */
		contp();
		waitch();
		/* now continue with next assertion */
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion b) */
		sprintf(tmp, "Parent closes and reopens the file %d times, "
		    "then\n\tread locks the file", N);

		/*
		 * Mark the start of the assertion in debug mode, in a way that
		 * won't interfere with the summary gathering script
		 */
		dprint("%s_%s_0%o_%s{%s}: %s, expect %s.\n", Testname, scen,
		    scen_mode, oflagstr(scen_flag), "b", tmp, "multiple");
		for (i = 0; i < N; i++) {
			close_file(fd1, filename);
			tresult(expect[1], errno);
			fd1 = open_file(filename, oflag, mode);
			tresult(expect[0], errno);
		}
		read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[2], errno);
		/* wait for previous assertion to be printed */
		waitp();
		/* Now print the real assertion message */
		assertion("b", tmp, "multiple");
		admerrors(ASSERT);

		contch();
		waitp();

/* assertion c) */
		assertion("c", "Parent write locks the file",
		    errtostr(expect[3]));
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion d) */
		assertion("d", "Child read locks the file",
		    errtostr(expect[4]));
		read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[4], errno);
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion e) */
		sprintf(tmp, "Parent read locks the file, then unlocks and "
		    "read locks it for %d times", N);
		assertion("e", tmp, "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[2], errno);
		for (i = 0; i < N; i++) {
			un_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
			tresult(expect[1], errno);
			read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
			tresult(expect[2], errno);
		}
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion f) */
		sprintf(tmp, "Child read locks the file, then unlocks and "
		    "read locks it for %d times", N);
		assertion("f", tmp, "multiple");
		read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[2], errno);
		for (i = 0; i < N; i++) {
			un_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
			tresult(expect[1], errno);
			read_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
			tresult(expect[2], errno);
		}
		admerrors(ASSERT);
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion g) */
		assertion("g", "Parent unlocks the file", errtostr(expect[1]));
		un_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion h) */
		sprintf(tmp, "Child write locks the file and waits for the "
		    "lease period (%d + 2 seconds) to expire", renew);
		assertion("h", tmp, errtostr(expect[3]));
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contp();

		sleep(renew + 2);
	}

	if (me == PARENT) {
/* assertion i) */
		assertion("i", "Parent read locks first 1 KB",
		    errtostr(expect[4]));
		read_lock(fd1, MAND_NO, 0, SEEK_SET, 1024);
		tresult(expect[4], errno);
		admerrors(ASSERT);
		waitp();
	}

	if (me == CHILD) {
		contp();
		waitch();
	}

	if (me == PARENT) {
/* assertion j) */
		assertion("j", "Parent unlocks the file", errtostr(expect[1]));
		un_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[1], errno);
		admerrors(ASSERT);
		contch();
		waitp();
	}

	if (me == CHILD) {
/* assertion k) */
		assertion("k", "Child write locks the file",
		    errtostr(expect[3]));
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		contp();
		wait_send_cresult();

		while (1)
			sleep(1);
	}

	if (me == PARENT) {
		if (wait_get_cresult())
			ret = NOOK;
		kill_child(OK);

/* assertion l) */
		assertion("l", "Parent kills the child process and write locks"
		    " the file", errtostr(expect[3]));
		write_lock(fd1, MAND_NO, 0, SEEK_SET, TO_EOF);
		tresult(expect[3], errno);
		admerrors(ASSERT);
		goto clean_up;
	}

	if (me == CHILD) {
		print("ERROR: child should be dead. Quitting ...\n");
		exit_test(NOOK);
	}


clean_up:
	close_file(fd1, filename);
	unlink_file(filename);
	ret = admerrors(SCENARIO);

	print("Scenario C finished.\n\n\n");
	return (ret);
}
