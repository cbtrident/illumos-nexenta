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

#ifndef	_NFSGEN_H
#define	_NFSGEN_H

#ifdef	__cplusplus
extern "C" {
#endif

/* include for common C functions */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>

#include <stf.h>

/* Constants */
/* lock functions' mandatory values */
#define	MAND_NO		0	/* No mandatory locking */
#define	MAND_YES	1	/* Non-blocking mandatory locking */
#define	MANDW_YES	2	/* Blocking mandatory locking */

/* to use in locks */
#define	TO_EOF	0

/* used in pipes */
#define	CHILD	'C'
#define	PARENT	'P'

/* general status */
#define	OK		STF_PASS
#define	NOOK		STF_FAIL
#define	UNTESTED	STF_UNTESTED

/* admerrors commands */
#define	TOTALS		0
#define	TOTERROR	1
#define	TOTSTEPS	2
#define	TOTASSERT	3
#define	ASSERT		4
#define	TOTDB		5
#define	SCENARIO	6

/* mmap read/write flag */
#define	MMREAD		1
#define	MMWRITE		2

/* Macros */

#define	IS64BIT_OFF_T	sizeof (off_t) > sizeof (long)

#define	read_lock(fd, mand, offset, whence, len) \
	lock_reg(fd, mand, F_RDLCK, offset, whence, len)

#define	write_lock(fd, mand, offset, whence, len) \
	lock_reg(fd, mand, F_WRLCK, offset, whence, len)

#define	un_lock(fd, mand, offset, whence, len) \
	lock_reg(fd, mand, F_UNLCK, offset, whence, len)

/* Globals */

extern int	me;			/* current process (PARENT or CHILD) */
extern pid_t	PidParent, PidChild;	/* Pids */
extern int	NBlocks;		/* flag to avoid mandatory locks */
					/*   from waiting */
extern int	SYNCWRITE;		/* force access to file (server) by */
					/*   invalidating mem copy */
extern int	mmflag;			/* flag to use mmap on read/writes */
extern int	debug;			/* debug flag */
extern int	showerror;		/* display error messages flag */
extern int	expecterr;		/* Expected return value for open & */
					/* friends: OK, errno, NOOK->unknown */
extern int	errflag;		/* Number of errors */
extern int	tsflag;			/* Number of tresults failed */
extern int	tsprev;			/* Previous value for tsflag */
extern int	aflag;			/* Number of assertions failed */
extern int	tspflag;		/* Number of succesful tresults */
extern int	apflag;			/* Number of successful assertions */
extern int	byeflag;		/* insert atexit() notification once */
extern char	*GLOBdata;		/* temp storage used for verifying */
					/*	reads */
extern int	Glob_status;		/* global status to control */
					/*	say_bye() msg */
extern struct timeval	tpstart;	/* Time sttructure for event's */
					/*	starting time */
extern struct timeval	tpend;		/* Time sttructure for event's ending */
					/*	time */
extern struct stat	Stat;		/* file stat output */

extern int	errtoout;		/* make stderr same as sdtout */
extern char	odir[512];		/* original directory */
extern char	cwd[512];		/* test direcory */
extern char	*Testname;		/* this process name */
extern int	renew;			/* lease period */

extern char	*scen;			/* scenario name */
extern int	scen_mode;		/* mode for testscenarios */
extern int	scen_flag;		/* flags for test scenarios */

extern char	lfilename[512];		/* local machine path/filename for */
					/* testfile */
extern int	lperms;			/* testfile permissions */
extern int	lflags;			/* testfile flags */
extern int	delay;			/* time delay in seconds */
extern int	srv_local;		/* flag to signal this process is */
					/*   running locally on the server */

extern uid_t	uid;			/* first user test uid */
extern uid_t	uid2;			/* second test uid */
extern gid_t	gid;			/* first user test gid */
extern gid_t	gid2;			/* second user test gid */

extern int 	skip_getdeleg;		/* call get_deleg_type() or not */

		/* The next 4 vars are for per scenario instance stats */
extern int	serrflag;	/* Number of errors scenario */
extern int	stsflag;	/* Number of tresults failed scenario */
extern int	saflag;		/* Number of assertions failed scenario */
extern int	stspflag;	/* Number of succesful tresults scenario */
extern int	sapflag;	/* Number of successful assertions scenario */

/* Functions */

extern void	print(char *, ...);
extern void	dprint(char *, ...);
extern void	eprint(char *, ...);
extern void	Perror(const char *);
extern char	*errtostr(int);
extern char	*sigtostr(int);
extern char	*mandtostr(int);
extern char	*whencetostr(int);
extern char	*cmdtostr(int);
extern char	*typetostr(int);
extern char	*pidtostr(pid_t);
extern char	*oflagstr(int);
extern char	*mmtypetostr(int);
extern int	tresult(int, int);
extern void	assertion(char *, char *, char *);
extern int	admerrors(int);
extern char	*Whoami(void);
extern int	lock_reg(int, int, int, off_t, int, off_t);
extern pid_t	lock_test(int, int, off_t, int, off_t);
extern int	create_test_data_file(char *, int);
extern int	create_10K_test_data_file(char *, int);
extern off_t	pos_file(int, off_t);
extern int	open_file(char *, int, int);
extern int	close_file(int, char *);
extern int	chmod_file(int, char *, mode_t);
extern int	link_file(char *, char *);
extern int	unlink_file(char *);
extern ssize_t	nfsgenRead(int, void*, size_t);
extern ssize_t	nfsgenWrite(int, void*, size_t);
extern int	write_file(int, char *, char *, off_t, unsigned);
extern int	read_file(int, char *, char *, off_t, unsigned);
extern char	*strbackup(char *);
extern int	dupfile(int);
extern int	Seteuid(uid_t);
extern int	Setegid(gid_t);
extern int	Setgroups(int, gid_t *);
extern int	truncatefile(int, char *, off_t);
extern int	statfile(int, char *);
extern int	mmapfile(int, char **, off_t, off_t *, int);
extern int	munmapfile(char *, off_t);
extern int	dirtyfile(int, char *, size_t);
extern int	_nfssys(int, void *);
extern int	get_deleg(int, char *);
extern void	exit_test(int);
extern void	kill_child(int);
extern void	encode_errors(void);
extern void	decode_errors(void);
extern void	notify_parent(int);
extern void	notify_child(int);
extern void	childisdead(int);
extern void	say_bye(void);
extern void	insert_bye(void);
extern void	initialize(void);
extern void	init_comm(void);
extern void	sendintp(int);
extern int	getintp(void);
extern void	contch(void);
extern void	waitch(void);
extern void	contp(void);
extern void	waitp(void);
extern void	clientinfo(void);
extern void	starttime(char *);
extern void	endtime(char *);
extern int	rsh_cmd(char *, char *, char *, char *);
extern void	cd_to_odir(void);
extern void	Usage(void);
extern void	parse_args(int, char **);
extern int	wait_get_cresult(void);
extern int	wait_send_cresult(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _NFSGEN_H */
