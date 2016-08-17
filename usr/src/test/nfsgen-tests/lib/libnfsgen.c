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

/* common C functions */

#include "nfsgen.h"

/* local constants */
#define	ASSERTION_MSG	2048


/* global variables */
int me = PARENT;		/* current process (PARENT or CHILD) */
pid_t PidParent = -1,		/* Pids */
	PidChild = -1;
int NBlocks = 0;		/* flag to avoid mandatory locks from waiting */
int SYNCWRITE = 0;		/* force access to file (server) by */
				/* 	invalidating mem copy */
int mmflag = 0;			/* flag to use mmap on read/writes */
int debug = 0;			/* debug flag */
int showerror = 0;		/* display error messages flag */
int expecterr = NOOK;		/* Expected return value for open & friends */
				/* 	OK, errno, NOOK->unknown */
int errflag = 0;		/* Number of errors */
int tsflag = 0;			/* Number of test steps failed */
int tsprev = 0;			/* Previous value for tsflag */
int aflag = 0;			/* Number of assertions failed */
int tspflag = 0;		/* Number of succesful test steps */
int apflag = 0;			/* Number of successful assertions */
int serrflag = 0;		/* Number of errors scenario */
int stsflag = 0;		/* Number of test steps failed scenario */
int saflag = 0;			/* Number of assertions failed scenario */
int stspflag = 0;		/* Number of succesful test steps scenario */
int sapflag = 0;		/* Number of successful assertions scenario */
int byeflag = 0;		/* insert atexit() notification once */
char *GLOBdata = NULL;		/* temp storage used for verifying reads */
int Glob_status = OK;		/* global status to control say_bye() msg */
static int PChild[2];		/* Comm. pipes for child */
static int PParent[2];		/* Comm. pipes for Parent */
static char last_assert[ASSERTION_MSG] = "";
				/* last failed assertion message */
struct timeval tpstart;		/* Time sttructure for event's starting time */
struct timeval tpend;		/* Time sttructure for event's ending time */
struct stat Stat;		/* file stat output */

int	errtoout = 0;		/* make stderr same as sdtout */
char	odir[512] = "";		/* original directory */
char	cwd[512] = ".";		/* test directory */
char	*Testname = NULL;	/* this process name */
int	renew = -1;		/* lease period */

char	*scen = NULL;		/* scenario name */
int	scen_mode = 0;		/* mode for testscenarios */
int	scen_flag = 0;		/* flags for test scenarios */

char	lfilename[512] = "";	/* local machine path/filename for testfile */
int	lperms = 0777;		/* testfile permissions */
int	lflags = O_CREAT|O_RDWR;	/* testfile flags */
int	delay = 0;		/* time delay in seconds */
int	srv_local = 0;		/* flag to signal this process is running */
				/*	locally on the server */
uid_t	uid = 999999999;	/* first user test uid */
uid_t	uid2 = 888888888;	/* second test uid */
gid_t	gid = 777777;		/* first user test gid */
gid_t	gid2 = 666666;		/* second user test gid */

int	skip_getdeleg = 0;	/* get delegation type or not */


/* functions */

/*
 * ****************************************************************************
 * function	print()
 * purpose	printing messages to stdout, preceded by calling proccess.
 * arguments	similar to printf().
 * returns	nothing.
 * ****************************************************************************
 */

void
print(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stdout, "%s: ", Whoami());
	(void) vfprintf(stdout, fmt, ap);
	va_end(ap);
	(void) fflush(stdout);
}


/*
 * ****************************************************************************
 * function	dprint()
 * purpose	printing debug messages to stdout, preceded by calling proccess,
 *		if global "debug" is set.
 * arguments	similar to printf().
 * returns	nothing.
 * ****************************************************************************
 */

void
dprint(char *fmt, ...)
{
	va_list ap;

	if (!debug)
		return;
	va_start(ap, fmt);
	(void) fprintf(stdout, "%s: ", Whoami());
	(void) vfprintf(stdout, fmt, ap);
	va_end(ap);
	(void) fflush(stdout);
}


/*
 * ****************************************************************************
 * function	eprint()
 * purpose	printing error messages to stderr, preceded by calling proccess,
 *		if global "showerror" is set. Also, global "errflag" is
 *		incremented.
 * arguments	similar to printf().
 * returns	nothing.
 * ***************************************************************************
 */

void
eprint(char *fmt, ...)
{
	va_list ap;

	/* increment number of errors found so far */
	errflag++;

	if (!showerror)
		return;
	va_start(ap, fmt);
	(void) fprintf(stderr, "E %s:", Whoami());
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fflush(stderr);
}


/*
 * ****************************************************************************
 * function	Perror()
 * purpose	call perror() conditionally upon global "showerror" being set.
 * arguments	Same as perror().
 * returns	nothing.
 * ****************************************************************************
 */

void
Perror(const char *s)
{
	if (showerror)
		perror(s);
}


/*
 * ****************************************************************************
 * function	errtostr()
 * purpose	Converts error codes returned in errno to name of constant
 *		(string) as defined in system include files.
 * arguments	error number to convert.
 * returns	name of constant for given error number, or "" if error.
 * ****************************************************************************
 */

char *
errtostr(int error)
{
	static const char *errstring[] = {
	"OK",		/*   0 No error				*/
	"EPERM",	/*   1 Not super-user			*/
	"ENOENT",	/*   2 No such file or directory	*/
	"ESRCH",	/*   3 No such process			*/
	"EINTR",	/*   4 interrupted system call		*/
	"EIO",		/*   5 I/O error			*/
	"ENXIO",	/*   6 No such device or address	*/
	"E2BIG",	/*   7 Arg list too long		*/
	"ENOEXEC",	/*   8 Exec format error		*/
	"EBADF",	/*   9 Bad file number			*/
	"ECHILD",	/*  10 No children			*/
	"EAGAIN",	/*  11 Resource temporarily unavailable */
	"ENOMEM",	/*  12 Not enough core			*/
	"EACCES",	/*  13 Permission denied		*/
	"EFAULT",	/*  14 Bad address			*/
	"ENOTBLK",	/*  15 Block device required		*/
	"EBUSY",	/*  16 Mount device busy		*/
	"EEXIST",	/*  17 File exists			*/
	"EXDEV",	/*  18 Cross-device link		*/
	"ENODEV",	/*  19 No such device			*/
	"ENOTDIR",	/*  20 Not a directory			*/
	"EISDIR",	/*  21 Is a directory			*/
	"EINVAL",	/*  22 Invalid argument			*/
	"ENFILE",	/*  23 File table overflow		*/
	"EMFILE",	/*  24 Too many open files		*/
	"ENOTTY",	/*  25 Inappropriate ioctl for device	*/
	"ETXTBSY",	/*  26 Text file busy			*/
	"EFBIG",	/*  27 File too large			*/
	"ENOSPC",	/*  28 No space left on device		*/
	"ESPIPE",	/*  29 Illegal seek			*/
	"EROFS",	/*  30 Read only file system		*/
	"EMLINK",	/*  31 Too many links			*/
	"EPIPE",	/*  32 Broken pipe			*/
	"EDOM",		/*  33 Math arg out of domain of func	*/
	"ERANGE",	/*  34 Math result not representable	*/
	"ENOMSG",	/*  35 No message of desired type	*/
	"EIDRM",	/*  36 Identifier removed		*/
	"ECHRNG",	/*  37 Channel number out of range	*/
	"EL2NSYNC",	/*  38 Level 2 not synchronized	*/
	"EL3HLT",	/*  39 Level 3 halted			*/
	"EL3RST",	/*  40 Level 3 reset			*/
	"ELNRNG",	/*  41 Link number out of range		*/
	"EUNATCH",	/*  42 Protocol driver not attached	*/
	"ENOCSI",	/*  43 No CSI structure available	*/
	"EL2HLT",	/*  44 Level 2 halted			*/
	"EDEADLK",	/*  45 Deadlock condition.		*/
	"ENOLCK",	/*  46 No record locks available.	*/
	"ECANCELED",	/*  47 Operation canceled		*/
	"ENOTSUP",	/*  48 Operation not supported		*/

	/* Filesystem Quotas */
	"EDQUOT",	/*  49 Disc quota exceeded		*/

	/* Convergent Error Returns */
	"EBADE",	/*  50 invalid exchange			*/
	"EBADR",	/*  51 invalid request descriptor	*/
	"EXFULL",	/*  52 exchange full			*/
	"ENOANO",	/*  53 no anode				*/
	"EBADRQC",	/*  54 invalid request code		*/
	"EBADSLT",	/*  55 invalid slot			*/
	"EDEADLOCK",	/*  56 file locking deadlock error	*/

	"EBFONT",	/*  57 bad font file fmt		*/

	/* Interprocess Robust Locks */
	"EOWNERDEAD",	/*  58 process died with the lock	*/
	"ENOTRECOVERABLE",	/*  59 lock is not recoverable	*/

	/* stream problems */
	"ENOSTR",	/*  60 Device not a stream		*/
	"ENODATA",	/*  61 no data (for no delay io)	*/
	"ETIME",	/*  62 timer expired			*/
	"ENOSR",	/*  63 out of streams resources		*/

	"ENONET",	/*  64 Machine is not on the network	*/
	"ENOPKG",	/*  65 Package not installed		*/
	"EREMOTE",	/*  66 The object is remote		*/
	"ENOLINK",	/*  67 the link has been severed	*/
	"EADV",		/*  68 advertise error			*/
	"ESRMNT",	/*  69 srmount error			*/

	"ECOMM",	/*  70 Communication error on send	*/
	"EPROTO",	/*  71 Protocol error			*/

	/* Interprocess Robust Locks */
	"ELOCKUNMAPPED",	/*  72 locked lock was unmapped		*/

	"ENOTACTIVE",	/*  73 Facility is not active		*/
	"EMULTIHOP",	/*  74 multihop attempted		*/
	"EBADMSG",	/*  77 trying to read unreadable message	*/
	"ENAMETOOLONG",	/*  78 path name is too long		*/
	"EOVERFLOW",	/*  79 value too large to be stored in data type */
	"ENOTUNIQ",	/*  80 given log. name not unique	*/
	"EBADFD",	/*  81 f.d. invalid for this operation	*/
	"EREMCHG",	/*  82 Remote address changed		*/

	/* shared library problems */
	"ELIBACC",	/*  83 Can't access a needed shared lib.	*/
	"ELIBBAD",	/*  84 Accessing a corrupted shared lib.	*/
	"ELIBSCN",	/*  85 .lib section in a.out corrupted. */
	"ELIBMAX",	/*  86 Attempting to link in too many libs.	*/
	"ELIBEXEC",	/*  87 Attempting to exec a shared library.	*/
	"EILSEQ",	/*  88 Illegal byte sequence.		*/
	"ENOSYS",	/*  89 Unsupported file system operation	*/
	"ELOOP",	/*  90 Symbolic link loop		*/
	"ERESTART",	/*  91 Restartable system call		*/
	"ESTRPIPE",	/*  92 if pipe/FIFO, don't sleep in stream head	*/
	"ENOTEMPTY",	/*  93 directory not empty		*/
	"EUSERS",	/*  94 Too many users (for UFS)		*/

	/* BSD Networking Software */
		/* argument errors */
	"ENOTSOCK",	/*  95 Socket operation on non-socket	*/
	"EDESTADDRREQ",	/*  96 Destination address required	*/
	"EMSGSIZE",	/*  97 Message too long			*/
	"EPROTOTYPE",	/*  98 Protocol wrong type for socket	*/
	"ENOPROTOOPT",	/*  99 Protocol not available		*/
	"UNKOWN",	/* 100 Undefined error			*/
	"UNKOWN",	/* 101 Undefined error			*/
	"UNKOWN",	/* 102 Undefined error			*/
	"UNKOWN",	/* 103 Undefined error			*/
	"UNKOWN",	/* 104 Undefined error			*/
	"UNKOWN",	/* 105 Undefined error			*/
	"UNKOWN",	/* 106 Undefined error			*/
	"UNKOWN",	/* 107 Undefined error			*/
	"UNKOWN",	/* 108 Undefined error			*/
	"UNKOWN",	/* 109 Undefined error			*/
	"UNKOWN",	/* 110 Undefined error			*/
	"UNKOWN",	/* 111 Undefined error			*/
	"UNKOWN",	/* 112 Undefined error			*/
	"UNKOWN",	/* 113 Undefined error			*/
	"UNKOWN",	/* 114 Undefined error			*/
	"UNKOWN",	/* 115 Undefined error			*/
	"UNKOWN",	/* 116 Undefined error			*/
	"UNKOWN",	/* 117 Undefined error			*/
	"UNKOWN",	/* 118 Undefined error			*/
	"UNKOWN",	/* 119 Undefined error			*/
	"EPROTONOSUPPORT",	/* 120 Protocol not supported	*/
	"ESOCKTNOSUPPORT",	/* 121 Socket type not supported	*/
	"EOPNOTSUPP",	/* 122 Operation not supported on socket	*/
	"EPFNOSUPPORT",	/* 123 Protocol family not supported	*/
	"EAFNOSUPPORT",	/* 124 Address family not supported by	*/
				/* protocol family		*/
	"EADDRINUSE",	/* 125 Address already in use		*/
	"EADDRNOTAVAIL",	/* 126 Can't assign requested address	*/
		/* operational errors */
	"ENETDOWN",	/* 127 Network is down			*/
	"ENETUNREACH",	/* 128 Network is unreachable		*/
	"ENETRESET",	/* 129 Network dropped connection because	*/
				/* of reset			*/
	"ECONNABORTED",	/* 130 Software caused connection abort */
	"ECONNRESET",	/* 131 Connection reset by peer		*/
	"ENOBUFS",	/* 132 No buffer space available	*/
	"EISCONN",	/* 133 Socket is already connected	*/
	"ENOTCONN",	/* 134 Socket is not connected		*/

	/* XENIX has 135 - 142 */
	"XENIX",	/* 135 XENIX error			*/
	"XENIX",	/* 136 XENIX error			*/
	"XENIX",	/* 137 XENIX error			*/
	"XENIX",	/* 138 XENIX error			*/
	"XENIX",	/* 139 XENIX error			*/
	"XENIX",	/* 140 XENIX error			*/
	"XENIX",	/* 141 XENIX error			*/
	"XENIX",	/* 142 XENIX error			*/
	"ESHUTDOWN",	/* 143 Can't send after socket shutdown */
	"ETOOMANYREFS",	/* 144 Too many references: can't splice	*/
	"ETIMEDOUT",	/* 145 Connection timed out		*/
	"ECONNREFUSED",	/* 146 Connection refused		*/
	"EHOSTDOWN",	/* 147 Host is down			*/
	"EHOSTUNREACH",	/* 148 No route to host			*/
	/* EWOULDBLOCK	EAGAIN					*/
	"EALREADY",	/* 149 operation already in progress	*/
	"EINPROGRESS",	/* 150 operation now in progress	*/

	/* SUN Network File System */
	"ESTALE"	/* 151 Stale NFS file handle		*/
	};
	static const char *null = "";

	if ((error < 0) || (error > 151))
		return ((char *)null);
	else
		return ((char *)errstring[error]);
}


/*
 * ****************************************************************************
 * function	sigtostr()
 * purpose	Converts signal numbers name of constant
 *		(string) as defined in system include files.
 * arguments	signal number to convert.
 * returns	name of constant for given signal number, or signal number if
 * 		not defined.
 * ****************************************************************************
 */

char *
sigtostr(int sig)
{
	static const char *sigstring[] = {
	"NONE",		/* 0  ????   No signal */
	"SIGHUP",	/* 1  Exit   Hangup (see termio(7I)) */
	"SIGINT",	/* 2  Exit   Interrupt (see termio(7I)) */
	"SIGQUIT",	/* 3  Core   Quit (see termio(7I)) */
	"SIGILL",	/* 4  Core   Illegal Instruction */
	"SIGTRAP",	/* 5  Core   Trace or Breakpoint Trap */
	"SIGABRT",	/* 6  Core   Abort */
	"SIGEMT",	/* 7  Core   Emulation Trap */
	"SIGFPE",	/* 8  Core   Arithmetic Exception */
	"SIGKILL",	/* 9  Exit   Killed */
	"SIGBUS",	/* 10 Core   Bus Error */
	"SIGSEGV",	/* 11 Core   Segmentation Fault */
	"SIGSYS",	/* 12 Core   Bad System Call */
	"SIGPIPE",	/* 13 Exit   Broken Pipe */
	"SIGALRM",	/* 14 Exit   Alarm Clock */
	"SIGTERM",	/* 15 Exit   Terminated */
	"SIGUSR1",	/* 16 Exit   User Signal 1 */
	"SIGUSR2",	/* 17 Exit   User Signal 2 */
	"SIGCHLD",	/* 18 Ignore Child Status Changed */
	"SIGPWR",	/* 19 Ignore Power Fail or Restart */
	"SIGWINCH",	/* 20 Ignore Window Size Change */
	"SIGURG",	/* 21 Ignore Urgent Socket Condition */
	"SIGPOLL",	/* 22 Exit   Pollable Event (see streamio(7I)) */
	"SIGSTOP",	/* 23 Stop   Stopped (signal) */
	"SIGTSTP",	/* 24 Stop   Stopped (user) (see termio(7I)) */
	"SIGCONT",	/* 25 Ignore Continued */
	"SIGTTIN",	/* 26 Stop   Stopped (tty input) (see termio(7I)) */
	"SIGTTOU",	/* 27 Stop   Stopped (tty output) (see termio(7I)) */
	"SIGVTALRM",	/* 28 Exit   Virtual Timer Expired */
	"SIGPROF",	/* 29 Exit   Profiling Timer Expired */
	"SIGXCPU",	/* 30 Core   CPU time limit exceeded */
	"SIGXFSZ",	/* 31 Core   File size limit exceeded */
	"SIGWAITING",	/* 32 Ignore Concurrency signal reserved by threads */
			/* library */
	"SIGLWP",	/* 33 Ignore Inter-LWP signal reserved by threads */
			/* library */
	"SIGFREEZE",	/* 34 Ignore Check point Freeze */
	"SIGTHAW",	/* 35 Ignore Check point Thaw */
	"SIGCANCEL",	/* 36 Ignore Cancellation signal reserved by threads */
			/* library */
	"SIGLOST",	/* 37 ????   resource lost (eg, record-lock lost) */
	"SIGXRES",	/* 38 ????   resource control exceeded */
	"SIGRTMIN",	/* 39 Exit   First real time signal */
	"SIGRTMIN+1",	/* 40 Exit   Second real time signal */
	"SIGRTMIN+2",	/* 41 Exit   Third real time signal */
	"SIGRTMIN+3",	/* 42 Exit   Fourth real time signal */
	"SIGRTMIN+4",	/* 43 Exit   Fifth real time signal */
	"SIGRTMIN+5",	/* 44 Exit   Sixth real time signal */
	"SIGRTMIN+6",	/* 45 Exit   Seventh real time signal */
	"SIGRTMAX"	/* 46 Exit   Last real time signal */
	};

	if ((sig < 0) || (sig > 46)) {
		static char buf[10] = "";

		(void) snprintf(buf, 10, "%d", sig);
		return (buf);
	} else {
		return ((char *)sigstring[sig]);
	}
}


/*
 * ****************************************************************************
 * function	mandtostr()
 * purpose	Converts mandatory flag to name of constant as defined in
 *		common.h. Used to made logs easily readable.
 * arguments	Value used in mandatory flag.
 * returns	Name of constant equivalent to mandatory flag value, or ""
 *		if error.
 * ****************************************************************************
 */

char *
mandtostr(int mand)
{
	static const char *mandstring[] = {
		"F_SETLK",		/* 0 MAND_NO */
		"F_SETLK_NBMAND",	/* 1 MAND_YES */
		"F_SETLKW"		/* 2 MANDW_YES */
	};
	static const char *null = "";

	if ((mand < 0) || (mand > 2))
		return ((char *)null);
	else
		return ((char *)mandstring[mand]);
}


/*
 * ****************************************************************************
 * function	whencetostr()
 * purpose	Converts value used in argument whence (utilized in several
 *		function calls) to a string for logs readability.
 * arguments	Value used for whence parameter.
 * returns	Name of constant as defined in system headers, or "" if error.
 * ****************************************************************************
 */

char *
whencetostr(int whence)
{
	static const char *whencestring[] = {
		"SEEK_SET",	/* 0 Set file pointer to "offset" */
		"SEEK_CUR",	/* 1 Set file pointer to current + "offset" */
		"SEEK_END"	/* 2 Set file pointer to EOF plus "offset" */
	};
	static const char *null = "";

	if ((whence < 0) || (whence > 2))
		return ((char *)null);
	else
		return ((char *)whencestring[whence]);
}


/*
 * ****************************************************************************
 * function	cmdtostr()
 * purpose	Converts the value for fcntl's argument cmd, to constant name
 *		as defined in system header files. Used for logs readability.
 * arguments	Value for cmd argument.
 * returns	String with name of cmd constant, or "" if error.
 * ****************************************************************************
 */

char *
cmdtostr(int cmdvalue)
{
	static const char *null = "";
	static char *cmd;

	cmd = (char *)null;

	switch (cmdvalue) {
#ifndef __sparcv9
	case F_SETLK:
		cmd = "F_SETLK";	/* Set file lock */
		break;
	case F_SETLKW:
		cmd = "F_SETLKW";	/* Set file lock and wait */
		break;
	case F_FREESP:
		cmd = "F_FREESP";	/* Free file space */
		break;
	case F_GETLK:
		cmd = "F_GETLK";	/* Get file lock */
		break;
	case F_SETLK_NBMAND:
		cmd = "F_SETLK_NBMAND";	/* private */
		break;
#else
	case F_SETLK64:
		cmd = "F_SETLK64";	/* Set file lock */
		break;
	case F_SETLKW64:
		cmd = "F_SETLKW64";	/* Set file lock and wait */
		break;
	case F_FREESP64:
		cmd = "F_FREESP64";	/* Free file space */
		break;
	case F_GETLK64:
		cmd = "F_GETLK64";	/* Get file lock */
		break;
	case F_SETLK64_NBMAND:
		cmd = "F_SETLK64_NBMAND";	/* private */
		break;
#endif
	case F_SHARE:
		cmd = "F_SHARE";	/* Set a file share reservation */
		break;
	case F_UNSHARE:
		cmd = "F_UNSHARE";	/* Remove a file share reservation */
		break;
	case F_SHARE_NBMAND:
		cmd = "F_SHARE_NBMAND";	/* private */
		break;
	default:
		cmd = (char *)null;
	}

	return (cmd);
}


/*
 * ****************************************************************************
 * function	typetostr()
 * purpose	Convert the lock type (fcntl()) value to name of constant as
 *		defined in system header files. Used for logs readability.
 * arguments	Value of lock type argument.
 * returns	String with name of lock type, or "" if error.
 * ****************************************************************************
 */

char *
typetostr(int type)
{
	static const char *typestring[] = {
		"",
		"F_RDLCK",	/* 1 Read lock */
		"F_WRLCK",	/* 2 Write lock */
		"F_UNLCK",	/* 3 Remove lock(s) */
		"F_UNLKSYS"	/* 4 remove remote locks for a given system */
	};
	static const char *null = "";


	if ((type < 0) || (type > 4))
		return ((char *)null);
	else
		return ((char *)typestring[type]);
}


/*
 * ****************************************************************************
 * function	pidtostr()
 * purpose	Converts the PID given to either string "PARENT", "CHILD" or
 *		"proc pid XXXX". Used for logs readability.
 * arguments	PID of interest.
 * returns	String specifying parent, child or pid number.
 * ****************************************************************************
 */

char *
pidtostr(pid_t pid)
{
	static char buf[256];
	static char *owner;

	if (pid == PidChild)
		owner = "Child";
	else if (pid == PidParent)
		owner = "Parent";
	else {
		(void) snprintf(buf, 256, "proc pid %ld\0", (long)pid);
		owner = buf;
	}

	return (owner);
}


/*
 * ****************************************************************************
 * function	oflagstr()
 * purpose	Convert the value of oflag parameter for open() to constant
 *		names as defined in system header files. Used for logs
 *		readability.
 * arguments	Value of oflag as described for open().
 * returns	String with all flags constant names described for open()
 *		sparated by "|".
 * ****************************************************************************
 */

char *
oflagstr(int flag)
{
	static const char *flagstr[] = {
		"O_RDONLY",	/* read only				*/
		"O_WRONLY",	/* write only				*/
		"O_RDWR",	/* read and write			*/
		"O_NDELAY",	/* non-blocking I/O			*/
		"O_APPEND",	/* append (writes guaranteed at the end) */
		"O_SYNC",	/* synchronized file update option	*/
		"O_DSYNC",	/* synchronized data update option	*/
		"O_NONBLOCK",	/* non-blocking I/O (POSIX)		*/
		"O_PRIV",	/* Private access to file		*/
		"O_LARGEFILE",	/* large file (offset 64 bits)		*/
		"O_XATTR",	/* extended attribute			*/
		"O_RSYNC",	/* synchronized file update option	*/
				/* defines read/write file integrity	*/
		"O_CREAT",	/* open with file create (uses third arg) */
		"O_TRUNC",	/* open with truncation			*/
		"O_EXCL",	/* exclusive open			*/
		"O_NOCTTY"	/* don't allocate controlling tty (POSIX) */
		};
	static const int flagval[] = {
		0,	/* read only				*/
		1,	/* write only				*/
		2,	/* read and write			*/
		0x04,	/* non-blocking I/O			*/
		0x08,	/* append (writes guaranteed at the end) */
		0x10,	/* synchronized file update option	*/
		0x40,	/* synchronized data update option	*/
		0x80,	/* non-blocking I/O (POSIX)		*/
		0x1000,	/* Private access to file		*/
		0x2000,	/* large file (offset 64 bits)		*/
		0x4000,	/* synchronized file update option	*/
		0x8000,	/* synchronized file update option	*/
			/* defines read/write file integrity	*/
		0x100,	/* open with file create (uses third arg) */
		0x200,	/* open with truncation			*/
		0x400,	/* exclusive open			*/
		0x800	/* don't allocate controlling tty (POSIX) */
		};
	int i;
	static char buf[1024];

	buf[0] = '\0';
	for (i = 0; i < 15; i++)
		if (flag & flagval[i])
			if (buf[0] == 0)
				strcpy(buf, flagstr[i]);
			else {
			/* use underscore instead of spaces for summary func */
				strcat(buf, "_|_");
				strcat(buf, flagstr[i]);
			}
	if (strlen(buf) == 0)
		strcpy(buf, flagstr[0]);

	return (buf);
}


/*
 * ****************************************************************************
 * function	mmtypetostr()
 * purpose	Converts the type used for mmap to string.
 * arguments	type used in mmap.
 * returns	String specifying mmap type to be used.
 * ****************************************************************************
 */

char *
mmtypetostr(int type)
{
	static char buf[256];

	buf[0] = '\0';
	if (type & MMREAD)
		(void) snprintf(buf, 256, "PROT_READ");
	if (type & MMWRITE) {
		if (buf[0] != '\0')
			(void) strcat(buf, "|");
		(void) strcat(buf, "PROT_WRITE");
	}

	return (buf);
}


/*
 * ****************************************************************************
 * function	tresult()
 * purpose	Checkpoint for test step. Compares actual and expected error
 *		codes (including OK), updating globals "tsflag" (tests step
 *		failures) and "tspflag" (teststep successes) as appropriate.
 * arguments	expect- expected error code.
 *		actual- actual error code.
 * returns	OK (0) upon success (expect == actual), otherwise NO OK (-1).
 * ****************************************************************************
 */

int
tresult(int expect, int actual)
{
	char tmp[512] = "";

	if (expect != actual) {
		(void) snprintf(tmp, 512, \
		    "\tTest FAIL: Expected message was %s, "
		    "actual message is %s\n",
		    errtostr(expect), errtostr(actual));
		if (strlcat(last_assert, tmp, ASSERTION_MSG) >= ASSERTION_MSG) {
			eprint("tresult() warning: buffer overflow.\n"
			    "\tassertion messages may be incomplete.\n");
		}
		dprint("%s\n", last_assert);

		/* increment number of test steps failed so far */
		tsflag++;
		return (NOOK);
	} else {
		dprint("Expected message %s was correct.\n", errtostr(expect));
		/* increment number of test steps passed so far */
		tspflag++;
		return (OK);
	}
}

/*
 * ****************************************************************************
 * function     assertion()
 * purpose      Print information assertions.
 *
 * arguments    assert		name of the assertion.
 *		desc		string describing the assertion to run
 * returns      nothing.
 * ****************************************************************************
 */

void
assertion(char *assert, char *desc, char *expect)
{
	(void) printf("%s_%s_0%o_%s{%s}: %s, expect %s.\n",
	    Testname, scen, scen_mode,
	    oflagstr(scen_flag), assert, desc, expect);
}

/*
 * ****************************************************************************
 * function	admerrors()
 * purpose	Handle and print information about errors, test steps and
 *		assertions.
 * arguments	command to obtain status on passes or failures (test steps and
 *		assertions) and number of errors, evaluate current assertion
 *		based on its test steps, and update information at the end of
 *		a scenario execution.
 * returns	nothing.
 * ****************************************************************************
 */

int
admerrors(int cmd)
{
	int ret = OK;

	switch (cmd) {
	case TOTALS:
		/* print totals for all pass and failure information */
		dprint("A total of %d error(s) were found.\n", errflag);
		dprint("A total of %d test step(s) failed.\n", tsflag);
		dprint("A total of %d successful test step(s).\n", tspflag);
		(void) print("Total assertion(s) failed %d and passed %d.\n",
		    aflag, apflag);
		break;

	case TOTDB:
		/* same as TOTALS, but immune to global "debug" */
		(void) print("A total of %d error(s) were found.\n", errflag);
		(void) print("A total of %d test step(s) failed.\n", tsflag);
		(void) print("A total of %d test step(s) passed.\n", tspflag);
		(void) print("Total assertion(s) failed: %d and passed: %d.\n",
		    aflag, apflag);
		break;

	case TOTERROR:
		/* only print total number of errors */
		(void) print("A total of %d error(s) were found.\n", errflag);
		break;

	case TOTSTEPS:
		/* only print totals for test steps */
		(void) print("A total of %d test step(s) failed.\n", tsflag);
		(void) print("A total of %d test step(s) passed.\n", tspflag);
		break;

	case TOTASSERT:
		/* only print totals regarding assertions */
		(void) print("A total of %d assertion(s) failed.\n", aflag);
		(void) print("A total of %d assertion(s) passed.\n", apflag);
		break;

	case ASSERT:
		/* evaluate current assertion based on its test steps */
		/* if more ts errors than previous time, assertion failed */
		dprint("assert %d < %d.\n", tsprev, tsflag);
		if (tsprev < tsflag) {
			aflag ++;
			tsprev = tsflag;
			/* Test FAIL: message(s) */
			(void) printf("%s\n", last_assert);
			last_assert[0] = '\0'; /* reset */
		} else {
			apflag ++;
			(void) printf("\tTest PASS\n");
		}
		last_assert[0] = '\0';

		/* flush stdout and stderr before continuing */
		(void) fflush(stdout);
		(void) fflush(stderr);
		break;

	case SCENARIO:
		/* prints summary at the end of current test scenario */
		/*  and updates status globals */
		(void) fprintf(stdout, "\n\n");
		dprint("A total of %d error(s) were found.\n",
		    errflag - serrflag);
		dprint("A total of %d test step(s) failed.\n",
		    tsflag - stsflag);
		dprint("A total of %d successful test step(s).\n",
		    tspflag - stspflag);
		(void) print("Total assertion(s) failed %d and passed %d.\n",
		    aflag - saflag, apflag - sapflag);
		if ((aflag - saflag) > 0)
			ret = NOOK;
		else if ((apflag - sapflag) == 0)
			ret = UNTESTED;

		serrflag = errflag;
		stsflag = tsflag;
		saflag = aflag;
		stspflag = tspflag;
		sapflag = apflag;
		break;

	default:
		(void) print("admerrors(%d): ERROR unknown command\n", cmd);
	}

	return (ret);
}


/*
 * ****************************************************************************
 * function	Whoami()
 * purpose	Returns either "Parent" or "Child" based on calling process.
 * arguments	None.
 * returns	String stating calling proccess identity.
 * ****************************************************************************
 */

char *
Whoami(void)
{
	static char	parent[] = "Parent",
	    child[]	 = "Child";

	if (me == CHILD) {
		return (child);
	} else {
		return (parent);
	}
}


/*
 * ****************************************************************************
 * function	lock_reg()
 * purpose	Handle locks (regions of a files).
 * arguments	fd- file descriptor of targeted file.
 *		mand- mandatory flag as defined in common.h
 *		type- lock type as defined in fcntl().
 *		offset- starting offset of lock as described for fcntl().
 *		whence- lock base indicator as described for fcntl().
 *		len- length of lock as described for fcntl().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
lock_reg(int fd, int mand, int type, off_t offset, int whence, off_t len)
{
	struct flock lock;
	int cmd;
	int res;

	if (IS64BIT_OFF_T) {
		dprint("Call to lock_reg(%d, %s, %s, %lld, %s, %lld).\n", fd,
		    mandtostr(mand), typetostr(type), offset,
		    whencetostr(whence), len);
	} else {
		dprint("Call to lock_reg(%d, %s, %s, %ld, %s, %ld).\n", fd,
		    mandtostr(mand), typetostr(type), offset,
		    whencetostr(whence), len);
	}

	switch (mand) {
		case 1:	/* Non-blocking mandatory locking */
			cmd = F_SETLK_NBMAND; break;
		case 2:	/* Blocking mandatory locking */
			cmd = F_SETLKW; break;
		default:	/* No mandatory locking */
			cmd = F_SETLK;
	}

	/* global Non-Blocking locks substitute normal mandatory locks by */
	/*  checking lock_test first */
	if ((cmd == F_SETLKW) && (NBlocks)) {
		pid_t pid;
		int tmp;

		tmp = debug;
		debug = 0;
		pid = lock_test(fd, type, offset, whence, len);
		debug = tmp;
		if (pid < 0) {
			eprint("lock_reg()- lock_test() failed\n");
			errno = OK;
			return (NOOK);
		} else if (pid > 0) {
			if (IS64BIT_OFF_T) {
				dprint("lock_reg(%d, %s, %s, %lld, %s, %lld)-"\
				    " lock already taken by %s.\n", fd,
				    mandtostr(mand), typetostr(type),
				    offset, whencetostr(whence), len,
				    pidtostr(pid));
			} else {
				dprint("lock_reg(%d, %s, %s, %ld, %s, %ld)-"\
				    " lock already taken by %s.\n", fd,
				    mandtostr(mand), typetostr(type),
				    offset, whencetostr(whence), len,
				    pidtostr(pid));
			}
			errno = OK;
			return (NOOK);
		} /* else pid == 0, OK to proceed */
	}

	/* perform actual lock using fcntl() */
	lock.l_type = type;
	lock.l_start = offset;
	lock.l_whence = whence;
	lock.l_len = len;

	if ((res = fcntl(fd, cmd, &lock)) == -1) {
		if (IS64BIT_OFF_T) {
			eprint("lock_reg()- Call to fcntl(%d, %s, {%s, %lld,"\
			    " %s, %lld}) failed\n", fd, cmdtostr(cmd),
			    typetostr(type), offset, whencetostr(whence),
			    len);
		} else {
			eprint("lock_reg()- Call to fcntl(%d, %s, {%s, %ld,"\
			    " %s, %ld}) failed\n", fd, cmdtostr(cmd),
			    typetostr(type), offset, whencetostr(whence),
			    len);
		}
		Perror("\t\t");
		return (res);
	}

	if (IS64BIT_OFF_T) {
		dprint("lock_reg(%d, %s, %s, %lld, %s, %lld) successful.\n",
		    fd, mandtostr(mand), typetostr(type), offset,
		    whencetostr(whence), len);
	} else {
		dprint("lock_reg(%d, %s, %s, %ld, %s, %ld) successful.\n", fd,
		    mandtostr(mand), typetostr(type), offset,
		    whencetostr(whence), len);
	}

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	lock_test()
 * purpose	Test for ownership of lock (regions of a files).
 * arguments	fd- file descriptor of targeted file.
 *		type- lock type as defined in fcntl().
 *		offset- starting offset of lock as described for fcntl().
 *		whence- lock base indicator as described for fcntl().
 *		len- length of lock as described for fcntl().
 * returns	PID of process owner of lock (positive number), 0 if region is
 *		not locked, otherwise either NO OK (-1) or syscall fail result
 *		code.
 * ****************************************************************************
 */

pid_t
lock_test(int fd, int type, off_t offset, int whence, off_t len) {
	struct flock lock;
	int res;

	lock.l_type = type;
	lock.l_start = offset;
	lock.l_whence = whence;
	lock.l_len = len;

	if (IS64BIT_OFF_T) {
		dprint("Call to lock_test(%d, %s, %lld, %s, %lld).\n", fd,
			typetostr(type), offset,
			whencetostr(whence), len);
	} else {
		dprint("Call to lock_test(%d, %s, %ld, %s, %ld).\n", fd,
			typetostr(type), offset,
			whencetostr(whence), len);
	}

	if ((res = fcntl(fd,  F_GETLK, &lock)) < 0) {
		if (IS64BIT_OFF_T) {
			eprint("Call to lock_test(%d, %s, %lld, %s, %lld) "\
				"failed\n", fd, typetostr(type), offset,
				whencetostr(whence), len);
		} else {
			eprint("Call to lock_test(%d, %s, %ld, %s, %ld) "\
				"failed\n", fd, typetostr(type), offset,
				whencetostr(whence), len);
		}
		Perror("\t\t");
		return (res);
	}

	if (IS64BIT_OFF_T) {
		dprint("lock_test(%d, %s, %lld, %s, %lld) successful.\n",
			fd, typetostr(type), offset, whencetostr(whence), len);
	} else {
		dprint("lock_test(%d, %s, %ld, %s, %ld) successful.\n",
			fd, typetostr(type), offset, whencetostr(whence), len);
	}

	if (lock.l_type == F_UNLCK) {
		dprint("\tno lock assigned.\n");

		errno = OK;
		return (OK);
	} else {
		pid_t pid = lock.l_pid;

		dprint("\tthe owner of the lock is the %s.\n", pidtostr(pid));

		errno = OK;
		return (pid);
	}
}

/*
 * ****************************************************************************
 * function	ioFunc(...)
 * purpose	read or write data, check read/write func return value
 * arguments:
 *      $1 : file descriptor
 *      $2 : buffer which will save data for read, and provide data
 *           for write
 *      $3 : specify the number of bytes will written or read
 *	$4 : specify is read or write
 * return value: the number of bytes written or read is returned
 */
ssize_t
ioFunc(int fd, unsigned char *buf, size_t nbyte, int isread)
{
	ssize_t tmp = 0;
	size_t bytes = 0;

	while (bytes != nbyte) {
		if (isread == 1) {
			tmp = read(fd, buf + bytes, nbyte - bytes);
		} else {
			tmp = write(fd, buf + bytes, nbyte - bytes);
		}

		if (tmp < 0) {
			eprint("failed to read/write data, %s\n", \
			    strerror(errno));
			// set return code as tmp to indicate
			// the caller that IO failed
			bytes = tmp;
			break;
		} else if ((tmp == 0) && (isread == 1)) {
			dprint("read reach end of the file, bytes already \
			    read:%i\n", bytes);
			break;
		} else {
			bytes += tmp;
		}
	}

	return (bytes);
}


ssize_t
nfsgenRead(int fd, void *buf, size_t nbyte)
{
	ssize_t ret = ioFunc(fd, (unsigned char *)buf, nbyte, 1);
	return (ret);
}


ssize_t
nfsgenWrite(int fd, void *buf, size_t nbyte)
{
	ssize_t ret = ioFunc(fd, (unsigned char *)buf, nbyte, 0);
	return (ret);
}


/*
 * ****************************************************************************
 * function	create_test_data_file()
 * purpose	Create a small file (30 bytes) with a predefined content.
 * arguments	filename- path and filename for new file.
 *		mode- desired file permissions as defined in open().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
create_test_data_file(char *filename, int mode) {
	int fd;
	int res;
	char buff[31] = "#123456789#123456789#123456789";

	dprint("Call to create_test_file(%s, 0%o).\n", filename, mode);

	if ((fd = open(filename, (O_RDWR | O_CREAT | O_TRUNC), 0600)) < 0) {
		(void) print("Could not open %s\n", filename);
		perror("\t\t");
		exit_test(NOOK);
	}

	if ((res = nfsgenWrite(fd, buff, 30)) < 0) {
		(void) print("Write to %s failed returned %d\n", filename, res);
		perror("\t\t");
		exit_test(NOOK);
	}

	if ((res = chmod_file(fd, filename, mode)) < 0) {
		(void) print("Could not change file mode to %o\n", mode);
		perror("\t\t");
		exit_test(NOOK);
	}

	if ((res = close(fd)) < 0) {
		(void) print("Close %s failed returned %d\n", filename, res);
		perror("\t\t");
		exit_test(NOOK);
	}

	dprint("test data file %s was succesfully created.\n", filename);

	errno = OK;
	return (OK);
}


/*
 * ****************************************************************************
 * function	create_10K_test_data_file()
 * purpose	Create a file (about 10Kbytes in size) with a predefined
 *		content written at intervals of 1K, but not aligned to the
 *		1K boundaries.
 * arguments	filename- path and filename for new file.
 *		mode- desired file permissions as defined in open().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
create_10K_test_data_file(char *filename, int mode) {
	int fd;
	int res;
	off_t resl;
	char buff[] = "#123456789#1234567890";
	int i;

	dprint("Call to create_10K_test_file(%s, 0%o).\n", filename, mode);

	if ((fd = open(filename, (O_RDWR | O_CREAT | O_TRUNC), 0600)) < 0) {
		(void) print("Could not open %s\n", filename);
		perror("\t\t");
		exit_test(NOOK);
	}

	/* write initial string at beggining of the file */
	if ((res = nfsgenWrite(fd, buff, 10)) < 0) {
		(void) print("Write to %s failed returned %d\n", filename, res);
		perror("\t\t");
		exit_test(NOOK);
		}

	for (i = 0; i < 10; i++) {
		if ((resl = llseek(fd, 1014 + 1024*i, SEEK_SET)) == -1) {
			(void) print("llseek failed on file %s returned %d\n",
				filename, resl);
			perror("\t\t");
			exit_test(NOOK);
		}

		/* Now just write the buf to the end of the file */
		if ((res = nfsgenWrite(fd, buff, 10)) < 0) {
			(void) print("Write to %s failed returned %d\n",
				filename, res);
			perror("\t\t");
			exit_test(NOOK);
		}
	}

	if ((res = chmod_file(fd, filename, mode)) < 0) {
		(void) print("Could not change file mode to %o\n", mode);
		perror("\t\t");
		exit_test(NOOK);
	}

	if ((res = close(fd)) < 0) {
		(void) print("Close %s failed returned %d\n", filename, res);
		perror("\t\t");
		exit_test(NOOK);
	}

	dprint("10K test data file %s was succesfully created.\n", filename);

	errno = OK;
	return (OK);
}

/*
 * ****************************************************************************
 * function	pos_file()
 * purpose	Move a file pointer to specified position from start of file.
 * arguments	fd- file descriptor of target file.
 *		start- offset from start of file.
 * returns	newfile offset upon success, otherwise either NO OK (-1) or
 *		syscall fail result code.
 * ****************************************************************************
 */

off_t
pos_file(int fd, off_t start)
{
	off_t res;

	if ((res = llseek(fd, start, SEEK_SET)) == -1) {
		if (IS64BIT_OFF_T) {
			eprint("pos_file(%d, %lld) failed returned %lld\n",
			    fd, start, res);
		} else {
			eprint("pos_file(%d, %ld) failed returned %ld\n",
			    fd, start, res);
		}
		Perror("\t\t");
		return ((int)res);
	}

	if (IS64BIT_OFF_T) {
		dprint("file (%d) pointer moved to %lld.\n",
		    fd, start);
	} else {
		dprint("file (%d) pointer moved to %ld.\n",
		    fd, start);
	}

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	open_file()
 * purpose	Wraps syscall open() to handle log messages and errors.
 * arguments	Same as syscall open().
 * returns	filedescriptor upon success, otherwise either NO OK (-1) or
 *		syscall fail result code.
 * ****************************************************************************
 */

int
open_file(char *filename, int flags, int mode)
{
	int	fd;

	dprint("Call to open_file(%s, %s, 0%o).\n", filename, oflagstr(flags),
	    mode);

	if ((fd = open(filename, flags, mode)) < 0) {
		if ((expecterr == NOOK) || (expecterr != errno)) {
			(void) print("Open file %s,flags=%s,mode=0%o failed\n",
			    filename, oflagstr(flags), mode);
			perror("\t\t");
		} else {
			eprint("Open file %s, flags=%s, mode=0%o failed\n",
			    filename, oflagstr(flags), mode);
			Perror("\t\t");
		}
		return (fd);
	}

	dprint("Open file %s (flags=%s, mode=0%o fildes %d).\n",
	    filename, oflagstr(flags), mode, fd);

	errno = OK;
	return (fd);	/* OK */
}


/*
 * ****************************************************************************
 * function	close_file()
 * purpose	Wraps syscall close() to handle log messages and errors.
 * arguments	fd- file descriptor to be used in close().
 *		filename- associated filename for log messages.
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
close_file(int fd, char *filename)
{
	int res;

	dprint("Call to close_file(%d, %s).\n", fd, filename);

	if ((res = close(fd)) < 0) {
		eprint("Close file %s, fildes %d failed\n",
		    filename, fd);
		Perror("\t\t");
		return (res);
	}

	dprint("file %s was closed.\n", filename);

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	chmod_file()
 * purpose	Wraps syscall fchmod() to handle log messages and errors.
 * arguments	fd- file descriptor to be used in fchmod().
 *		filename- associated filename for log messages.
 *		mode- mode parameter as described for fchmod().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
chmod_file(int fd, char *filename,  mode_t mode)
{
	int res;

	if ((res = fchmod(fd, mode)) < 0) {
		eprint("fchmod(%d, 0%o) on %s failed\n", fd, mode, filename);
		Perror("\t\t");
		return (res);
	}

	dprint("File %s (fildes %d) mode was changed to 0%o.\n", filename, fd,
	    mode);

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	link_file()
 * purpose	Wraps syscall link() to handle log messages and errors.
 * arguments	Same as syscall link().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
link_file(char *old, char *new)
{
	int res;

	dprint("Call to link_file(%s, %s).\n", old, new);

	if ((res = link(old, new)) < 0) {
		if ((expecterr == NOOK) || (expecterr != errno)) {
			(void) print("link(%s, %s) failed\n", old, new);
			perror("\t\t");
		} else {
			eprint("link(%s, %s) failed\n", old, new);
			Perror("\t\t");
		}
		return (res);
	}

	dprint("Hard link %s created, pointing to %s.\n", new, old);

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	unlink_file()
 * purpose	Wraps syscall unlink() to handle log messages and errors.
 * arguments	Same as syscall unlink().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
unlink_file(char *filename)
{
	int res;

	dprint("Call to unlink_file(%s).\n", filename);

	if ((res = unlink(filename)) < 0) {
		eprint("Unlink file %s failed\n", filename);
		Perror("\t\t");
		return (res);
	}

	dprint("File %s was unlinked.\n", filename);

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	write_file()
 * purpose	Wraps syscalls lseek() and write() to handle log messages and
 *		errors. Additionally, based on global SYNCWRITE, calls fsync(),
 *		dirtyfile() and read_file() to make sure file is immediately
 *		updated at server (ignoring cache) and verifying the written
 *		information.
 * arguments	fd- file descriptor of targeted file.
 *		filename- correspondent filename for log messages purposes.
 *		datap- pointer to data to be written in file.
 *		offset- from start of file, where data is to be written.
 *			a -1 causes to set it to file size
 *		count- size (number of bytes) of data to be written.
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
write_file(int fd, char *filename, char *datap, off_t offset, unsigned count)
{
	int res;
	int result = OK;
	off_t resl;
	char *Datap;
	int append = offset == -1;

	if (offset == -1) {	/* move to EOF */
		statfile(fd, filename);
		offset = Stat.st_size;
		dprint("offset to use: %lld\n", (long long) offset);
	}

	if ((Datap = malloc(count + 256)) == NULL) {
		(void) print("write_file() out of mem. Aborting ...\n");
		perror("\t\t");
		exit_test(NOOK);
	}

	(void) strlcpy(Datap, datap, 31);
	if (strlen(datap) > 30)
		strcat(Datap, " ...");
	if (IS64BIT_OFF_T) {
		dprint("Call to write_file(%d, %s, %s, %lld, %u).\n", fd,
		    filename, Datap, offset, count);
	} else {
		dprint("Call to write_file(%d, %s, %s, %ld, %u).\n", fd,
		    filename, Datap, offset, count);
	}

	(void) strncpy(Datap, datap, count);
	Datap[count] = '\0';

	if ((resl = lseek(fd, offset, SEEK_SET)) < 0) {
		if (IS64BIT_OFF_T) {
			eprint("write_file(%d, %s, %s, %lld, %u) "\
			    "lseek failed\n",
			    fd, filename, datap, offset, count);
		} else {
			eprint("write_file(%d, %s, %s, %ld, %u) "\
			    "lseek failed\n",
			    fd, filename, datap, offset, count);
		}
		Perror("\t\t");
		free(Datap);
		return (resl);
	}
	if (IS64BIT_OFF_T) {
		dprint("write_file(%d, %s, %s, %lld, %u) "\
		    "lseek succeed\n",
		    fd, filename, datap, offset, count);
	} else {
		dprint("write_file(%d, %s, %s, %ld, %u) "\
		    "lseek succeed\n",
		    fd, filename, datap, offset, count);
	}

	if (mmflag == 1) {
		size_t size = (size_t)(offset + count);
		off_t osize = size; /* for mmapfile */
		void *Uaddr = NULL;
		char *start = NULL;
		size_t i;

		/* adjust size to include new data */
		if (append)
			truncatefile(fd, filename, osize);
		dprint("size (%llu) = offset (%llu) + count (%llu)\n",
		    (long long)size, (long long)offset, (long long)count);
		if ((res = mmapfile(fd, (char **)&Uaddr, (off_t)0L,
		    &osize, MMREAD|MMWRITE)) != 0) {
			eprint("write_file-mmapfile(%p, 0, %lld, %s) failed.\n",
			    Uaddr, (long long)osize,
			    mmtypetostr(MMREAD|MMWRITE));
			return (res);
		}
		size = osize;

		start = (char *)Uaddr + offset;
		dprint("start (%p) = Uaddr (%p) + offset (0x%llx)\n",
		    (char *)start, (char *)Uaddr, (long long)offset);
		(void) memcpy(start, datap, (size_t)count);
		dprint("write- memcpy(to=%p, from=%p, size=0x%lx)\n",
		    start, datap, (size_t)count);
		munmapfile(Uaddr, osize);
	} else {
		if ((res = nfsgenWrite(fd, datap, count)) < 0) {
			eprint("Cannot write to file %s.\n", filename);
			Perror("\t\t");
			free(Datap);
			return (res);
		}

		if (res != count) {
			eprint("Bad write len to file %s, got %u,"
			    " expected %d\n", filename, res, count);
			/* adjust if wrote shorter string */
			Datap[count] = '\0';

			result = NOOK;
		}
	}

	if (IS64BIT_OFF_T) {
		dprint("Wrote <%.32s> to %s [ %lld, %u ].\n",
		    Datap, filename, offset, count);
	} else {
		dprint("Wrote <%.32s> to %s [ %ld, %u ].\n",
		    Datap, filename, offset, count);
	}

	if (SYNCWRITE) {
		size_t size = (size_t)(offset + count);
		int tmp = debug;
		int ress;

		if ((ress = fsync(fd)) < 0) {
			eprint("write_file()- fsync() failed\n");
			Perror("\t\t");
		}
		/* invalidate cache is done at read_file() */
		debug = 0;
		if ((ress = read_file(fd, filename, Datap, offset, count))
		    < 0) {
			eprint("write_file()- read error in data "\
			    "written\n");

			result = NOOK;
		}
		debug = tmp;

		if (strncmp(datap, Datap, (size_t)count) != 0) {
			(void) print("Write_file()- Warning, read mismatch: "\
			    "Expected '%s', read '%s'\n",
			    datap, Datap);
			result = NOOK;
		}
	}

	free(Datap);

	errno = OK;
	return (result);
}


/*
 * ****************************************************************************
 * function	read_file()
 * purpose	Wraps syscalls lseek() and read() to handle log messages and
 *		errors. Additionally, based on global SYNCWRITE, calls
 *		dirtyfile() to make sure file is immediately read from server
 *		(ignoring cache) and verifying the read information.
 * arguments	fd- file descriptor of targeted file.
 *		filename- correspondent filename for log messages purposes.
 *		datap- pointer to data to be read from file.
 *		offset- from start of file, where data is to be read from.
 *		count- size (number of bytes) of data to be read.
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
read_file(int fd, char *filename, char *datap, off_t offset, unsigned count)
{
	int res;
	int result = 0;
	off_t resl;

	if (IS64BIT_OFF_T) {
		dprint("Call to read_file(%d, %s, %pp, %lld, %u).\n", fd,
		    filename, datap, offset, count);
	} else {
		dprint("Call to read_file(%d, %s, %pp, %ld, %u).\n", fd,
		    filename, datap, offset, count);
	}

	if (mmflag == 1) {
		size_t size = (size_t)(offset + count);
		off_t osize = size; /* for mmapfile */
		void *Uaddr = NULL;
		char *start = NULL;

		dprint("size (%llu) = offset (%llu) + count (%llu)\n",
		    (long long)size, (long long)offset, (long long)count);
		if ((res = mmapfile(fd, (char **)&Uaddr, (off_t)0L, \
		    &osize, MMREAD)) != 0) {
			eprint("read_file-mmapfile(%p, 0, %lld, %s) failed.\n",
			    Uaddr, (long long)osize, mmtypetostr(MMREAD));
			return (res);
		}
		size = osize;

		start = (char *)Uaddr + offset;
		dprint("start (%p) = Uaddr (%p) + offset (0x%llx)\n",
		    (char *)start, (char *)Uaddr, (long long)offset);
		(void) memcpy(datap, start, (size_t)count);
		dprint("read- memcpy(to=%p, from=%p, size=0x%lx).\n",
		    datap, start, (size_t)count);

		munmapfile(Uaddr, osize);
		/* null terminate string */
		datap[count] = '\0';
		if (IS64BIT_OFF_T) {
			dprint("Read <%.32s> from %s [ %lld, %u ].\n",
			    datap, filename, offset, count);
		} else {
			dprint("Read <%.32s> from %s [ %ld, %u ].\n",
			    datap, filename, offset, count);
		}
		errno = OK;
		return (OK);
	}

	/* invalidate cache to force a read from server */
	if (SYNCWRITE) {
		size_t size = (size_t)(offset + count);

		if ((res = dirtyfile(fd, filename, size)) < 0) {
			if (IS64BIT_OFF_T) {
				eprint("read_file()- "\
				    "dirtyfile(%d, %s, %lld) failed\n",
				    fd, filename, size);
				} else {
				eprint("read_file()- "\
				    "dirtyfile(%d, %s, %ld) failed\n",
				    fd, filename, size);
				}
		}
	}

	if ((resl = lseek(fd, offset, SEEK_SET)) < 0) {
		if (IS64BIT_OFF_T) {
			eprint("read_file(%d, %s, %pp, %lld, %u) "\
			    "lseek failed\n",
			    fd, filename, datap, offset, count);
		} else {
			eprint("read_file(%d, %s, %pp, %ld, %u) "\
			    "lseek failed\n",
			    fd, filename, datap, offset, count);
		}
		Perror("\t\t");
		return (resl);
	}
	if (IS64BIT_OFF_T) {
		dprint("read_file(%d, %s, %pp, %lld, %u) lseek succeed\n",
		    fd, filename, datap, offset, count);
	} else {
		dprint("read_file(%d, %s, %pp, %ld, %u) lseek succeed\n",
		    fd, filename, datap, offset, count);
	}

	if ((res = nfsgenRead(fd, datap, count)) < 0) {
		eprint("Cannot read to file %s.\n", filename);

		Perror("\t\t");
		return (res);
	}
	/* null terminate string */
	datap[count] = '\0';

	if (res != count) {
		eprint("Bad read len from file %s, got %d, expected %u\n",
		    filename, res, count);
		datap[res] = '\0';	/* adjust if wrote short string */
		result = NOOK;
	}

	if (IS64BIT_OFF_T) {
		dprint("Read <%.32s> from %s [ %lld, %u ].\n",
		    datap, filename, offset, count);
	} else {
		dprint("Read <%.32s> from %s [ %ld, %u ].\n",
		    datap, filename, offset, count);
	}

	/* If GLOBdata is non-null, make sure the bytes read are the same as */
	/*  what datap points to */
	if ((GLOBdata != NULL) && (strncmp(GLOBdata, datap, count) != 0)) {
		(void) print("Read test warning. Expected '%s', read '%s'\n",
		    GLOBdata, datap);
		result = NOOK;
	}

	errno = OK;
	return (result);
}


/*
 * ****************************************************************************
 * function	strbackup()
 * purpose	Stores a copy of data used in read_file() in global "GLOBdata".
 *		If GLOBdata is NULL (no mem allocated), no action is taken.
 * arguments	data- to be stored in "GLOBdata".
 * returns	Pointer to GLOBdata storage area, or data parameter value if
 *		GLOBdata has no memory allocated (is NULL).
 * ****************************************************************************
 */

char *
strbackup(char *data)
{
	if (GLOBdata != NULL) {
		(void) strcpy(GLOBdata, data);
		dprint("'%s' stored in global test var.\n", data);
		return (GLOBdata);
	} else {
		dprint("strbackup() global test var no memory allocated\n");
		return (data);
	}
}


/*
 * ****************************************************************************
 * function	dup_file()
 * purpose	Wraps syscall dup() to handle log messages and errors.
 * arguments	Same as syscall dup().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
dupfile(int fdo)
{
	int fd;

	dprint("Call to dupfile(%d).\n", fdo);
	if ((fd = dup(fdo)) < 0) {
		if ((expecterr == NOOK) || (expecterr != errno)) {
			(void) print("dupfile(%d) failed\n", fdo);
			perror("\t\t");
		} else {
			eprint("dupfile(%d) failed\n", fdo);
			Perror("\t\t");
		}
		return (fd);
	}

	dprint("Fildes %d was dupped in fildes %d.\n", fdo, fd);

	errno = OK;
	return (fd);	/* OK */
}


/*
 * ****************************************************************************
 * function	Seteuid()
 * purpose	Wraps syscall seteuid() to handle log messages and errors.
 * arguments	Same as syscall seteuid().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
Seteuid(uid_t uid)
{
	int res;

	dprint("Call to seteuid(%d).\n", uid);

	if ((res = seteuid(uid)) < 0) {
		eprint("seteuid(%d) failed\n", uid);
		Perror("\t\t");
		return (res);
	}

	dprint("Effective UID set to %d.\n", uid);

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	Setegid()
 * purpose	Wraps syscall setegid() to handle log messages and errors.
 * arguments	Same as syscall setegid().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
Setegid(gid_t gid)
{
	int res;

	dprint("Call to setegid(%d).\n", gid);

	if ((res = setegid(gid)) < 0) {
		eprint("setegid(%d) failed\n", gid);
		Perror("\t\t");
		return (res);
	}

	dprint("Effective GID set to %d.\n", gid);

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	Setgroups()
 * purpose	Wraps syscall setgroups() to handle log messages and errors.
 * arguments	Same as syscall setgroups().
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
Setgroups(int n, gid_t *gids)
{
	int res;
	int i;
	char buf[2048], buf2[256];

	(void) snprintf(buf, 2048, "{%ld", (long)gids[0]);
	for (i = 1; i < n; i++) {
		(void) snprintf(buf2, 256, ", %ld", (long)gids[i]);
		(void) strcat(buf, buf2);
	}
	(void) strcat(buf, "}");

	dprint("Call to setgroups(%d, %s).\n", n, buf);

	if ((res = setgroups(n, gids)) < 0) {
		eprint("setgroups(%d, %s) failed\n", buf);
		Perror("\t\t");
		return (res);
	}

	dprint("Supplemental groups set to %s.\n", buf);

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	truncatefile()
 * purpose	Wraps syscall ftruncate() to handle log messages and errors.
 * arguments	Same as syscall ftruncate() plus:
 *		filename- correspondent filename used for log messages.
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */
int
truncatefile(int fd, char *filename, off_t offset)
{
	int res;

	if (IS64BIT_OFF_T) {
		dprint("Call to truncatefile(%d, %s, %lld).\n", fd, filename,
		    offset);
	} else {
		dprint("Call to truncatefile(%d, %s, %ld).\n", fd, filename,
		    offset);
	}

	if ((res = ftruncate(fd, offset)) < 0) {
		if (IS64BIT_OFF_T) {
			eprint("truncatefile(%d, %s, %lld) failed\n",
			    fd, filename, offset);
		} else {
			eprint("truncatefile(%d, %s, %ld) failed\n",
			    fd, filename, offset);
		}
		Perror("\t\t");
		return (res);
	}

	if (IS64BIT_OFF_T) {
		dprint("File %s truncated to %lld.\n",
		    filename, offset);
	} else {
		dprint("File %s truncated to %ld.\n",
		    filename, offset);
	}

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	statfile()
 * purpose	Wraps syscall fstat() to handle log messages and errors.
 * arguments	Same as syscall fstat() plus:
 *		filename- correspondent filename used for log messages.
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */
int
statfile(int fd, char *filename)
{
	int res;

	dprint("Call to statfile(%d, %s).\n", fd, filename);

	if ((res = fstat(fd, &Stat)) < 0) {
		eprint("statfile(%d, %s) failed\n", fd, filename);
		Perror("\t\t");
		return (res);
	}

	dprint("File %s stats were gathered.\n", filename);

	errno = OK;
	return (res);	/* OK */
}


/*
 * ****************************************************************************
 * function	mmapfile()
 * purpose	Wraps syscall mmap() to handle log messages and errors.
 * arguments	Simplified version of syscall mmap():
 *		fd- file descriptor of targeted file.
 *		mapaddr- address of pointer var to hold area assigned in
 *			mapping.
 *		offset- from start of file to be mappen into memory.
 *		len- pointer to size of area to be mapped (will be adjusted to
 *			pagesize and then updated).
 *		type-	type of the mmap (READ, WRITE or both).
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
mmapfile(int fd, char **mapaddr, off_t offset, off_t *len, int type)
{
	size_t size;
	int rem;
	int page;
	void *addr = 0;
	int tflag = 0;

	if (IS64BIT_OFF_T) {
		dprint("Call to mmapfile(%d, %pp, %lld, %lld, %s).\n", fd,
		    *mapaddr, offset, *len, mmtypetostr(type));
	} else 	{
		dprint("Call to mmapfile(%d, %pp, %ld, %ld, %s).\n", fd,
		    *mapaddr, offset, *len, mmtypetostr(type));
	}

	page = sysconf(_SC_PAGESIZE);	/* page size */

	/* get mem size multiple of page size */
	size = offset / (off_t)page;
	offset = size;

	if ((type & MMREAD) != 0)
		tflag |= PROT_READ;
	if ((type & MMWRITE) != 0)
		tflag |= PROT_WRITE;

	size = *len;
	*mapaddr = mmap(addr, size, tflag, MAP_SHARED, fd, offset);
	if (*mapaddr == MAP_FAILED) {
		if (IS64BIT_OFF_T) {
			eprint("Call to mmap(%pp, %lld, %s, MAP_SHARED, "
			    "%d, %lld) failed\n",
			    addr, size, mmtypetostr(type), fd, offset);
		} else {
			eprint("Call to mmap(%pp, %ld, %s, MAP_SHARED,"
			    " %d, %ld) failed\n",
			    addr, size, mmtypetostr(type), fd, offset);
		}
		Perror("\t\t");
		return (errno);
	}

	if (IS64BIT_OFF_T) {
		dprint("Call to mmap(%pp, %lld, %s, MAP_SHARED,"
		    " %d, %lld) successful\n",
		    addr, size, mmtypetostr(type), fd, offset);
	} else {
		dprint("Call to mmap(%pp, %ld, %s, MAP_SHARED,"
		    " %d, %ld) successful\n",
		    addr, size, mmtypetostr(type), fd, offset);
	}

	errno = OK;
	return (OK);
}


/*
 * ****************************************************************************
 * function	munmapfile()
 * purpose	Wraps syscall munmap() to handle log messages and errors.
 * arguments	Same as syscall munmap():
 * returns	OK (0) upon success, otherwise either NO OK (-1) or syscall
 *		fail result code.
 * ****************************************************************************
 */

int
munmapfile(char *mapaddr, off_t len)
{
	int res;

	if (IS64BIT_OFF_T) {
		dprint("Call to munmapfile(%pp, %lld).\n", mapaddr, len);
	} else {
		dprint("Call to munmapfile(%pp, %ld).\n", mapaddr, len);
	}

	if ((res = munmap(mapaddr, (size_t)len)) < 0) {
		if (IS64BIT_OFF_T) {
			eprint("Call to munmap(%pp, %lld) failed\n",
			    mapaddr, len);
		} else {
			eprint("Call to munmap(%pp, %ld) failed\n",
			    mapaddr, len);
		}
		Perror("\t\t");
		return (res);
	}

	if (IS64BIT_OFF_T) {
		dprint("Call to munmap(%pp, %lld) successful.\n",
		    mapaddr,  len);
	} else {
		dprint("Call to munmap(%pp, %ld) successful.\n",
		    mapaddr,  len);
	}

	mapaddr = (caddr_t)0xdeadbeef;

	errno = OK;
	return (OK);
}


/*
 * ****************************************************************************
 * function	dirtyfile()
 * purpose	Use memory mapping to invalidate client cache and force
 *		operations from server.
 * arguments	fd- file descriptor of targeted file.
 *		filename- correspondent file for log messages.
 *		size of area to be mapped from offset 0. (XXX improve to value)
 * returns	OK (0) upon success, otherwise NO OK (-1).
 * ****************************************************************************
 */

int
dirtyfile(int fd, char *filename, size_t size)
{
	size_t	len;
	int	rem;
	int	page;
	void	*addr;


	page = sysconf(_SC_PAGESIZE);	/* page size */

	/* get mem size multiple of page size */
	rem = size % (off_t)page;
	len = size / (off_t)page;
	len += (rem > 0) ? page : 0;

	if ((addr = mmap((caddr_t)0, size, PROT_READ, MAP_PRIVATE, fd,
	    (off_t)0)) == NULL) {
		if (IS64BIT_OFF_T) {
			eprint("dirtyfile(%d, %s, %lld) (mmap) failed\n",
			    fd, filename, size);
		} else {
			eprint("dirtyfile(%d, %s, %ld) (mmap) failed\n",
			    fd, filename, size);
		}
		Perror("\t\t");
		return (NOOK);
	}
	if (msync(addr, len, MS_INVALIDATE) < 0) {
		if (IS64BIT_OFF_T) {
			eprint("dirtyfile(%d, %s, %lld) (msync) failed\n",
			    fd, filename, size);
		} else {
			eprint("dirtyfile(%d, %s, %ld) (msync) failed\n",
			    fd, filename, size);
		}
		Perror("\t\t");
		return (NOOK);
	}
	if (munmap(addr, (size_t)size) < 0) {
		if (IS64BIT_OFF_T) {
			eprint("dirtyfile(%d, %s, %lld) (munmap) failed\n",
			    fd, filename, size);
		} else {
			eprint("dirtyfile(%d, %s, %ld) (munamp) failed\n",
			    fd, filename, size);
		}
		Perror("\t\t");
		return (NOOK);
	}

	dprint("dirtyfile() on file %s (fildes %d) was successful.\n",
	    filename, fd);

	errno = OK;
	return (OK);
}


/*
 * ****************************************************************************
 * function     get_deleg()
 * purpose      queries what delegation type was granted to the file specified
 *              by fd.
 * arguments    fd- file descriptor of targeted file.
 *              filename- correspondent file for log messages.
 * returns      delegation type upon success, otherwise NO OK (-1).
 *		If run on a server, it returns NO OK (-1).
 * ****************************************************************************
 */

int
get_deleg(int fd, char *filename)
{
	struct nfs4_svc_args nsa;
	int dt = NOOK;

	if (srv_local == 0) {
		nsa.fd = fd;
		nsa.cmd = NFS4_DQUERY;
		nsa.netid = (char *)&dt;

		if (_nfssys(NFS4_SVC, &nsa)) {
			eprint("_nfssys NFS4_SVC\n");
			Perror("\t\t");
			return (NOOK);
		}
	} else {
		dt = NOOK;
	}

	print("delegation type granted for file %s is %d\n", filename, dt);

	return (dt);
}


/*
 * ****************************************************************************
 * function	exit_test()
 * purpose	Gracefully exit testcase when parent and child exist. It
 *		restore some signals, pass testcase statistics (pass & fail
 *		type) from child to parent, prints those statistics, killing
 *		related process when needed, and Parents waits for child to
 *		exit.
 * arguments	Exit code to be used typically OK (0) upon success,
 *		otherwise NO OK (-1).
 * returns	nothing.
 * ****************************************************************************
 */

void
exit_test(int code)
{
	pid_t Pid = 0;
	static int once = 0;
	int status;


	dprint("Call to exit_test(%d)\n", code);
	if (PidChild ==  -1)
		goto DONE;
	if (me == PARENT) {
		dprint("signal(SIGCLD, SIG_DFL) issued.\n");
		signal(SIGCLD, SIG_DFL);
		Pid = PidChild;
	} else {
		Pid = PidParent;
	}

	if (code == OK) {
		if (me == PARENT) {
			contch();
		} else {
			waitch();
		}
	}

	if (Pid >= 0) {
		if ((once == 0) && (code != OK)) {
			once++; /* send signal once */
			dprint("signal(SIGINT, SIG_IGN) issued.\n");
			signal(SIGINT, SIG_IGN);
			dprint("kill(%s, SIGINT) issued.\n",
			    (Pid == PidChild) ? "Child" : "Parent");
			kill(Pid, SIGINT);
		}
	}

	if (code == OK) {
		if (me == PARENT) {
			if (PidChild >= 0) {
				decode_errors();
				wait(&status);
			}
		} else {
			encode_errors();
		}
	}

DONE:
	Glob_status = code;
	exit(code);
}


/*
 * ****************************************************************************
 * function	kill_child()
 * purpose	Gracefully terminates child process.
 *		Parent restores some signals, and notify child to execute this
 *		function. Gets testcase statistics from child, closes its
 *		communication pipes to it, and waits for its exit.
 *		Child prints testcase statistics, send parent those statistics,
 *		close communications pipes and exits.
 * arguments	sig- not really used, but required by signal system syscall.
 * returns	nothing.
 * ****************************************************************************
 */

void
kill_child(int sig)
{
	int status;

	dprint("Call to kill_child(%d)\n", sig);
	if (me == PARENT) {
		int status;

		dprint("Killing Child.\n");

		dprint("signal(SIGCLD, SIG_DFL) issued.\n");
		signal(SIGCLD, SIG_DFL);
		if (PidChild != -1) {
			dprint("kill(Child, SIGUSR1) issued.\n");
			kill(PidChild, SIGUSR1);
		} else {
			print("kill_child()- Warning: child pid is unvalid,"\
			    " (already dead?).\n");
			return;
		}

		waitp();
		dprint("kill - decode()\n");
		decode_errors();

		/* close pipes */
		close(PChild[1]);
		dprint("Fildes %d (pipe end PChild[1]) was closed.\n",
		    PChild[1]);
		close(PParent[0]);
		dprint("Fildes %d (pipe end PParent[0]) was closed.\n",
		    PParent[0]);

		wait(&status);
		dprint("Child exited with status %d\n", status);

		PidChild = -1;

	} else { /* child */
		admerrors(TOTALS);

		contp();
		dprint("kill - encode()\n");
		encode_errors();

		/* close pipes */
		close(PChild[0]);
		dprint("Fildes %d (pipe end PChild[0]) was closed.\n",
		    PChild[0]);
		close(PParent[1]);
		dprint("Fildes %d (pipe end PParent[1]) was closed.\n",
		    PParent[1]);

		exit(OK);
	}
}


/*
 * ****************************************************************************
 * function	encode_errors()
 * purpose	Child sends the parent, its testcase execution (pass &
 *		fail type) statistics.
 * arguments	none.
 * returns	nothing.
 * ****************************************************************************
 */

void
encode_errors(void)
{
	dprint("Call to encode_errors()\n");
	sendintp(errflag);
	sendintp(tsflag);
	sendintp(aflag);
	sendintp(tspflag);
	sendintp(apflag);
}


/*
 * ****************************************************************************
 * function	decode_errors()
 * purpose	Parent receives its child testcase execution (pass &
 *		fail type) statistics.
 * arguments	none.
 * returns	nothing.
 * ****************************************************************************
 */

void
decode_errors(void)
{
	int a, ts, err, ap, tsp;

	dprint("Call to decode_errors()\n");
	err = getintp();
	dprint("Child reported %d errors.\n", err);
	ts = getintp();
	dprint("Child reported %d test steps failed.\n", ts);
	a = getintp();
	dprint("Child reported %d assertions failed.\n", a);
	tsp = getintp();
	dprint("Child reported %d test steps passed.\n", tsp);
	ap = getintp();
	dprint("Child reported %d assertions passed.\n", ap);

	errflag += err;
	tsflag += ts;
	tsprev += ts;
	aflag += a;
	tspflag += tsp;
	apflag += ap;

	if (debug) {
		admerrors(TOTALS);
	}
}


/*
 * ****************************************************************************
 * function	notify_parent()
 * purpose	Used to handle signals and terminate testcase gracefully.
 *		It is issued by the system only.
 * arguments	Signal received by system.
 * returns	nothing.
 * ****************************************************************************
 */

void
notify_parent(int sig)
{
	print("Call to notify_parent(signal received %s)\n", sigtostr(sig));
	perror("last error registered: ");

	exit_test(NOOK);
}


/*
 * ****************************************************************************
 * function	notify_child()
 * purpose	Used to handle signals and terminate testcase gracefully.
 *		It is issued by the system only.
 * arguments	Signal received by system.
 * returns	nothing.
 * ****************************************************************************
 */

void
notify_child(int sig)
{
	(void) print("Call to notify_child(signal received %s)\n",
	    sigtostr(sig));
	perror("last error registered: ");

	exit_test(NOOK);
}


/*
 * ****************************************************************************
 * function	childisdead()
 * purpose	Used to notify child was killed by signal X.
 *		System initiated only.
 * arguments	Signal received by system.
 * returns	nothing.
 * ****************************************************************************
 */

void
childisdead(int sig)
{
	(void) print("Call to childisdead(signal received %d)\n",
	    sigtostr(sig));
}


/*
 * ****************************************************************************
 * function	say_bye(void)
 * purpose	prints a message the either Child or Parent is exiting.
 * arguments	None.
 * returns	nothing.
 * ****************************************************************************
 */

void
say_bye(void)
{
	/* global var Glob_status keeps the status at exit time */
	if (Glob_status == OK || Glob_status == UNTESTED) {
		dprint("Process terminating ...\n");
	} else {
		(void) print("UNRESOLVED: aborting execution.\n\n\n");
	}
}



/*
 * ****************************************************************************
 * function	insert_bye(void)
 * purpose	insert the function say_bye with atexit() once only.
 * arguments	None.
 * returns	nothing.
 * ****************************************************************************
 */

void
insert_bye(void)
{
	/* global var byeflag keeps count of calls to this function */
	if (byeflag == 0) {
		atexit(say_bye);
	}
	byeflag++;
}


/*
 * ****************************************************************************
 * function	initialize()
 * purpose	Create communication pipes, forks a child (reseting testcase
 *		statistics on it), set some signal catching, PIDs information
 *		and closes unused ends of pipes.
 * arguments	none.
 * returns	nothing.
 * ****************************************************************************
 */

void
initialize(void)
{
	dprint("Call to initialize()\n");
	dprint("Initializing and forking child.\n");

	init_comm();

	PidParent = getpid();
	dprint("Pid is %d.\n", PidParent);

	/* flush stdout and stderr before continuing */
	(void) fflush(stdout);
	(void) fflush(stderr);

	/* Fork child */
	if ((PidChild = fork()) == 0) {
		/* reset error counters */
		errflag = 0;		/* Number of errors */
		tsflag = 0;		/* Number of test steps failed */
		tsprev = 0;		/* Previous value for tsflag */
		aflag = 0;		/* Number of assertions failed */
		tspflag = 0;		/* Number of successful test steps */
		apflag = 0;		/* Number of successful assertions */
		serrflag = 0;	/* Number of errors scenario */
		stsflag = 0;	/* Number of test steps failed scenario */
		saflag = 0;	/* Number of assertions failed scenario */
		stspflag = 0;	/* Number of succesful test steps scenario */
		sapflag = 0;	/* Number of successful assertions scenario */
		me = CHILD;
		PidChild = getpid();
		dprint("Pid is %d.\n", PidChild);
		dprint("signal(SIGINT, notify_parent) issued.\n");
		signal(SIGINT, notify_parent);
		dprint("signal(SIGUSR1, kill_child) issued.\n");
		signal(SIGUSR1, kill_child);

		/* finish pipes config, closing unused ends */
		close(PChild[1]);
		dprint("Fildes %d (pipe end PChild[1]) was closed.\n",
		    PChild[1]);
		close(PParent[0]);
		dprint("Fildes %d (pipe end PParent[0]) was closed.\n",
		    PParent[0]);
	} else {
		me = PARENT;
		dprint("signal(SIGINT, notify_child) issued.\n");
		signal(SIGINT, notify_child);
		dprint("signal(SIGCLD, childisdead) issued.\n");
		signal(SIGCLD, childisdead);

		/* finish pipes config, closing unused ends */
		close(PChild[0]);
		dprint("Fildes %d (pipe end PChild[0]) was closed.\n",
		    PChild[0]);
		close(PParent[1]);
		dprint("Fildes %d (pipe end PParent[1]) was closed.\n",
		    PParent[1]);
	}
	insert_bye();
}


/*
 * ****************************************************************************
 * function	init_comm()
 * purpose	Create communication pipes using global vars PParent and PChild.
 * arguments	none.
 * returns	nothing.
 * ****************************************************************************
 */

void
init_comm(void)
{
	dprint("Call to init_comm()\n");
	if (pipe(PParent) < 0 || pipe(PChild) < 0) {
		(void) print("init_comm(): Pipe creation error.\n");
		perror("\t\t");
		exit_test(NOOK);
	}

	dprint("Pipes initialized:\n");
	dprint("\tPParent[0] = %d\n", PParent[0]);
	dprint("\tPParent[1] = %d\n", PParent[1]);
	dprint("\tPChild[0] = %d\n", PChild[0]);
	dprint("\tPChild[1] = %d\n\n", PChild[1]);
}


/*
 * ****************************************************************************
 * function	sendintp()
 * purpose	Sends an integer value to parent.
 * arguments	val- value to send.
 * returns	nothing.
 * ****************************************************************************
 */

void
sendintp(int val)
{
	int i = val;
	int res;

	dprint("Call to sendintp(%d)\n", i);
	dprint("Sending <%x> thru PParent[%d].\n", i, 1);
	if ((res = nfsgenWrite(PParent[1], &i, sizeof (i))) != sizeof (i)) {
		(void) print("Pipe write error (res=%d)\n", res);
		perror("\t\t");
		return;
	}

	dprint("<%d> sent thru PParent[%d].\n", i, 1);
	waitch();
}


/*
 * ****************************************************************************
 * function	getintp()
 * purpose	Receives an integer value send from child.
 * arguments	none.
 * returns	Integer received.
 * ****************************************************************************
 */

int
getintp(void)
{
	int i = -1;
	int res;

	dprint("Call to getintp()\n");
	if ((res = nfsgenRead(PParent[0], &i, sizeof (i))) != sizeof (i)) {
		(void) print("Pipe read error (res=%d)\n", res);
		perror("\t\t");
		return (-1);
	}

	dprint("<%d> received from PParent[%d].\n", i, 0);
	contch();

	return (i);
}


/*
 * Set of routines to sync parent and child to control test step
 *  (and assertion) execution.
 */


/*
 * ****************************************************************************
 * function	contch()
 * purpose	Signal child to continue execution.
 * arguments	None.
 * returns	nothing.
 * ****************************************************************************
 */

void
contch(void)
{
	char buf[] = "CHILD";
	char tmp[10];
	int st = 0;

	dprint("Call to contch()\n");
	(void) strlcpy(tmp, buf, 2);
	dprint("Sending <%s> thru PChild[%d].\n", tmp, 1);

	if ((st = nfsgenWrite(PChild[1], buf, 1)) != 1) {
		(void) print("<%s> (size=%d) sent thru PChild[%d] status %d.\n",
		    buf, st, 1, errno);
		(void) print("Pipe write error\n");
		perror("\t\t");
		exit_test(NOOK);
	}

	dprint("<%s> sent thru PChild[%d].\n", strncpy(tmp, buf, 1), 1);
}


/*
 * ****************************************************************************
 * function	waitch()
 * purpose	Child waits for parent to signal continue execution.
 * arguments	None.
 * returns	nothing.
 * ****************************************************************************
 */

void
waitch(void)
{
	char	buf[10];
	int st = 0;

	dprint("Call to waitch()\n");
	if ((st = nfsgenRead(PChild[0], buf, 1)) != 1) {
		(void) print("<%s> (size=%d) received from PChild[%d] "\
		    "status %d.\n", buf, st, 0, errno);
		(void) print("Pipe read error\n");
		perror("\t\t");
		exit_test(NOOK);
	}

	if (buf[0] != CHILD) {
		(void) print("Incorrect pipe data (%c != %c)\n", buf[0], CHILD);
		exit_test(NOOK);
	}
	buf[1] = '\0';
	dprint("<%s> received from PChild[%d].\n", buf, 0);
}


/*
 * ****************************************************************************
 * function	contp()
 * purpose	Signal parent to continue execution.
 * arguments	None.
 * returns	nothing.
 * ****************************************************************************
 */

void
contp(void)
{
	char buf[] = "PARENT";
	char tmp[10];
	int st = 0;

	dprint("Call to contp()\n");
	(void) strlcpy(tmp, buf, 2);
	dprint("Sending <%s> thru PParent[%d].\n", tmp, 1);

	if ((st = nfsgenWrite(PParent[1], buf, 1)) != 1) {
		(void) print("<%s> (size=%d) sent thru PParent[%d] "\
		    "status %d.\n", buf, st, 1, errno);
		(void) print("Pipe write error\n");
		perror("\t\t");
		exit_test(NOOK);
	}

	dprint("<%s> sent thru PParent[%d].\n",
	    strncpy(tmp, buf, 1), 1);
}


/*
 * ****************************************************************************
 * function	waitp()
 * purpose	Parent waits for child to signal continue execution.
 * arguments	None.
 * returns	nothing.
 * ****************************************************************************
 */

void
waitp(void)
{
	char buf[10];
	int st = 0;

	dprint("Call to waitp()\n");
	if ((st = nfsgenRead(PParent[0], buf, 1)) != 1) {
		(void) print("<%s> (size=%d) received from PParent[%d] "\
		    "status %d.\n", buf, st, 0, errno);
		(void) print("Pipe read error\n");
		perror("\t\t");
		exit_test(NOOK);
	}
	if (buf[0] != PARENT) {
		(void) print("Incorrect pipe data (%c != %c)\n",
		    buf[0], PARENT);
		exit_test(NOOK);
	}
	buf[1] = '\0';

	dprint("<%s> received from PParent[%d].\n", buf, 0);
}


/*
 * ****************************************************************************
 * function	wait_get_cresult()
 * purpose	Signal child to get the test result in child
 * arguments	None.
 * returns	nothing.
 * ****************************************************************************
 */

int
wait_get_cresult(void)
{
	char buf[] = "RESULT";
	char tmp[10];
	int st = 0;
	int ret = OK;

	dprint("Call to wait_get_cresult()\n");
	(void) strlcpy(tmp, buf, 2);
	dprint("Sending <%s> thru PChild[%d].\n", tmp, 1);

	if ((st = nfsgenWrite(PChild[1], buf, 1)) != 1) {
		(void) print("<%s> (size=%d) sent thru PChild[%d] status %d.\n",
		    buf, st, 1, errno);
		(void) print("Pipe write error\n");
		perror("\t\t");
		exit_test(NOOK);
	}
	dprint("<%s> sent thru PChild[%d].\n", strncpy(tmp, buf, 1), 1);

	if ((st = nfsgenRead(PParent[0], buf, 1)) != 1) {
		(void) print("<%s> (size=%d) received from PParent[%d] "\
		    "status %d.\n", buf, st, 0, errno);
		(void) print("Pipe read error\n");
		perror("\t\t");
		exit_test(NOOK);
	}

	switch (buf[0]) {
	case 'F':
		ret = NOOK;
		break;
	case 'P':
		ret = OK;
		break;
	default:
		(void) print("Incorrect pipe data (%c)\n", buf[0]);
		exit_test(NOOK);
	}
	buf[1] = '\0';
	dprint("<%s> received from PParent[%d].\n", buf, 0);
	dprint("ret=%d", ret);
	return (ret);
}

/*
 * ****************************************************************************
 * function	wait_send_cresult()
 * purpose	Child waits for parent to signal get execution result.
 * arguments	None.
 * returns	nothing.
 * ****************************************************************************
 */

int
wait_send_cresult(void)
{
	char buf[10];
	int st = 0;

	dprint("Call to wait_send_cresult()\n");
	if ((st = nfsgenRead(PChild[0], buf, 1)) != 1) {
		(void) print("<%s> (size=%d) received from PChild[%d] "\
		    "status %d.\n", buf, st, 0, errno);
		(void) print("Pipe read error\n");
		perror("\t\t");
		exit_test(NOOK);
	}

	if (buf[0] == 'R') {
		buf[1] = '\0';
		dprint("<%s> received from PChild[%d].\n", buf, 0);
		if (aflag != 0)
			(void) strcpy(buf, "FAIL");
		else
			(void) strcpy(buf, "PASS");
		dprint("Sending <%s> thru PParent[%d].\n", buf, 1);

		if ((st = nfsgenWrite(PParent[1], buf, 1)) != 1) {
			(void) print("<%s> (size=%d) sent thru PParent[%d] "\
			    "status %d.\n", buf, st, 1, errno);
			(void) print("Pipe write error\n");
			perror("\t\t");
			exit_test(NOOK);
		}
		dprint("<%s> sent thru PParent[%d].\n", buf, 1);
	} else {
		(void) print("Incorrect pipe data (%c != %c)\n", buf[0], 'R');
		exit_test(NOOK);
	}

	return (OK);
}

/*
 * ****************************************************************************
 * function     clientinfo()
 * purpose      Prints client information: name, release, version and machine
 *              type.
 * arguments    none.
 * returns      nothing.
 * ****************************************************************************
 */

void
clientinfo(void)
{
	struct utsname mn;

	/* print the system information */
	if ((uname(&mn)) == -1) {
		(void) fprintf(stderr, "warning uname() failed=%s\n",
		    strerror(errno));
	}
	(void) fprintf(stdout, "system info: %s %s %s %s %s\n\n\n", mn.nodename,
	    mn.sysname, mn.release, mn.version, mn.machine);
	(void) fflush(stdout);
}


/*
 * ****************************************************************************
 * function	starttime()
 * purpose	Prints start time of an event (usually the current testcase).
 * arguments	msg- header of time stamp, or NULL if no header needed.
 * returns	nothing.
 * ****************************************************************************
 */

void
starttime(char *msg)
{
	char *timeStr;

	if (msg != NULL)
		(void) fprintf(stdout, "%s", msg);

	/* print the current date & time that the test started */
	gettimeofday(&tpstart, (void *)NULL);
	timeStr = ctime((clock_t *)&tpstart.tv_sec);
	(void) fprintf(stdout, "START TIME: %s\n", timeStr);
	(void) fflush(stdout);
}


/*
 * ****************************************************************************
 * function	endtime()
 * purpose	Prints ending time of an event (usually the testcase).
 * arguments	msg- header of time stamp, or NULL if no header needed.
 * returns	nothing.
 * ****************************************************************************
 */

void
endtime(char *msg)
{
	char *timeStr;

	if (msg != NULL)
		(void) fprintf(stdout, "%s", msg);

	gettimeofday(&tpend, (void *)NULL);
	timeStr = ctime((clock_t *)&tpend.tv_sec);
	(void) fprintf(stdout, "END TIME:   %s\n", timeStr);
	(void) fflush(stdout);
}


/*
 * ****************************************************************************
 * function	rsh_cmd()
 * purpose	Execute command on remote host as user.
 * arguments	cmd- command to execute.
 *		rhost- remote host name or IP address.
 *		user- target user on rhost.
 *		file- path and filename of .out (stdout) and .err (stderr) files
 * returns	nothing.
 * ****************************************************************************
 */

int
rsh_cmd(char *cmd, char *rhost, char *user, char *file)
{
	int res;
	char buf[2048];

	/* execute testname in remote host as user and capture output */
	(void) snprintf(buf, 2048,
	    "ssh %s@%s \"%s\" > %s.out 2> %s.err &",
	    user, rhost, cmd, file, file);

	dprint("Executing remotely on %s:\n%s\n", rhost, buf);

	if ((res = system(buf)) < 0) {
		eprint("Cannot start %s on %s. terminating ...\n",
		    Testname, rhost);
	}

	return (res);
}


/*
 * ****************************************************************************
 * function	cd_to_odir()
 * purpose	Restore original PWD at exit of testcase.
 * arguments	none.
 * returns	nothing.
 * ****************************************************************************
 */

void
cd_to_odir(void)
{
	(void) strcpy(cwd, odir);
	(void) chdir(cwd);
}


/*
 * ****************************************************************************
 * function	Usage()
 * purpose	Print testcase parameter usage.
 * arguments	none.
 * returns	nothing.
 * ****************************************************************************
 */

void
Usage(void)
{
	(void) printf("usage: %s -u testuser_uid -g testuser_gid [-heSDEWm]\n"
	    "[-d debug_level] [-p perms] [-f flags] [-t delay]\n"
	    "-l filename -U other_uid -G other_gid [test_directory]\n",
	    Testname);
	(void) printf("Where:\n");
	(void) printf("-u uid to seteuid for user that runs "\
	    "most of this tests\n");
	(void) printf("-g gid to setegid for user that runs "\
	    "most of this tests\n");
	(void) printf("-U uid to seteuid for testing access as other user\n");
	(void) printf("-G gid to setegid for testing access as other user\n");
	(void) printf("-t delay time delay\n");
	(void) printf("-h Help - print this usage info\n");
	(void) printf("-s to notify this process is running on the server\n");
	(void) printf("-e synchronize stderr to stdout to check results, "\
	    "default off\n");
	(void) printf("-S force writes to server and reads from server, "\
	    "invalidating client cache\n");
	(void) printf("-D turn debug messages on\n");
	(void) printf("-E turn error messages on\n");
	(void) printf("-W cause mandatory locks to avoid waiting\n");
	(void) printf("-d debug_level	0 - none, 1 - error mmsgs, "\
	    "2 - error and debug msgs\n");
	(void) printf("-m turn on use of mmap for reads/writes\n");
	(void) printf("-l file path and filename of test file\n");
	(void) printf("-p perm	creation permissions for test file\n");
	(void) printf("-f flags for test file");
	(void) printf("test_directory	is the working directory to be used"\
	    " by this testcase\n");
}


/*
 * ****************************************************************************
 * function	parse_args()
 * purpose	parse testcase arguments, set flags and allocate global memory.
 * arguments	argc and argv from main().
 * returns	nothing.
 * ****************************************************************************
 */

void
parse_args(int argc, char **argv)
{
	int c;
	char *buf;
	extern int optind;
	extern char *optarg;
	int errflg = 0;
	int i, j;
	unsigned int x;
	mode_t old_mask;

	old_mask = umask(0000);
	dprint("Old umask 0%o, new umask 0000\n", old_mask);

	dprint("Call to parse_args()\n");
	Testname = argv[0];

	if ((buf = getenv("SYNCWRITE")) != NULL) {
		if (strcasecmp(buf, "ON") == 0)
			SYNCWRITE = 1;
		if (strcasecmp(buf, "OFF") == 0)
			SYNCWRITE = 0;
	}

	if ((buf = getenv("SHOWERROR")) != NULL) {
		if (strcasecmp(buf, "ON") == 0)
			showerror = 1;
		if (strcasecmp(buf, "OFF") == 0)
			showerror = 0;
	}


	/* allocate mem for vars */
	while ((c = getopt(argc, argv, "u:g:U:G:d:l:t:p:hseSDEWmn")) != -1) {
		switch (c) {
		case 'u':
			(void) sscanf(optarg, "%d", &i);
			uid = i;
			break;
		case 'g':
			(void) sscanf(optarg, "%d", &i);
			gid = i;
			break;
		case 'U':
			(void) sscanf(optarg, "%d", &i);
			uid2 = i;
			break;
		case 'G':
			(void) sscanf(optarg, "%d", &i);
			gid2 = i;
			break;
		case 'd':
			(void) sscanf(optarg, "%d", &debug);
			switch (debug) {
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
				errflg++;
				Usage();
				exit(-1);
			}
			break;
		case 'l':	/* local path and filename for testfile */
			(void) strcpy(lfilename, optarg);
			break;
		case 't':	/* permission for testfile */
			(void) sscanf(optarg, "%o", &x);
			delay = x;
			break;
		case 'p':	/* permission for testfile */
			(void) sscanf(optarg, "%o", &x);
			lperms = x;
			break;
		case 'f':	/* flags for testfile */
			(void) sscanf(optarg, "%o", &x);
			lflags = x;
			break;
		case 'h':
			Usage();
			exit(0);
			break;	/* unreachable, used to quiet lint */
		case 's':
			srv_local = 1;
			break;
		case 'e':
			errtoout = 1;
			break;
		case 'S':
			SYNCWRITE = 1;
			break;
		case 'D':
			debug = 1;
			break;
		case 'E':
			showerror = 1;
			break;
		case 'W':
			NBlocks = 1;
			break;
		case 'm':
			mmflag = 1;
			break;
		case 'n':
			skip_getdeleg = 1;
			break;
		default:
			errflg++;
			Usage();
			exit(-1);
		}
	}

	/* check for  mandatory flags */
	if (uid < 0 || gid < 0 || uid2 < 0 || gid2 < 0) {
		errflg++;
	}

	if (optind < argc) {	/* get test dir and cd to it */
		char *dirtmp;

		if (getcwd(odir, 512) == NULL) {
			(void) fprintf(stderr,
			    "Warning: Cannot get original CDW\n");
			(void) strcpy(odir, ".");
		}
		(void) strcpy(cwd, argv[optind]);
		(void) chdir(cwd);
		dirtmp = getcwd(NULL, 512);
		if (dirtmp != NULL) {
			if (strcmp(cwd, dirtmp) != 0) {
				(void) fprintf(stderr,
				    "ERROR: cd %s failed, cwd %s\n",\
				    cwd, dirtmp);
				errflg++;
			} else { /* register func to cd to original dir */
				if (atexit(cd_to_odir) != 0) {
					(void) fprintf(stderr,
					    "Wanrning: atexit() "\
					    "failed, cd to original dir "\
					    " won't be possible\n");
				}
			}
		free(dirtmp);
		}
	}

	if (errflg) {
		Usage();
		exit(-1);
	}

	insert_bye();

	/* sync stderr to stdout, by making them the same */
	if (errtoout != 0) {
		dprint("Synchronicing stderr to stdout ...\n");
		dprint("dup2(stdout, stderr) result %d.\n", dup2(1, 2));
	}

	if ((buf = getenv("LEASE_TIME")) != NULL) {
		renew = atoi(buf);
		/* default value */
		if (renew > 1800) {
			(void) printf("lease renewal period too long (%d), "\
			    "180 seconds will be used in test.\n", renew);
		}
		if (renew < 0 || renew > 1800)
			renew = 180;
	}

	if ((GLOBdata = malloc(256)) == NULL) {
		perror("main()- malloc() for GLOBdata");
		Glob_status = NOOK;
		exit(NOOK);
	}


	if (getuid() != 0 && geteuid() != 0) {
		(void) print("This program must be run as root. "\
		    "Quitting ...\n");
		Glob_status = 1;
		exit(1);
	}

	if (Setegid(gid) < 0) {
		(void) print("Main, setegid(%d) failed quitting ...\n", gid);
		Glob_status = 1;
		exit(1);
	}

	if (Seteuid(uid) < 0) {
		(void) print("Main, seteuid(%d) failed quitting ...\n", uid);
		Glob_status = 1;
		exit(1);
	}
}
