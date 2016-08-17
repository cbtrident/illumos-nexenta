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
 * A program to become another unix user or kerberos principal
 * to execute specified command.
 *
 * Usage: chg_usr_exec [-k kpassword ] <login> <commands>
 *		-k kpassword	Kerberos password if login is specified
 *				to a kerberos principal.
 *		login		a unix user or kerberos principal
 *		command 	Soaris command or executable file executed
 *				by login.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>

#define	BUFSIZE 10240

void
usage(char *cmd)
{
	(void) printf("\tUsage: %s [-k kpassword ] <login> <commands> ...\n",
	    cmd);
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *plogin = NULL;
	char cmds[BUFSIZE] = { 0 };
	char sep[] = " ";
	struct passwd *ppw = NULL;
	char *kpasswd = NULL;
	int c, i, len;

	while ((c = getopt(argc, argv, "k:")) != -1) {
		switch (c) {
			case 'k':
				kpasswd = optarg;
				break;
			default:
				usage(argv[0]);
				break;
		}
	}

	if ((argc-optind) < 2 || strlen(argv[optind]) == 0)
		usage(argv[0]);

	len = 0;
	plogin = argv[optind];
	if (kpasswd) {
		(void) snprintf(cmds, sizeof (cmds),
		    "echo %s | kinit %s > /dev/null && ", kpasswd, plogin);
		len = strlen(cmds);
	}

	for (i = optind + 1; i < argc; i++) {
		(void) snprintf(cmds+len, sizeof (cmds)-len,
		    "%s%s", argv[i], sep);
		len += strlen(argv[i]) + strlen(sep);
	}

	if ((ppw = getpwnam(plogin)) == NULL) {
		(void) printf("User(%s) isn't found,getpwnam() returns NULL",
		    plogin);
		return (1);
	}
	if (setgid(ppw->pw_gid) != 0) {
		perror("setgid");
		return (errno);
	}
	if (setuid(ppw->pw_uid) != 0) {
		perror("setuid");
		return (errno);
	}

	if (execl("/usr/xpg4/bin/sh", "sh",  "-c", cmds, (char *)0) != 0) {
		perror("execl");
		return (errno);
	}

	return (0);
}
