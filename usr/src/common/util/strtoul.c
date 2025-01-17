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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#if	defined(_KERNEL) && !defined(_BOOT)
#include <sys/null.h>
#include <sys/errno.h>
#else	/* _KERNEL && !_BOOT */
#if	!defined(_BOOT) && !defined(_KMDB) && !defined(_STANDALONE)
#include "lint.h"
#endif	/* !_BOOT && !_KMDB && !_STANDALONE */
#if	defined(_STANDALONE)
#include <sys/cdefs.h>
#include <stand.h>
#include <limits.h>
#else
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#endif	/* _STANDALONE */
#endif	/* _KERNEL && !_BOOT */
#include "strtolctype.h"
#include <sys/types.h>

#if	defined(_KERNEL) && !defined(_BOOT)
int
ddi_strtoul(const char *str, char **nptr, int base, unsigned long *result)
#else	/* _KERNEL && !_BOOT */
unsigned long
strtoul(const char *str, char **nptr, int base)
#endif	/* _KERNEL && !_BOOT */
{
	unsigned long val;
	int c;
	int xx;
	int neg = 0;
	unsigned long multmax;
	const char **ptr = (const char **)nptr;
	const unsigned char *ustr = (const unsigned char *)str;

	if (ptr != NULL)
		*ptr = (char *)ustr; /* in case no number is formed */
	if (base < 0 || base > MBASE || base == 1) {
		/* base is invalid -- should be a fatal error */
#if	defined(_KERNEL) && !defined(_BOOT)
		return (EINVAL);
#else	/* _KERNEL && !_BOOT */
		errno = EINVAL;
		return (0);
#endif	/* _KERNEL && !_BOOT */
	}
	if (!isalnum(c = *ustr)) {
		while (isspace(c))
			c = *++ustr;
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *++ustr;
		}
	}
	if (base == 0) {
		if (c != '0')
			base = 10;
		else if (ustr[1] == 'x' || ustr[1] == 'X')
			base = 16;
		else
			base = 8;
	}
	/*
	 * for any base > 10, the digits incrementally following
	 *	9 are assumed to be "abc...z" or "ABC...Z"
	 */
	if (!lisalnum(c) || (xx = DIGIT(c)) >= base) {
		/* no number formed */
#if	defined(_KERNEL) && !defined(_BOOT)
		return (EINVAL);
#else	/* _KERNEL && !_BOOT */
		return (0);
#endif	/* _KERNEL && !_BOOT */
	}
	if (base == 16 && c == '0' && (ustr[1] == 'x' || ustr[1] == 'X') &&
	    isxdigit(ustr[2]))
		c = *(ustr += 2); /* skip over leading "0x" or "0X" */

	multmax = ULONG_MAX / (unsigned long)base;
	val = DIGIT(c);
	for (c = *++ustr; lisalnum(c) && (xx = DIGIT(c)) < base; ) {
		if (val > multmax)
			goto overflow;
		val *= base;
		if (ULONG_MAX - val < (unsigned long)xx)
			goto overflow;
		val += xx;
		c = *++ustr;
	}
	if (ptr != NULL)
		*ptr = (char *)ustr;
#if	defined(_KERNEL) && !defined(_BOOT)
	*result = neg ? -val : val;
	return (0);
#else	/* _KERNEL && !_BOOT */
	return (neg ? -val : val);
#endif	/* _KERNEL && !_BOOT */

overflow:
	for (c = *++ustr; lisalnum(c) && (xx = DIGIT(c)) < base; (c = *++ustr))
		;
	if (ptr != NULL)
		*ptr = (char *)ustr;
#if	defined(_KERNEL) && !defined(_BOOT)
	return (ERANGE);
#else	/* _KERNEL && !_BOOT */
	errno = ERANGE;
	return (ULONG_MAX);
#endif	/* _KERNEL && !_BOOT */
}
