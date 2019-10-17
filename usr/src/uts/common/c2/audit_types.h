/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
 */

/*
 * c2/audit.h has become a giant melting pot of header includes.
 * That is causing problems elsewhere, especially in NFS.
 * This is intended to include only the very basics
 * that we need in other modules.
 * Some typedefs for the fundamentals.
 */

#ifndef	_BSM_AUDIT_TYPES_H
#define	_BSM_AUDIT_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif


typedef uint_t au_asid_t;
typedef uint_t  au_class_t;
typedef ushort_t au_event_t;
typedef ushort_t au_emod_t;
typedef uid_t au_id_t;

/*
 * An audit event mask.
 */
#define	AU_MASK_ALL	0xFFFFFFFF	/* all bits on for unsigned int */
#define	AU_MASK_NONE	0x0		/* all bits off = no:invalid class */

struct au_mask {
	unsigned int	am_success;	/* success bits */
	unsigned int	am_failure;	/* failure bits */
};
typedef struct au_mask au_mask_t;
#define	as_success am_success
#define	as_failure am_failure

#ifdef __cplusplus
}
#endif

#endif /* _BSM_AUDIT_TYPES_H */
