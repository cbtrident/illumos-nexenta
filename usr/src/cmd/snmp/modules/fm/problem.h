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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
 */

#ifndef	_PROBLEM_H
#define	_PROBLEM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

#include <libnvpair.h>
#include <libuutil.h>

typedef struct sunFmProblem_data {
	int		d_valid;
	uu_avl_node_t	d_uuid_avl;
	const char	*d_aci_uuid;
	const char	*d_aci_code;
	const char	*d_aci_type;
	const char	*d_aci_severity;
	const char	*d_aci_url;
	const char	*d_aci_desc;
	const char	*d_aci_fmri;
	const char	*d_diag_engine;
	struct timeval	d_diag_time;
	uint32_t	d_nsuspects;
	nvlist_t	**d_suspects;
	nvlist_t	*d_aci_event;
	uint8_t		*d_statuses;
} sunFmProblem_data_t;

typedef nvlist_t sunFmFaultEvent_data_t;
typedef uint8_t sunFmFaultStatus_data_t;

void sunFmProblemTable_init(void);
void sunFmProblemTable_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _PROBLEM_H */
