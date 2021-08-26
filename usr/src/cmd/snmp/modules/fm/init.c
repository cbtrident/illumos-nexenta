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
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "fm_snmp.h"
#include "module.h"
#include "problem.h"
#include "resource.h"

const char *const modname = "fm";

void
init_fm(void)
{
	sunFmModuleTable_init();
	sunFmProblemTable_init();
	sunFmResourceTable_init();
}

void
deinit_fm(void)
{
	sunFmModuleTable_fini();
	sunFmProblemTable_fini();
	sunFmResourceTable_fini();
}
