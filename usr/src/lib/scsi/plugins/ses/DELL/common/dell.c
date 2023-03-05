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
 * Copyright 2023 Tintri by DDN, Inc. All rights reserved.
 */

#include <scsi/libses.h>
#include <scsi/libses_plugin.h>

/*
 * Dell enclosures do not provide serial number, but have service tag
 * that can be used in its place.
 *
 * Add the service tag to both parent (root) and enclosure (current) nodes,
 * same as done in libses when creating snapshot skeleton.
 */

#define	DELL_DP_B2	0xb2

ses_pagedesc_t dell_pages[] = {
{
	.spd_pagenum = DELL_DP_B2,
	.spd_index = NULL,
	.spd_req = SES_REQ_OPTIONAL_STANDARD,
	.spd_gcoff = -1,
},
{
	.spd_pagenum = -1,
	.spd_gcoff = -1,
},
};

/*
 * The actual page contents are bigger than this, but we are only interested in
 * service tag at the moment.
 */
typedef struct {
	uint8_t	pad1[36];
	char	svctag[10];
} __packed dell_dp_b2_t;

static int
dell_fill_enc_node(ses_plugin_t *sp, ses_node_t *np)
{
	ses_snap_t *snap;
	ses_node_t *pnp;
	nvlist_t *pr, *ppr;
	dell_dp_b2_t *page;
	size_t plen, slen;
	int nverr;

	pnp = ses_node_parent(np);
	ppr = ses_node_props(pnp);
	/* Check if root node already has serial property set */
	if (nvlist_exists(ppr, SCSI_PROP_USN))
		return (0);

	pr = ses_node_props(np);
	snap = ses_node_snapshot(np);
	page = ses_plugin_page_lookup(sp, snap, DELL_DP_B2, np, &plen);
	if (page == NULL)
		return (0);

	/* Trim trailing whitespaces */
	slen = sizeof (page->svctag);
	while (*(page->svctag + slen - 1) == ' ')
		slen--;
	SES_NV_ADD(fixed_string, nverr, pr, SCSI_PROP_USN, page->svctag, slen);
	SES_NV_ADD(fixed_string, nverr, ppr, SCSI_PROP_USN, page->svctag, slen);

	return (0);
}

static int
dell_parse_node(ses_plugin_t *sp, ses_node_t *np)
{
	switch (ses_node_type(np)) {
	case SES_NODE_ENCLOSURE:
		return (dell_fill_enc_node(sp, np));
	default:
		return (0);
	}
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_node_parse = dell_parse_node,
		.spc_pages = dell_pages,
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION, &config) != 0);
}
