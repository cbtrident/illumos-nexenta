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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#include <scsi/libses.h>
#include <scsi/plugins/ses/framework/ses2_impl.h>

/*
 * Override bay number if the invalid bit is set for the AES descriptor
 */
static int
lenovo_d12_fix_bay(ses_plugin_t *sp, ses_node_t *np)
{
        ses2_aes_descr_eip_impl_t *dep;
        ses2_aes_descr_sas0_eip_impl_t *s0ep;
        size_t len;
        int nverr;
        nvlist_t *props = ses_node_props(np);

        /*
         * The spec conveniently defines the bay number as part of the
         * additional element status descriptor. However, the AES descriptor
         * is technically only valid if the device is inserted.
         * Thankfully, the Lenovo enclosure defines this value even if
         * the invalid bit is set, so we override bay value, even for empty
         * bays.
         */
        if ((dep = ses_plugin_page_lookup(sp, ses_node_snapshot(np),
            SES2_DIAGPAGE_ADDL_ELEM_STATUS, np, &len)) == NULL)
                return (0);

        if (dep->sadei_protocol_identifier != SPC4_PROTO_SAS ||
            !dep->sadei_eip || !dep->sadei_invalid)
                return (0);

        s0ep = (ses2_aes_descr_sas0_eip_impl_t *)dep->sadei_protocol_specific;

        SES_NV_ADD(uint64, nverr, props, SES_PROP_BAY_NUMBER,
            s0ep->sadsi_bay_number);

        return (0);
}

/*
 * Lenovo specific ses node parsing is needed to get bay numbers from empty bays
 */
static int
lenovo_d12_parse_node(ses_plugin_t *sp, ses_node_t *np)
{
	uint64_t type;
	nvlist_t *props;

	if (ses_node_type(np) != SES_NODE_ELEMENT)
		return (0);

	props = ses_node_props(np);
	type = fnvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE);
	if (type != SES_ET_ARRAY_DEVICE)
		return (0);

	return (lenovo_d12_fix_bay(sp, np));
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_node_parse = lenovo_d12_parse_node
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION, &config) != 0);
}
