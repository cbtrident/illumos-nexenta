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
 * Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
 */

#include <stddef.h>
#include <libnvpair.h>
#include <scsi/libses.h>
#include <scsi/libses_plugin.h>
#include <scsi/plugins/ses/framework/ses2_impl.h>

/*
 * This is a plugin for HP's SPS-CHASSIS JBOD.  It updates libses'
 * ses-description field to include the correct bay number,
 * and overrides the bay number if the invalid bit is set for the
 * AES descriptor.
 */

/*
 * Override bay number if the invalid bit is set for the AES descriptor.
 * This is modeled after the LENOVO-D1224J12ESM3P plugin.
 */
static int
hp_fix_bay(ses_plugin_t *sp, ses_node_t *np)
{
	ses2_aes_descr_eip_impl_t *dep;
	ses2_aes_descr_sas0_eip_impl_t *s0ep;
	size_t len;
	int nverr;
	nvlist_t *props = ses_node_props(np);

	/*
	 * The spec conveniently defines the bay number as part of the
	 * additional element status descriptor.  However, the AES descriptor
	 * is technically only valid if the device is inserted.
	 * Thankfully, the Dell enclosure defines this value even if
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
 * This updates libses' ses-description field for HP's SPS-CHASSIS JBOD.
 * Bay numbering on this JBOD is numbered from 1-24, however, the
 * description field, which is formatted as a "Drive #" string,
 * shows the drives numbered from "Drive 0" to "Drive 23".  To ensure
 * the drive number in the description field matches the actual bay
 * number, the bay number will be used to populate the drive number
 * in the description field..
 */

/*ARGSUSED*/
static int
hp_parse_node(ses_plugin_t *sp, ses_node_t *np)
{
	uint64_t type, bay;
	int nverr, rc;
	nvlist_t *props;
	char *descr, buf[SES2_MIN_DIAGPAGE_ALLOC];

	if (ses_node_type(np) != SES_NODE_ELEMENT)
		return (0);

	props = ses_node_props(np);
	VERIFY(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE, &type) == 0);
	if (type != SES_ET_ARRAY_DEVICE && type != SES_ET_DEVICE) {
		return (0);
	}

	if ((rc = hp_fix_bay(sp, np)) != 0)
		return (rc);

	if (nvlist_lookup_uint64(props, SES_PROP_BAY_NUMBER, &bay) != 0)
		return (0);

	if (nvlist_lookup_string(props, SES_PROP_DESCRIPTION, &descr) != 0)
		return (0);

	/* modify the description to include the bay number */
	buf[SES2_MIN_DIAGPAGE_ALLOC - 1] = '\0';
	if (snprintf(buf, SES2_MIN_DIAGPAGE_ALLOC - 1, "Drive %d", bay) < 0)
		return (0);

	/* replace the ses-description field with the string created above */
	SES_NV_ADD(string, nverr, props, SES_PROP_DESCRIPTION, buf);

	return (0);
}

int
_ses_init(ses_plugin_t *sp)
{
	ses_plugin_config_t config = {
		.spc_node_parse = hp_parse_node
	};

	return (ses_plugin_register(sp, LIBSES_PLUGIN_VERSION, &config) != 0);
}
