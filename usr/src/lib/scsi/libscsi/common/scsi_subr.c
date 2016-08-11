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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/spc3_types.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

#include <scsi/libscsi.h>
#include <sys/byteorder.h>
#include "libscsi_impl.h"

int
libscsi_assert(const char *expr, const char *file, int line)
{
	char *msg;
	size_t len;

	len = snprintf(NULL, 0,
	    "ABORT: \"%s\", line %d: assertion failed: %s\n", file, line, expr);

	msg = alloca(len + 1);

	(void) snprintf(msg, len + 1,
	    "ABORT: \"%s\", line %d: assertion failed: %s\n", file, line, expr);

	(void) write(STDERR_FILENO, msg, strlen(msg));

	abort();
	_exit(1);

	/*NOTREACHED*/
	return (0);
}

int
libscsi_set_errno(libscsi_hdl_t *hp, libscsi_errno_t err)
{
	hp->lsh_errno = err;
	hp->lsh_errmsg[0] = '\0';

	return (-1);
}

/*
 * Internal routine for setting both _ue_errno and _ue_errmsg.  We save
 * and restore the UNIX errno across this routing so the caller can use either
 * libscsi_set_errno(), libscsi_error(), or libscsi_verror() without this value
 * changing.
 */
int
libscsi_verror(libscsi_hdl_t *hp, libscsi_errno_t err, const char *fmt,
    va_list ap)
{
	size_t n;
	char *errmsg;

	/*
	 * To allow the existing error message to itself be used in an error
	 * message, we put the new error message into a buffer on the stack,
	 * and then copy it into lsh_errmsg.  We also need to set the errno,
	 * but because the call to libscsi_set_errno() is destructive to
	 * lsh_errmsg, we do this after we print into our temporary buffer
	 * (in case _libscsi_errmsg is part of the error message) and before we
	 * copy the temporary buffer on to _libscsi_errmsg (to prevent our new
	 * message from being nuked by the call to libscsi_set_errno()).
	 */
	errmsg = alloca(sizeof (hp->lsh_errmsg));
	(void) vsnprintf(errmsg, sizeof (hp->lsh_errmsg), fmt, ap);
	(void) libscsi_set_errno(hp, err);

	n = strlen(errmsg);

	if (n != 0 && errmsg[n - 1] == '\n')
		errmsg[n - 1] = '\0';

	bcopy(errmsg, hp->lsh_errmsg, n + 1);

	return (-1);
}

/*PRINTFLIKE3*/
int
libscsi_error(libscsi_hdl_t *hp, libscsi_errno_t err, const char *fmt, ...)
{
	va_list ap;

	if (fmt == NULL)
		return (libscsi_set_errno(hp, err));

	va_start(ap, fmt);
	err = libscsi_verror(hp, err, fmt, ap);
	va_end(ap);

	return (err);
}

libscsi_errno_t
libscsi_errno(libscsi_hdl_t *hp)
{
	return (hp->lsh_errno);
}

const char *
libscsi_errmsg(libscsi_hdl_t *hp)
{
	if (hp->lsh_errmsg[0] == '\0')
		(void) strlcpy(hp->lsh_errmsg, libscsi_strerror(hp->lsh_errno),
		    sizeof (hp->lsh_errmsg));

	return (hp->lsh_errmsg);
}

void *
libscsi_alloc(libscsi_hdl_t *hp, size_t size)
{
	void *mem;

	if (size == 0) {
		(void) libscsi_set_errno(hp, ESCSI_ZERO_LENGTH);
		return (NULL);
	}

	if ((mem = malloc(size)) == NULL)
		(void) libscsi_set_errno(hp, ESCSI_NOMEM);

	return (mem);
}

void *
libscsi_zalloc(libscsi_hdl_t *hp, size_t size)
{
	void *mem;

	if ((mem = libscsi_alloc(hp, size)) == NULL)
		return (NULL);

	bzero(mem, size);

	return (mem);
}

char *
libscsi_strdup(libscsi_hdl_t *hp, const char *str)
{
	size_t len = strlen(str);
	char *dup = libscsi_alloc(hp, len + 1);

	if (dup == NULL)
		return (NULL);

	return (strcpy(dup, str));
}

/*ARGSUSED*/
void
libscsi_free(libscsi_hdl_t *hp, void *ptr)
{
	free(ptr);
}

libscsi_hdl_t *
libscsi_init(uint_t version, libscsi_errno_t *errp)
{
	libscsi_hdl_t *hp;

	if ((hp = malloc(sizeof (libscsi_hdl_t))) == NULL) {
		if (errp != NULL)
			*errp = ESCSI_NOMEM;
		return (NULL);
	}

	bzero(hp, sizeof (libscsi_hdl_t));
	hp->lsh_version = version;

	return (hp);
}

void
libscsi_fini(libscsi_hdl_t *hp)
{
	libscsi_engine_impl_t *eip, *neip;

	if (hp == NULL)
		return;

	ASSERT(hp->lsh_targets == 0);

	for (eip = hp->lsh_engines; eip != NULL; eip = neip) {
		neip = eip->lsei_next;
		(void) dlclose(eip->lsei_dl_hdl);
		libscsi_free(hp, eip);
	}

	free(hp);
}

size_t
libscsi_cmd_cdblen(libscsi_hdl_t *hp, uint8_t cmd)
{
	size_t sz;

	switch (CDB_GROUPID(cmd)) {
	case CDB_GROUPID_0:
		sz = CDB_GROUP0;
		break;
	case CDB_GROUPID_1:
		sz = CDB_GROUP1;
		break;
	case CDB_GROUPID_2:
		sz = CDB_GROUP2;
		break;
	case CDB_GROUPID_3:
		sz = CDB_GROUP3;
		break;
	case CDB_GROUPID_4:
		sz = CDB_GROUP4;
		break;
	case CDB_GROUPID_5:
		sz = CDB_GROUP5;
		break;
	case CDB_GROUPID_6:
		sz = CDB_GROUP6;
		break;
	case CDB_GROUPID_7:
		sz = CDB_GROUP7;
		break;
	default:
		sz = 0;
	}

	if (sz == 0)
		(void) libscsi_error(hp, ESCSI_BADCMD,
		    "unknown or unsupported command %u", cmd);

	return (sz);
}

static char *
libscsi_process_inquiry_string(libscsi_hdl_t *hp, const char *raw, size_t len)
{
	char *buf;

	buf = alloca(len + 1);
	bcopy(raw, buf, len);

	for (; len > 0; len--) {
		if (buf[len - 1] != ' ')
			break;
	}

	buf[len] = '\0';

	return (libscsi_strdup(hp, buf));
}

/*
 * As part of basic initialization, we always retrieve the INQUIRY information
 * to have the vendor/product/revision information available for all consumers.
 */
int
libscsi_get_inquiry(libscsi_hdl_t *hp, libscsi_target_t *tp)
{
	libscsi_action_t *ap;
	spc3_inquiry_cdb_t *cp;
	spc3_inquiry_data_t data;
	size_t len;

	if ((ap = libscsi_action_alloc(hp, SPC3_CMD_INQUIRY,
	    LIBSCSI_AF_READ | LIBSCSI_AF_SILENT | LIBSCSI_AF_DIAGNOSE, &data,
	    offsetof(spc3_inquiry_data_t, id_vs_36[0]))) == NULL)
		return (libscsi_set_errno(hp, ESCSI_INQUIRY_FAILED));

	cp = (spc3_inquiry_cdb_t *)libscsi_action_get_cdb(ap);

	SCSI_WRITE16(&cp->ic_allocation_length,
	    offsetof(spc3_inquiry_data_t, id_vs_36[0]));

	if (libscsi_exec(ap, tp) != 0 ||
	    libscsi_action_get_status(ap) != 0) {
		libscsi_action_free(ap);
		return (libscsi_set_errno(hp, ESCSI_INQUIRY_FAILED));
	}

	(void) libscsi_action_get_buffer(ap, NULL, NULL, &len);
	libscsi_action_free(ap);

	if (len < offsetof(spc3_inquiry_data_t, id_vs_36))
		return (libscsi_set_errno(hp, ESCSI_INQUIRY_FAILED));

	if ((tp->lst_vendor = libscsi_process_inquiry_string(hp,
	    data.id_vendor_id, sizeof (data.id_vendor_id))) == NULL ||
	    (tp->lst_product = libscsi_process_inquiry_string(hp,
	    data.id_product_id, sizeof (data.id_product_id))) == NULL ||
	    (tp->lst_revision = libscsi_process_inquiry_string(hp,
	    data.id_product_revision,
	    sizeof (data.id_product_revision))) == NULL) {
		return (libscsi_set_errno(hp, ESCSI_INQUIRY_FAILED));
	}

	return (0);
}

/*
 * A designation descriptor consists of the header followed by data.
 * When given a pointer to the header to get to next descriptor we need to add
 * to hdr pointer the number of data bytes plus size of the header itself.
 */
#define NEXT_DESC(hdr, data_len, hdr_type) ((hdr_type *)((((uint8_t *)hdr) + \
    data_len + sizeof (hdr_type))))

int
libscsi_get_inquiry_dev_id(libscsi_hdl_t *hp, libscsi_target_t *tp)
{
	libscsi_action_t *ap;
	spc3_inquiry_cdb_t *cp;
	spc3_dev_id_vpd_page_impl_t data;
	size_t len;
	int des_bytes_left;
	struct vpd_desc *cur_desc;
	char lid[17];

	if ((ap = libscsi_action_alloc(hp, SPC3_CMD_INQUIRY,
	    LIBSCSI_AF_READ | LIBSCSI_AF_SILENT | LIBSCSI_AF_DIAGNOSE, &data,
	    sizeof (spc3_dev_id_vpd_page_impl_t))) == NULL)
		return (libscsi_set_errno(hp, ESCSI_NOMEM));

	cp = (spc3_inquiry_cdb_t *)libscsi_action_get_cdb(ap);
	cp->ic_evpd = 1; /* return vital product data for bellow page code */
	cp->ic_page_code = DEV_ID_VPD_PAGE_CODE;
	SCSI_WRITE16(&cp->ic_allocation_length,
	    sizeof (spc3_dev_id_vpd_page_impl_t));

	if (libscsi_exec(ap, tp) != 0 ||
	    libscsi_action_get_status(ap) != 0) {
		libscsi_action_free(ap);
		return (libscsi_set_errno(hp, ESCSI_IO));
	}

	(void) libscsi_action_get_buffer(ap, NULL, NULL, &len);
	libscsi_action_free(ap);

	/* make sure we at least got the header */
	if (len < offsetof(spc3_dev_id_vpd_page_impl_t, divpi_descrs[0]))
		return (libscsi_set_errno(hp, ESCSI_BADLENGTH));

	/* make sure we got the page we asked for */
	if (data.divpi_hdr.page_code != DEV_ID_VPD_PAGE_CODE)
		return (libscsi_set_errno(hp, ESCSI_IO));

	/* check for page truncation */
	len = ((data.divpi_hdr.page_len)[0] << 8 |
	    (data.divpi_hdr.page_len)[1]);
	if (len > sizeof (data.divpi_descrs))
		return (libscsi_set_errno(hp, ESCSI_BADLENGTH));

	/* get the first descriptor */
	cur_desc = (struct vpd_desc *)(data.divpi_descrs);
	/* iterate over descriptors looking for the one we need */
	des_bytes_left = len;
	for (; des_bytes_left > sizeof (struct vpd_desc);
	    des_bytes_left -= (sizeof (struct vpd_desc) + cur_desc->len),
	    cur_desc = NEXT_DESC(cur_desc, cur_desc->len, struct vpd_desc)) {

		/*
		 * Len for the NAA IEEE designators is 12 (aka 0x08).
		 * Designator type (id_type) 3 means a NAA formatted
		 * designator.
		 * Code set for the NAA IEEE designators is 1 (binary format).
		 * Association 0 means this designator is for a Logical Unit.
		 * Association 2 means this designator is for a SCSI device
		 * that contains the Logical Unit.
		 * With the ASSOCIATION field set to 0 or 2, device shall
		 * return the same descriptor when it is accessed through any
		 * other I_T nexus. See SPC4 7.8.6.1
		 */
		if (cur_desc->len == 0x08 && cur_desc->id_type == 0x3 &&
		    cur_desc->code_set == 0x1 &&
		    (cur_desc->association == 0x0 ||
		     cur_desc->association == 0x2)) {
			/* get to the data - skip the descriptor header */
			cur_desc = (struct vpd_desc *)(((uint8_t *)cur_desc) +
			    sizeof (struct vpd_desc));

			/*
			 * Bits 7-4 of the NAA formatted designator hold
			 * the designator type. We're only interested
			 * in designator type 0x5 - a 64bit value
			 * (including this type filed) that represents a
			 * NAA IEEE Registered designator that we use as
			 * the LID.
			 * See SPC4 "NAA designator format" section.
			 */
			if (((*((uint8_t *)cur_desc)) & 0x50) != 0x50) {
				/*
				 * This is not an IEEE Registered NAA
				 * designator, point cur_desc back to the
				 * header and skip this designator.
				 */
				cur_desc = (struct vpd_desc * )
				    (((uint8_t *)cur_desc) -
				    sizeof (struct vpd_desc));
				continue;
			}

			/* byte swap to have LID match what libses displays */
			if (snprintf(lid, sizeof (lid), "%llx",
				    BE_IN64(cur_desc)) < 0)
				return (libscsi_set_errno(hp, ESCSI_UNKNOWN));

			if ((tp->lst_lid = libscsi_process_inquiry_string(hp,
			    lid, sizeof (lid))) == NULL)
				return (libscsi_set_errno(hp, ESCSI_NOMEM));

			return (0);
		}
	}

	return (libscsi_set_errno(hp, ESCSI_NOTSUP));
}

/*
 * Execute inquiry for VPD page 0x80 (unit serial #) and extract the USN
 */
int
libscsi_get_inquiry_usn(libscsi_hdl_t *hp, libscsi_target_t *tp)
{
	libscsi_action_t *ap;
	spc3_inquiry_cdb_t *cp;
	spc3_usn_vpd_page_impl_t data;
	size_t len;

	if ((ap = libscsi_action_alloc(hp, SPC3_CMD_INQUIRY,
	    LIBSCSI_AF_READ | LIBSCSI_AF_SILENT | LIBSCSI_AF_DIAGNOSE, &data,
	    sizeof (spc3_usn_vpd_page_impl_t))) == NULL)
		return (libscsi_set_errno(hp, ESCSI_NOMEM));

	cp = (spc3_inquiry_cdb_t *)libscsi_action_get_cdb(ap);
	cp->ic_evpd = 1; /* return vital product data for bellow page code */
	cp->ic_page_code = USN_VPD_PAGE_CODE;
	SCSI_WRITE16(&cp->ic_allocation_length,
	    sizeof (spc3_usn_vpd_page_impl_t));

	if (libscsi_exec(ap, tp) != 0 ||
	    libscsi_action_get_status(ap) != 0) {
		libscsi_action_free(ap);
		return (libscsi_set_errno(hp, ESCSI_IO));
	}

	(void) libscsi_action_get_buffer(ap, NULL, NULL, &len);
	libscsi_action_free(ap);

	/* make sure we at least got the header */
	if (len < offsetof(spc3_usn_vpd_page_impl_t, uvpi_usn[0]))
		return (libscsi_set_errno(hp, ESCSI_BADLENGTH));

	/* make sure we got the page we asked for */
	if (data.uvpi_hdr.page_code != USN_VPD_PAGE_CODE)
		return (libscsi_set_errno(hp, ESCSI_IO));

	/* check for USN truncation */
	len = ((data.uvpi_hdr.page_len)[0] << 8 | (data.uvpi_hdr.page_len)[1]);
	if (len == 0 || len > sizeof (data.uvpi_usn))
		return (libscsi_set_errno(hp, ESCSI_BADLENGTH));

	/* USN is ASCII encoded */
	if ((tp->lst_usn = libscsi_process_inquiry_string(hp,
	    (char *)data.uvpi_usn, len)) == NULL)
	    return (libscsi_set_errno(hp, ESCSI_NOMEM));

	return (0);
}

const char *
libscsi_vendor(libscsi_target_t *tp)
{
	return (tp->lst_vendor);
}

const char *
libscsi_product(libscsi_target_t *tp)
{
	return (tp->lst_product);
}

const char *
libscsi_revision(libscsi_target_t *tp)
{
	return (tp->lst_revision);
}

const char *
libscsi_lid(libscsi_target_t *tp)
{
	return (tp->lst_lid);
}

const char *
libscsi_usn(libscsi_target_t *tp)
{
	return (tp->lst_usn);
}
