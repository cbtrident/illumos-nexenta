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
 * Copyright 2016 Nexenta Systems, Inc.
 */

#ifndef _NVMEADM_H
#define	_NVMEADM_H

#include <stdio.h>
#include <libdevinfo.h>
#include <sys/nvme.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int verbose;
extern int debug;

/* printing functions */
extern void nvme_print(int, char *, int, const char *, ...);
extern void nvme_print_ctrl_summary(nvme_identify_ctrl_t *, nvme_version_t *);
extern void nvme_print_nsid_summary(nvme_identify_nsid_t *);
extern void nvme_print_identify_ctrl(nvme_identify_ctrl_t *,
    nvme_capabilities_t *, nvme_version_t *);
extern void nvme_print_identify_nsid(nvme_identify_nsid_t *, nvme_version_t *);
extern void nvme_print_error_log(int, nvme_error_log_entry_t *);
extern void nvme_print_health_log(nvme_health_log_t *, nvme_identify_ctrl_t *);
extern void nvme_print_fwslot_log(nvme_fwslot_log_t *);
extern void nvme_print_feat_common(int, uint64_t, nvme_identify_ctrl_t *);
extern void nvme_print_feat_lba_range(nvme_lba_range_type_t,
    nvme_lba_range_t *);
extern void nvme_print_feat_auto_pst(nvme_auto_power_state_trans_t,
    nvme_auto_power_state_t *);

/* device node functions */
extern int nvme_open(di_minor_t);
extern void nvme_close(int);
extern nvme_version_t *nvme_version(int);
extern nvme_capabilities_t *nvme_capabilities(int);
extern nvme_identify_ctrl_t *nvme_identify_ctrl(int);
extern nvme_identify_nsid_t *nvme_identify_nsid(int);
extern void *nvme_get_logpage(int, uint8_t, size_t);
extern boolean_t nvme_get_feature(int, uint8_t, uint32_t, uint64_t *, size_t,
    void **);
extern int nvme_intr_cnt(int);

#ifdef __cplusplus
}
#endif

#endif /* _NVMEADM_H */
