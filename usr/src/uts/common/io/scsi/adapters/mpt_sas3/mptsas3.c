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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 * Copyright 2014 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Copyright (c) 2000 to 2010, LSI Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms of all code within
 * this file that is exclusively owned by LSI, with or without
 * modification, is permitted provided that, in addition to the CDDL 1.0
 * License requirements, the following conditions are met:
 *
 *    Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * mptsas3 - This is a driver based on LSI Logic's MPT2.0/2.5 interface.
 *
 */

#if defined(lint) || defined(DEBUG)
#define	MPTSAS_DEBUG
#endif

/*
 * standard header files.
 */
#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/pci.h>
#include <sys/file.h>
#include <sys/policy.h>
#include <sys/model.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <sys/sata/sata_defs.h>
#include <sys/sata/sata_hba.h>
#include <sys/scsi/generic/sas.h>
#include <sys/scsi/impl/scsi_sas.h>
#include <sys/sdt.h>

#pragma pack(1)
#include <sys/scsi/adapters/mpt_sas3/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpt_sas3/mpi/mpi2.h>
#include <sys/scsi/adapters/mpt_sas3/mpi/mpi2_cnfg.h>
#include <sys/scsi/adapters/mpt_sas3/mpi/mpi2_init.h>
#include <sys/scsi/adapters/mpt_sas3/mpi/mpi2_ioc.h>
#include <sys/scsi/adapters/mpt_sas3/mpi/mpi2_sas.h>
#include <sys/scsi/adapters/mpt_sas3/mpi/mpi2_tool.h>
#include <sys/scsi/adapters/mpt_sas3/mpi/mpi2_raid.h>
#pragma pack()

/*
 * private header files.
 *
 */
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/scsi/adapters/mpt_sas3/mptsas3_var.h>
#include <sys/scsi/adapters/mpt_sas3/mptsas3_ioctl.h>
#include <sys/scsi/adapters/mpt_sas3/mptsas3_smhba.h>
#include <sys/scsi/adapters/mpt_sas3/mptsas3_hash.h>
#include <sys/raidioctl.h>

#include <sys/fs/dv_node.h>	/* devfs_clean */

/*
 * FMA header files
 */
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

/*
 * autoconfiguration data and routines.
 */
static int mptsas_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int mptsas_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int mptsas_power(dev_info_t *dip, int component, int level);

/*
 * cb_ops function
 */
static int mptsas_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval);
#ifdef __sparc
static int mptsas_reset(dev_info_t *devi, ddi_reset_cmd_t cmd);
#else  /* __sparc */
static int mptsas_quiesce(dev_info_t *devi);
#endif	/* __sparc */

/*
 * Resource initilaization for hardware
 */
static void mptsas_setup_cmd_reg(mptsas_t *mpt);
static void mptsas_disable_bus_master(mptsas_t *mpt);
static void mptsas_hba_fini(mptsas_t *mpt);
static void mptsas_cfg_fini(mptsas_t *mptsas_blkp);
static int mptsas_hba_setup(mptsas_t *mpt);
static void mptsas_hba_teardown(mptsas_t *mpt);
static int mptsas_config_space_init(mptsas_t *mpt);
static void mptsas_config_space_fini(mptsas_t *mpt);
static void mptsas_iport_register(mptsas_t *mpt);
static int mptsas_smp_setup(mptsas_t *mpt);
static void mptsas_smp_teardown(mptsas_t *mpt);
static int mptsas_cache_create(mptsas_t *mpt);
static void mptsas_cache_destroy(mptsas_t *mpt);
static int mptsas_alloc_request_frames(mptsas_t *mpt);
static int mptsas_alloc_sense_bufs(mptsas_t *mpt);
static int mptsas_alloc_reply_frames(mptsas_t *mpt);
static int mptsas_alloc_free_queue(mptsas_t *mpt);
static int mptsas_alloc_post_queue(mptsas_t *mpt);
static void mptsas_free_post_queue(mptsas_t *mpt);
static void mptsas_alloc_reply_args(mptsas_t *mpt);
static int mptsas_alloc_extra_sgl_frame(mptsas_t *mpt, mptsas_cmd_t *cmd);
static void mptsas_free_extra_sgl_frame(mptsas_t *mpt, mptsas_cmd_t *cmd);
static int mptsas_init_chip(mptsas_t *mpt, int first_time);
static void mptsas_restart_ioc_task(void *args);

/*
 * SCSA function prototypes
 */
static int mptsas_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int mptsas_scsi_reset(struct scsi_address *ap, int level);
static int mptsas_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int mptsas_scsi_getcap(struct scsi_address *ap, char *cap, int tgtonly);
static int mptsas_scsi_setcap(struct scsi_address *ap, char *cap, int value,
    int tgtonly);
static void mptsas_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt);
static struct scsi_pkt *mptsas_scsi_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
	int tgtlen, int flags, int (*callback)(), caddr_t arg);
static void mptsas_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);
static void mptsas_scsi_destroy_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static int mptsas_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static void mptsas_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int mptsas_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg);
static int mptsas_get_name(struct scsi_device *sd, char *name, int len);
static int mptsas_get_bus_addr(struct scsi_device *sd, char *name, int len);
static int mptsas_scsi_quiesce(dev_info_t *dip);
static int mptsas_scsi_unquiesce(dev_info_t *dip);
static int mptsas_bus_config(dev_info_t *pdip, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);

/*
 * SMP functions
 */
static int mptsas_smp_start(struct smp_pkt *smp_pkt);

/*
 * internal function prototypes.
 */
static void mptsas_list_add(mptsas_t *mpt);
static void mptsas_list_del(mptsas_t *mpt);

static int mptsas_quiesce_bus(mptsas_t *mpt);
static int mptsas_unquiesce_bus(mptsas_t *mpt);

static int mptsas_alloc_handshake_msg(mptsas_t *mpt, size_t alloc_size);
static void mptsas_free_handshake_msg(mptsas_t *mpt);

static void mptsas_ncmds_checkdrain(void *arg);

static void mptsas_prepare_pkt(mptsas_cmd_t *cmd);
static void mptsas_retry_pkt(mptsas_t *mpt, mptsas_cmd_t *sp);
static int mptsas_save_cmd_to_slot(mptsas_t *mpt, mptsas_cmd_t *cmd);
static int mptsas_accept_pkt(mptsas_t *mpt, mptsas_cmd_t *sp);

static int mptsas_do_detach(dev_info_t *dev);
static int mptsas_do_scsi_reset(mptsas_t *mpt, uint16_t devhdl,
    boolean_t wait);
static int mptsas_do_scsi_abort(mptsas_t *mpt, int target, int lun,
    struct scsi_pkt *pkt);
static int mptsas_scsi_capchk(char *cap, int tgtonly, int *cidxp);

static void mptsas_handle_qfull(mptsas_t *mpt, mptsas_cmd_t *cmd);
static void mptsas_handle_event(void *args);
static int mptsas_handle_event_sync(void *args);
static void mptsas_handle_dr(void *args);
static void mptsas_handle_topo_change(mptsas_topo_change_list_t *topo_node,
    dev_info_t *pdip);

static void mptsas_restart_cmd(void *);

static void mptsas_flush_hba(mptsas_t *mpt);
static void mptsas_flush_alltarg_waitqs(mptsas_t *mpt, boolean_t only_cfgluns,
    boolean_t pkt_flags, uint32_t flags, uint32_t flgmsk, uint_t stat,
    uchar_t reason);
static void mptsas_flush_waitq(mptsas_t *mpt, boolean_t forreset);
static void mptsas_flush_target_hba(mptsas_t *mpt, ushort_t target, int lun,
	uint8_t tasktype);
static void mptsas_set_pkt_reason(mptsas_t *mpt, mptsas_cmd_t *cmd,
    uchar_t reason, uint_t stat);

static uint_t mptsas_intr(caddr_t arg1, caddr_t arg2);
static void mptsas_process_intr(mptsas_t *mpt, mptsas_reply_pqueue_t *rpqp,
    pMpi2ReplyDescriptorsUnion_t reply_desc_union);
static void mptsas_handle_scsi_io_success(mptsas_t *mpt,
    mptsas_reply_pqueue_t *rpqp, pMpi2ReplyDescriptorsUnion_t reply_desc);
static void mptsas_handle_address_reply(mptsas_t *mpt,
    pMpi2ReplyDescriptorsUnion_t reply_desc);
static int mptsas_wait_intr(mptsas_t *mpt, int polltime);
static void mptsas_sge_setup(mptsas_t *mpt, mptsas_cmd_t *cmd,
    uint32_t *control, pMpi2SCSIIORequest_t frame, ddi_acc_handle_t acc_hdl);

static void mptsas_watch(void *arg);
static int mptsas_watchsubr(mptsas_t *mpt);
static void mptsas_cmd_timeout(mptsas_t *mpt, mptsas_target_t *ptgt);

static void mptsas_start_passthru(mptsas_t *mpt, mptsas_cmd_t *cmd);
static int mptsas_do_passthru(mptsas_t *mpt, uint8_t *request, uint8_t *reply,
    uint8_t *data, uint32_t request_size, uint32_t reply_size,
    uint32_t data_size, uint8_t direction, uint8_t *dataout,
    uint32_t dataout_size, short timeout, int mode);
static int mptsas_free_devhdl(mptsas_t *mpt, uint16_t devhdl);

static uint8_t mptsas_get_fw_diag_buffer_number(mptsas_t *mpt,
    uint32_t unique_id);
static void mptsas_start_diag(mptsas_t *mpt, mptsas_cmd_t *cmd);
static int mptsas_post_fw_diag_buffer(mptsas_t *mpt,
    mptsas_fw_diagnostic_buffer_t *pBuffer, uint32_t *return_code);
static int mptsas_release_fw_diag_buffer(mptsas_t *mpt,
    mptsas_fw_diagnostic_buffer_t *pBuffer, uint32_t *return_code,
    uint32_t diag_type);
static int mptsas_diag_register(mptsas_t *mpt,
    mptsas_fw_diag_register_t *diag_register, uint32_t *return_code);
static int mptsas_diag_unregister(mptsas_t *mpt,
    mptsas_fw_diag_unregister_t *diag_unregister, uint32_t *return_code);
static int mptsas_diag_query(mptsas_t *mpt, mptsas_fw_diag_query_t *diag_query,
    uint32_t *return_code);
static int mptsas_diag_read_buffer(mptsas_t *mpt,
    mptsas_diag_read_buffer_t *diag_read_buffer, uint8_t *ioctl_buf,
    uint32_t *return_code, int ioctl_mode);
static int mptsas_diag_release(mptsas_t *mpt,
    mptsas_fw_diag_release_t *diag_release, uint32_t *return_code);
static int mptsas_do_diag_action(mptsas_t *mpt, uint32_t action,
    uint8_t *diag_action, uint32_t length, uint32_t *return_code,
    int ioctl_mode);
static int mptsas_diag_action(mptsas_t *mpt, mptsas_diag_action_t *data,
    int mode);

static int mptsas_pkt_alloc_extern(mptsas_t *mpt, mptsas_cmd_t *cmd,
    int cmdlen, int tgtlen, int statuslen, int kf);
static void mptsas_pkt_destroy_extern(mptsas_t *mpt, mptsas_cmd_t *cmd);

static int mptsas_kmem_cache_constructor(void *buf, void *cdrarg, int kmflags);
static void mptsas_kmem_cache_destructor(void *buf, void *cdrarg);

static int mptsas_cache_frames_constructor(void *buf, void *cdrarg,
    int kmflags);
static void mptsas_cache_frames_destructor(void *buf, void *cdrarg);

static void mptsas_check_scsi_io_error(mptsas_t *mpt, pMpi2SCSIIOReply_t reply,
    mptsas_cmd_t *cmd);
static void mptsas_check_task_mgt(mptsas_t *mpt,
    pMpi2SCSIManagementReply_t reply, mptsas_cmd_t *cmd);
static int mptsas_send_scsi_cmd(mptsas_t *mpt, struct scsi_address *ap,
    mptsas_target_t *ptgt, uchar_t *cdb, int cdblen, struct buf *data_bp,
    int *resid);

static int mptsas_alloc_active_slots(mptsas_t *mpt, int flag);
static void mptsas_free_active_slots(mptsas_t *mpt);
static int mptsas_start_cmd(mptsas_t *mpt, mptsas_cmd_t *cmd);

static void mptsas_restart_hba(mptsas_t *mpt);
static void mptsas_restart_waitq(mptsas_t *mpt);
static void mptsas_restart_twaitq(mptsas_t *mpt, mptsas_target_t *ptgt);
static void mptsas_targwaitq_add(mptsas_t *mpt, mptsas_target_t *ptgt,
    mptsas_cmd_t *cmd);
static void mptsas_targwaitq_delete(mptsas_t *mpt, mptsas_target_t *ptgt,
    mptsas_cmd_t *cmd);

static void mptsas_deliver_doneq_thread(mptsas_t *mpt,
    mptsas_cmd_list_t *dlist);
static void mptsas_doneq_add(mptsas_t *mpt, mptsas_cmd_t *cmd);
static void mptsas_rpdoneq_add(mptsas_t *mpt, mptsas_reply_pqueue_t *rpqp,
    mptsas_cmd_t *cmd);
static void mptsas_doneq_mv(mptsas_cmd_list_t *from,
    mptsas_doneq_thread_list_t *item);

static void mptsas_doneq_empty(mptsas_t *mpt);
static void mptsas_rpdoneq_empty(mptsas_t *mpt, mptsas_reply_pqueue_t *rpqp,
    boolean_t all);
static void mptsas_doneq_thread(mptsas_thread_arg_t *arg);

static mptsas_cmd_t *mptsas_waitq_rm(mptsas_t *mpt);
static void mptsas_waitq_delete(mptsas_t *mpt, mptsas_cmd_t *cmd);
static void mptsas_flush_target_waitq(mptsas_t *mpt, mptsas_target_t *ptgt,
    boolean_t pkt_flags, uint32_t flags, uint32_t flgmsk, uint_t stat,
    uchar_t reason);

static void mptsas_start_watch_reset_delay();
static void mptsas_setup_bus_reset_delay(mptsas_t *mpt);
static void mptsas_setup_target_reset_delay(mptsas_t *mpt,
    mptsas_target_t *ptgt, int eticks);
static void mptsas_watch_reset_delay(void *arg);
static int mptsas_watch_reset_delay_subr(mptsas_t *mpt);
static void mptsas_set_throttle(struct mptsas *mpt, mptsas_target_t *ptgt,
    int what);
static void mptsas_set_throttle_mtx(struct mptsas *mpt, mptsas_target_t *ptgt,
    int what);
static void mptsas_deref_tgtcmd(mptsas_t *mpt, mptsas_cmd_t *cmd);
static void mptsas_deref_cmd(mptsas_t *mpt, mptsas_cmd_t *cmd);
static void mptsas_config_wait(mptsas_t *mpt, mptsas_target_t *ptgt,
    uint8_t tinit);
static void mptsas_rpqlock_chkpoint(mptsas_t *mpt);
static void mptsas_pkt_comp(mptsas_cmd_t *cmd);

/*
 * helper functions
 */
static void mptsas_dump_cmd(mptsas_t *mpt, mptsas_cmd_t *cmd);

static dev_info_t *mptsas_find_child(dev_info_t *pdip, char *name);
static dev_info_t *mptsas_find_child_phy(dev_info_t *pdip, uint8_t phy);
static dev_info_t *mptsas_find_child_addr(dev_info_t *pdip, uint64_t sasaddr,
    int lun);
static mdi_pathinfo_t *mptsas_find_path_addr(dev_info_t *pdip, uint64_t sasaddr,
    uint16_t lun);
static mdi_pathinfo_t *mptsas_find_path_phy(dev_info_t *pdip, uint8_t phy);
static dev_info_t *mptsas_find_smp_child(dev_info_t *pdip, char *str_wwn);

static int mptsas_parse_address(char *name, uint64_t *wwid, uint8_t *phy,
    int *lun);
static int mptsas_parse_smp_name(char *name, uint64_t *wwn);

static mptsas_target_t *mptsas_phy_to_tgt(mptsas_t *mpt,
    mptsas_phymask_t phymask, uint8_t phy);
static mptsas_target_t *mptsas_wwid_to_ptgt(mptsas_t *mpt,
    mptsas_phymask_t phymask, uint64_t wwid);
static mptsas_smp_t *mptsas_wwid_to_psmp(mptsas_t *mpt,
    mptsas_phymask_t phymask, uint64_t wwid);

static int mptsas_inquiry(mptsas_t *mpt, mptsas_target_t *ptgt, int lun,
    uchar_t page, unsigned char *buf, int len, int *rlen, uchar_t evpd);

static int mptsas_get_target_device_info(mptsas_t *mpt, uint32_t page_address,
    uint16_t *handle, mptsas_target_t **pptgt);
static uint64_t mptsas_get_sata_guid(mptsas_t *mpt, mptsas_target_t *ptgt);
static void mptsas_update_phymask(mptsas_t *mpt);

static int mptsas_send_sep(mptsas_t *mpt, mptsas_target_t *ptgt,
    uint32_t *status, uint8_t cmd);
static dev_info_t *mptsas_get_dip_from_dev(dev_t dev,
    mptsas_phymask_t *phymask);
static mptsas_target_t *mptsas_addr_to_ptgt(mptsas_t *mpt, char *addr,
    mptsas_phymask_t phymask, uint8_t *ppnum, uint64_t *pwwn, int *plun);
static int mptsas_flush_led_status(mptsas_t *mpt, mptsas_target_t *ptgt);


/*
 * Enumeration / DR functions
 */
static void mptsas_config_all(dev_info_t *pdip);
static void mptsas_probe_all(dev_info_t *pdip);
static int mptsas_config_one_addr(dev_info_t *pdip, mptsas_target_t *ptgt,
    uint64_t sasaddr, int lun, dev_info_t **lundip);
static int mptsas_config_one_phy(dev_info_t *pdip, mptsas_target_t *ptgt,
    uint8_t phy, int lun, dev_info_t **lundip);

static int mptsas_config_target(dev_info_t *pdip, mptsas_target_t *ptgt);
static int mptsas_probe_target(dev_info_t *pdip, mptsas_target_t *ptgt);
static int mptsas_offline_targetdev(dev_info_t *pdip, char *name);
static void mptsas_offline_target(mptsas_t *mpt, mptsas_target_t *ptgt,
    uint8_t topo_flags, dev_info_t *parent);

static int mptsas_config_raid(dev_info_t *pdip, uint16_t target,
    dev_info_t **dip);

static int mptsas_config_luns(dev_info_t *pdip, mptsas_target_t *ptgt);
static void mptsas_clr_tgtcl(mptsas_t *mpt, mptsas_target_t *ptgt);

static int mptsas_create_lun(dev_info_t *pdip, dev_info_t **dip,
    mptsas_target_t *ptgt, mptsas_lun_t *plun);

static int mptsas_create_phys_lun(dev_info_t *pdip, dev_info_t **dip,
    mptsas_target_t *ptgt, mptsas_lun_t *lun);
static int mptsas_create_virt_lun(dev_info_t *pdip, dev_info_t **dip,
    mdi_pathinfo_t **pip, mptsas_target_t *ptgt, mptsas_lun_t *plun);

static void mptsas_offline_missed_luns(dev_info_t *pdip,
    int lun_cnt, mptsas_target_t *ptgt);
static int mptsas_offline_lun(dev_info_t *pdip, dev_info_t *rdip,
    mdi_pathinfo_t *rpip, uint_t flags);

static void mptsas_update_driver_data(struct mptsas *mpt);
static int mptsas_config_smp(dev_info_t *pdip, uint64_t sas_wwn,
    dev_info_t **smp_dip);
static int mptsas_offline_smp(dev_info_t *pdip, mptsas_smp_t *smp_node,
    uint_t flags);

static int mptsas_event_query(mptsas_t *mpt, mptsas_event_query_t *data,
    int mode, int *rval);
static int mptsas_event_enable(mptsas_t *mpt, mptsas_event_enable_t *data,
    int mode, int *rval);
static int mptsas_event_report(mptsas_t *mpt, mptsas_event_report_t *data,
    int mode, int *rval);
static void mptsas_record_event(void *args);
static int mptsas_reg_access(mptsas_t *mpt, mptsas_reg_access_t *data,
    int mode);

mptsas_target_t *mptsas_tgt_alloc(mptsas_t *, uint16_t, uint64_t,
    uint32_t, mptsas_phymask_t, uint8_t);
static mptsas_smp_t *mptsas_smp_alloc(mptsas_t *, mptsas_smp_t *);
static int mptsas_online_smp(dev_info_t *pdip, mptsas_smp_t *smp_node,
    dev_info_t **smp_dip);

/*
 * Power management functions
 */
static int mptsas_get_pci_cap(mptsas_t *mpt);
static int mptsas_init_pm(mptsas_t *mpt);

/*
 * MPT MSI tunable:
 *
 * By default MSI is enabled on all supported platforms.
 */
boolean_t mptsas_enable_msi = B_TRUE;
boolean_t mptsas_enable_msix = B_TRUE;
boolean_t mptsas_physical_bind_failed_page_83 = B_FALSE;

/*
 * Global switch for use of MPI2.5 FAST PATH.
 */
boolean_t mptsas3_use_fastpath = B_TRUE;

static int mptsas_register_intrs(mptsas_t *);
static void mptsas_unregister_intrs(mptsas_t *);
static int mptsas_add_intrs(mptsas_t *, int);
static void mptsas_rem_intrs(mptsas_t *);

/*
 * FMA Prototypes
 */
static void mptsas_fm_init(mptsas_t *mpt);
static void mptsas_fm_fini(mptsas_t *mpt);
static int mptsas_fm_error_cb(dev_info_t *, ddi_fm_error_t *, const void *);

extern pri_t minclsyspri, maxclsyspri;
/*
 * NCPUS is used to determine some optimal configurations for number
 * of threads created to perform specific jobs. If we are invoked because
 * a disk is part of the root file system ncpus may still be 1 so check
 * boot_ncpus as well.
 */
extern int ncpus, boot_ncpus;
#define	NCPUS	max(ncpus, boot_ncpus)

/*
 * This device is created by the SCSI pseudo nexus driver (SCSI vHCI).  It is
 * under this device that the paths to a physical device are created when
 * MPxIO is used.
 */
extern dev_info_t	*scsi_vhci_dip;

/*
 * Tunable timeout value for Inquiry VPD page 0x83
 * By default the value is 30 seconds.
 */
int mptsas_inq83_retry_timeout = 30;

/*
 * Tunable for default SCSI pkt timeout. Defaults to 5 seconds, which should
 * be plenty for INQUIRY and REPORT_LUNS, which are the only commands currently
 * issued by mptsas directly.
 */
int mptsas_scsi_pkt_time = 5;

#ifdef AUTO_OFFLINE_TARGETS

/*
 * maximum retries of allowing continuous command timeout on bad disk
 * before offlining it. By default mptsas_timeout_command_retries is 3
 */
#define	MPTSAS_DEFAULT_TIMEOUT_COMMAND_RETRY	3
uint32_t mptsas_timeout_cmd_retries = MPTSAS_DEFAULT_TIMEOUT_COMMAND_RETRY;

/*
 * tunables for offline target
 * mptsas_tgt_offline_timeout_grace is buffer time in seconds used to offline
 * target mptsas_tgt_offline_timeout is total time interval within which if
 * mptsas_timeout_cmd_retries are found then target will be taken offline
 */
#define	MPTSAS_TGT_OFFLINE_TIMEOUT_GRACE	6
uint32_t mptsas_tgt_offline_timeout_grace = MPTSAS_TGT_OFFLINE_TIMEOUT_GRACE;
uint32_t mptsas_tgt_offline_timeout;

#endif /* AUTO_OFFLINE_TARGETS */

/*
 * tunable to set a limit on the maximum number of times we try to probe or
 * config target before completely giving up on it. Once a target hits this
 * it needs to be offlined (pulled from a slot) and re-onlined (inserted)
 * to get it back.
 */
uint32_t mptsas_max_pcfail = 3;

/*
 * tunable timeout restriction in seconds for every command being executed
 * by mptsas driver passing through mptsas_accept_pkt
 */
#define	MPTSAS_DEFAULT_GLOBAL_COMMAND_TIMEOUT	16
uint32_t mptsas_global_cmd_timeout = MPTSAS_DEFAULT_GLOBAL_COMMAND_TIMEOUT;

/* flags to configure BROADCAST SES primitive event */
boolean_t mptsas_disable_broadcast_ses = B_FALSE;

/* Extra property */
#define	SCSI_ADDR_PROP_SES_SA	"ses-sas-address"

/*
 * This is used to allocate memory for message frame storage, not for
 * data I/O DMA. All message frames must be stored in the first 4G of
 * physical memory.
 */
ddi_dma_attr_t mptsas_dma_attrs = {
	DMA_ATTR_V0,	/* attribute layout version		*/
	0x0ull,		/* address low - should be 0 (longlong)	*/
	0xffffffffull,	/* address high - 32-bit max range	*/
	0x00ffffffull,	/* count max - max DMA object size	*/
	4,		/* allocation alignment requirements	*/
	0x78,		/* burstsizes - binary encoded values	*/
	1,		/* minxfer - gran. of DMA engine	*/
	0x00ffffffull,	/* maxxfer - gran. of DMA engine	*/
	0xffffffffull,	/* max segment size (DMA boundary)	*/
	MPTSAS_MAX_DMA_SEGS, /* scatter/gather list length	*/
	512,		/* granularity - device transfer size	*/
	0		/* flags, set to 0			*/
};

/*
 * This is used for data I/O DMA memory allocation. (full 64-bit DMA
 * physical addresses are supported.)
 */
ddi_dma_attr_t mptsas_dma_attrs64 = {
	DMA_ATTR_V0,	/* attribute layout version		*/
	0x0ull,		/* address low - should be 0 (longlong)	*/
	0xffffffffffffffffull,	/* address high - 64-bit max	*/
	0x00ffffffull,	/* count max - max DMA object size	*/
	4,		/* allocation alignment requirements	*/
	0x78,		/* burstsizes - binary encoded values	*/
	1,		/* minxfer - gran. of DMA engine	*/
	0x00ffffffull,	/* maxxfer - gran. of DMA engine	*/
	0xffffffffull,	/* max segment size (DMA boundary)	*/
	MPTSAS_MAX_DMA_SEGS, /* scatter/gather list length	*/
	512,		/* granularity - device transfer size	*/
	0		/* flags, set to 0 */
};

ddi_device_acc_attr_t mptsas_dev_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static struct cb_ops mptsas_cb_ops = {
	scsi_hba_open,		/* open */
	scsi_hba_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	mptsas_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops mptsas_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	mptsas_attach,		/* attach */
	mptsas_detach,		/* detach */
#ifdef  __sparc
	mptsas_reset,
#else
	nodev,			/* reset */
#endif  /* __sparc */
	&mptsas_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	mptsas_power,		/* power management */
#ifdef	__sparc
	ddi_quiesce_not_needed
#else
	mptsas_quiesce		/* quiesce */
#endif	/* __sparc */
};


#define	MPTSAS_MOD_STRING "MPTSAS3 HBA Driver 01.02.00"

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module. This one is a driver */
	MPTSAS_MOD_STRING, /* Name of the module. */
	&mptsas_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};
#define	TARGET_PROP	"target"
#define	LUN_PROP	"lun"
#define	LUN64_PROP	"lun64"
#define	SAS_PROP	"sas-mpt"
#define	MDI_GUID	"wwn"
#define	NDI_GUID	"guid"
#define	MPTSAS_DEV_GONE	"mptsas_dev_gone"


/*
 * Local static data
 */
#if defined(MPTSAS_DEBUG)
extern void prom_printf(const char *, ...);

#if !defined(MPTSAS_TEST)
#define	MPTSAS_TEST
#endif
uint32_t mptsas_debug_flags = 0x0;
/*
 * Flags to ignore these messages in local debug ring buffer.
 * Default is to ignore the watchsubr() output which normally happens
 * every second.
 */
uint32_t mptsas_dbglog_imask = 0x40000000;
#endif	/* defined(MPTSAS_DEBUG) */

#if defined(MPTSAS_TEST)
/*
 * mptsas_test_timeout and mptsas_test_retry have 2 parts, the bottom 16 bits
 * represent a valid test for an instance of mpt_sas3 (1<<instance).
 * The top 16 bits are the target (devhdl) you want to timeout, zero
 * means any target, i.e. whatever the next command on that instance is.
 */
uint32_t mptsas_test_timeout = 0;
uint32_t mptsas_test_retry = 0;

/*
 * These flags are checked in the watchsubr() function.
 * The same instance/target construction as above applies here.
 */
uint32_t mptsas_test_offline_target = 0;
uint32_t mptsas_test_online_target = 0;

/*
 * Set to invoke an IOC restart while onlining a target.
 * This is specifically to test ZEBI-14810.
 */
uint32_t mptsas_test_reset_while_online = 0;

uint32_t mptsas_test_reset_target = 0;
static int mptsas_rtest_use_rdelay = 1;

/*
 * Set to fail mptsas_probe_target for the specific mpt/target
 */
uint32_t mptsas_test_fail_probe = 0;

/*
 * Chip resets can be tested by using mdb to write 0x10
 * (MPTSAS_SS_RESET_INWATCH) to the m_softstate field in the mptsas_t
 * structure. If prior to that you set mptsas_fail_next_initchip it
 * simulates the reset failing.
 */
uint32_t mptsas_fail_next_initchip = 0;
#endif

static kmutex_t		mptsas_global_mutex;
static void		*mptsas3_state;		/* soft	state ptr */
static krwlock_t	mptsas_global_rwlock;

static kmutex_t		mptsas_log_mutex;
static char		mptsas_log_buf[256];
_NOTE(MUTEX_PROTECTS_DATA(mptsas_log_mutex, mptsas_log_buf))

static mptsas_t *mptsas_head, *mptsas_tail;
static clock_t mptsas_scsi_watchdog_tick;
static clock_t mptsas_tick;
static timeout_id_t mptsas_reset_watch;
static timeout_id_t mptsas_timeout_id;
static int mptsas_timeouts_enabled = 0;

/*
 * Maximum number of MSI-X interrupts any instance of mptsas3 can use.
 * Note that if you want to increase this you may have to also bump the
 * value of ddi_msix_alloc_limit which defaults to 8.
 * Set to zero to fall back to other interrupt types.
 */
int mptsas3_max_msix_intrs = 8;

/*
 * Default length for extended auto request sense buffers.
 * All sense buffers need to be under the same alloc because there
 * is only one common top 32bits (of 64bits) address register.
 * Most requests only require 32 bytes, but some request >256.
 * We use rmalloc()/rmfree() on this additional memory to manage the
 * "extended" requests.
 */
int mptsas_extreq_sense_bufsize = 256*64;

/*
 * Believe that all software resrictions of having to run with DMA
 * attributes to limit allocation to the first 4G are removed.
 * However, this flag remains to enable quick switchback should suspicious
 * problems emerge.
 * Note that scsi_alloc_consistent_buf() does still adhering to allocating
 * 32 bit addressable memory, but we can cope if that is changed now.
 */
int mptsas_use_64bit_msgaddr = 1;

/*
 * Default maximum throttle setting for normal targets.
 */
int mptsas_max_throttle = DEF_MAX_THROTTLE;

/*
 * Max number of failed Task Management commands before we reset HBA.
 */
int mptsas_max_failed_tm_cmds = 3;
int mptsas_max_failed_cfg_cmds = 2;

/*
 * warlock directives
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", scsi_pkt \
	mptsas_cmd NcrTableIndirect buf scsi_cdb scsi_status))
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", smp_pkt))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_device scsi_address))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", mptsas_tgt_private))
_NOTE(SCHEME_PROTECTS_DATA("No Mutex Needed", scsi_hba_tran::tran_tgt_private))

/*
 * SM - HBA statics
 */
char	*mptsas_driver_rev = MPTSAS_MOD_STRING;

#ifdef MPTSAS_DEBUG
void debug_enter(char *);
#endif

/*
 * Notes:
 *	- scsi_hba_init(9F) initializes SCSI HBA modules
 *	- must call scsi_hba_fini(9F) if modload() fails
 */
int
_init(void)
{
	int status;
	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	NDBG0(("_init"));

	status = ddi_soft_state_init(&mptsas3_state, MPTSAS_SIZE,
	    MPTSAS_INITIAL_SOFT_SPACE);
	if (status != 0) {
		return (status);
	}

	if ((status = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&mptsas3_state);
		return (status);
	}

	mutex_init(&mptsas_global_mutex, NULL, MUTEX_DRIVER, NULL);
	rw_init(&mptsas_global_rwlock, NULL, RW_DRIVER, NULL);
	mutex_init(&mptsas_log_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((status = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&mptsas_log_mutex);
		rw_destroy(&mptsas_global_rwlock);
		mutex_destroy(&mptsas_global_mutex);
		ddi_soft_state_fini(&mptsas3_state);
		scsi_hba_fini(&modlinkage);
	}

	return (status);
}

/*
 * Notes:
 *	- scsi_hba_fini(9F) uninitializes SCSI HBA modules
 */
int
_fini(void)
{
	int	status;
	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	NDBG0(("_fini"));

	if ((status = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&mptsas3_state);
		scsi_hba_fini(&modlinkage);
		mutex_destroy(&mptsas_global_mutex);
		rw_destroy(&mptsas_global_rwlock);
		mutex_destroy(&mptsas_log_mutex);
	}
	return (status);
}

/*
 * The loadable-module _info(9E) entry point
 */
int
_info(struct modinfo *modinfop)
{
	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	return (mod_info(&modlinkage, modinfop));
}

int
mptsas_target_eval_devhdl(const void *op, void *arg)
{
	uint16_t dh = *(uint16_t *)arg;
	const mptsas_target_t *tp = op;

	return ((int)tp->m_devhdl - (int)dh);
}

int
mptsas_target_eval_shdwhdl(const void *op, void *arg)
{
	uint16_t dh = *(uint16_t *)arg;
	const mptsas_target_t *tp = op;

	return ((int)tp->m_shdwhdl - (int)dh);
}

static int
mptsas_target_eval_slot(const void *op, void *arg)
{
	mptsas_led_control_t *lcp = arg;
	const mptsas_target_t *tp = op;

	if (tp->m_enclosure != lcp->Enclosure)
		return ((int)tp->m_enclosure - (int)lcp->Enclosure);

	return ((int)tp->m_slot_num - (int)lcp->Slot);
}

static int
mptsas_target_eval_nowwn(const void *op, void *arg)
{
	uint8_t phy = *(uint8_t *)arg;
	const mptsas_target_t *tp = op;

	if (tp->m_addr.mta_wwn != 0)
		return (-1);

	return ((int)tp->m_phynum - (int)phy);
}

static int
mptsas_smp_eval_devhdl(const void *op, void *arg)
{
	uint16_t dh = *(uint16_t *)arg;
	const mptsas_smp_t *sp = op;

	return ((int)sp->m_devhdl - (int)dh);
}

static uint64_t
mptsas_target_addr_hash(const void *tp)
{
	const mptsas_target_addr_t *tap = tp;

	return ((tap->mta_wwn & 0xffffffffffffULL) |
	    ((uint64_t)tap->mta_phymask << 48));
}

static int
mptsas_target_addr_cmp(const void *a, const void *b)
{
	const mptsas_target_addr_t *aap = a;
	const mptsas_target_addr_t *bap = b;

	if (aap->mta_wwn < bap->mta_wwn)
		return (-1);
	if (aap->mta_wwn > bap->mta_wwn)
		return (1);
	return ((int)bap->mta_phymask - (int)aap->mta_phymask);
}

static void
mptsas_target_free(void *op)
{
	kmem_free(op, sizeof (mptsas_target_t));
}

static void
mptsas_smp_free(void *op)
{
	kmem_free(op, sizeof (mptsas_smp_t));
}

static void
mptsas_destroy_hashes(mptsas_t *mpt)
{
	mptsas_target_t *tp, *ntp;
	mptsas_smp_t *sp, *nsp;

	for (tp = refhash_first(mpt->m_targets); tp != NULL; ) {
		ntp  = refhash_next(mpt->m_targets, tp);
		mutex_destroy(&tp->m_t_mutex);
		cv_destroy(&tp->m_t_cv);
		refhash_remove(mpt->m_targets, tp);
		tp = ntp;
	}
	for (sp = refhash_first(mpt->m_smp_targets); sp != NULL; ) {
		nsp = refhash_next(mpt->m_smp_targets, sp);
		refhash_remove(mpt->m_smp_targets, sp);
		sp = nsp;
	}
	refhash_destroy(mpt->m_targets);
	refhash_destroy(mpt->m_smp_targets);
	mpt->m_targets = NULL;
	mpt->m_smp_targets = NULL;
}

static int
mptsas_iport_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	dev_info_t		*pdip;
	mptsas_t		*mpt;
	scsi_hba_tran_t		*hba_tran;
	char			*iport = NULL;
	char			phymask[MPTSAS_MAX_PHYS];
	mptsas_phymask_t	phy_mask = 0;
	int			dynamic_port = 0;
	uint32_t		page_address;
	char			initiator_wwnstr[MPTSAS_WWN_STRLEN];
	int			rval = DDI_FAILURE;
	int			i = 0;
	uint8_t			numphys = 0;
	uint8_t			phy_id;
	uint8_t			phy_port = 0;
	uint16_t		attached_devhdl = 0;
	uint32_t		dev_info;
	uint64_t		attached_sas_wwn;
	uint16_t		dev_hdl;
	uint16_t		pdev_hdl;
	uint16_t		bay_num, enclosure, io_flags;
	char			attached_wwnstr[MPTSAS_WWN_STRLEN];

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/*
		 * If this a scsi-iport node, nothing to do here.
		 */
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	pdip = ddi_get_parent(dip);

	if ((hba_tran = ndi_flavorv_get(pdip, SCSA_FLAVOR_SCSI_DEVICE)) ==
	    NULL) {
		cmn_err(CE_WARN, "Failed attach iport because fail to "
		    "get tran vector for the HBA node");
		return (DDI_FAILURE);
	}

	mpt = TRAN2MPT(hba_tran);
	ASSERT(mpt != NULL);
	if (mpt == NULL)
		return (DDI_FAILURE);

	if ((hba_tran = ndi_flavorv_get(dip, SCSA_FLAVOR_SCSI_DEVICE)) ==
	    NULL) {
		mptsas_log(mpt, CE_WARN, "Failed attach iport because fail to "
		    "get tran vector for the iport node");
		return (DDI_FAILURE);
	}

	/*
	 * Overwrite parent's tran_hba_private to iport's tran vector
	 */
	hba_tran->tran_hba_private = mpt;

	ddi_report_dev(dip);

	/*
	 * Get SAS address for initiator port according dev_handle
	 */
	iport = ddi_get_name_addr(dip);
	if (iport && strncmp(iport, "v0", 2) == 0) {
		if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
		    MPTSAS_VIRTUAL_PORT, 1) !=
		    DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
			    MPTSAS_VIRTUAL_PORT);
			mptsas_log(mpt, CE_WARN, "mptsas virtual port "
			    "prop update failed");
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	}

	mutex_enter(&mpt->m_mutex);
	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		bzero(phymask, sizeof (phymask));
		(void) sprintf(phymask,
		    "%x", mpt->m_phy_info[i].phy_mask);
		if (strcmp(phymask, iport) == 0) {
			break;
		}
	}

	if (i == MPTSAS_MAX_PHYS) {
		mptsas_log(mpt, CE_WARN, "Failed attach port %s because port"
		    "seems not exist", iport);
		mutex_exit(&mpt->m_mutex);
		return (DDI_FAILURE);
	}

	phy_mask = mpt->m_phy_info[i].phy_mask;

	if (mpt->m_phy_info[i].port_flags & AUTO_PORT_CONFIGURATION)
		dynamic_port = 1;
	else
		dynamic_port = 0;

	/*
	 * Update PHY info for smhba
	 */
	if (mptsas_smhba_phy_init(mpt)) {
		mutex_exit(&mpt->m_mutex);
		mptsas_log(mpt, CE_WARN, "mptsas phy update "
		    "failed");
		return (DDI_FAILURE);
	}

	mutex_exit(&mpt->m_mutex);

	numphys = 0;
	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		if ((phy_mask >> i) & 0x01) {
			numphys++;
		}
	}

	bzero(initiator_wwnstr, sizeof (initiator_wwnstr));
	(void) sprintf(initiator_wwnstr, "w%016"PRIx64,
	    mpt->un.m_base_wwid);

	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    SCSI_ADDR_PROP_INITIATOR_PORT, initiator_wwnstr) !=
	    DDI_PROP_SUCCESS) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE,
		    dip, SCSI_ADDR_PROP_INITIATOR_PORT);
		mptsas_log(mpt, CE_WARN, "mptsas Initiator port "
		    "prop update failed");
		return (DDI_FAILURE);
	}
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    MPTSAS_NUM_PHYS, numphys) != DDI_PROP_SUCCESS) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, MPTSAS_NUM_PHYS);
		return (DDI_FAILURE);
	}

	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip, "phymask", phy_mask) !=
	    DDI_PROP_SUCCESS) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "phymask");
		mptsas_log(mpt, CE_WARN, "mptsas phy mask "
		    "prop update failed");
		return (DDI_FAILURE);
	}

	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "dynamic-port", dynamic_port) != DDI_PROP_SUCCESS) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "dynamic-port");
		mptsas_log(mpt, CE_WARN, "mptsas dynamic port "
		    "prop update failed");
		return (DDI_FAILURE);
	}
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    MPTSAS_VIRTUAL_PORT, 0) != DDI_PROP_SUCCESS) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
		    MPTSAS_VIRTUAL_PORT);
		mptsas_log(mpt, CE_WARN, "mptsas virtual port "
		    "prop update failed");
		return (DDI_FAILURE);
	}
	mptsas_smhba_set_all_phy_props(mpt, dip, numphys, phy_mask,
	    &attached_devhdl);

	mutex_enter(&mpt->m_mutex);
	page_address = (MPI2_SAS_DEVICE_PGAD_FORM_HANDLE &
	    MPI2_SAS_DEVICE_PGAD_FORM_MASK) | (uint32_t)attached_devhdl;
	rval = mptsas_get_sas_device_page0(mpt, page_address, &dev_hdl,
	    &attached_sas_wwn, &dev_info, &phy_port, &phy_id,
	    &pdev_hdl, &bay_num, &enclosure, &io_flags);
	if (rval != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN,
		    "Failed to get device page0 for handle:%d",
		    attached_devhdl);
		mutex_exit(&mpt->m_mutex);
		return (DDI_FAILURE);
	}

	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		bzero(phymask, sizeof (phymask));
		(void) sprintf(phymask, "%x", mpt->m_phy_info[i].phy_mask);
		if (strcmp(phymask, iport) == 0) {
			(void) sprintf(&mpt->m_phy_info[i].smhba_info.path[0],
			    "%x",
			    mpt->m_phy_info[i].phy_mask);
		}
	}
	mutex_exit(&mpt->m_mutex);

	bzero(attached_wwnstr, sizeof (attached_wwnstr));
	(void) sprintf(attached_wwnstr, "w%016"PRIx64,
	    attached_sas_wwn);
	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    SCSI_ADDR_PROP_ATTACHED_PORT, attached_wwnstr) !=
	    DDI_PROP_SUCCESS) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE,
		    dip, SCSI_ADDR_PROP_ATTACHED_PORT);
		return (DDI_FAILURE);
	}

	/* Create kstats for each phy on this iport */

	mptsas_create_phy_stats(mpt, iport, dip);

	/*
	 * register sas hba iport with mdi (MPxIO/vhci)
	 */
	if (mdi_phci_register(MDI_HCI_CLASS_SCSI,
	    dip, 0) == MDI_SUCCESS) {
		mpt->m_mpxio_enable = TRUE;
	}
	return (DDI_SUCCESS);
}

/*
 * Notes:
 *	Set up all device state and allocate data structures,
 *	mutexes, condition variables, etc. for device operation.
 *	Add interrupts needed.
 *	Return DDI_SUCCESS if device is ready, else return DDI_FAILURE.
 */
static int
mptsas_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	mptsas_t		*mpt = NULL;
	int			instance, i, j;
	int			q_thread_num;
	char			map_setup = 0;
	char			config_setup = 0;
	char			hba_attach_setup = 0;
	char			smp_attach_setup = 0;
	char			mutex_init_done = 0;
	char			event_taskq_create = 0;
	char			reset_taskq_create = 0;
	char			dr_taskq_create = 0;
	char			doneq_thread_create = 0;
	char			added_watchdog = 0;
	scsi_hba_tran_t		*hba_tran;
	uint_t			mem_bar = MEM_SPACE;
	int			rval = DDI_FAILURE;

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	mptsas_global_cmd_timeout = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    0, "mptsas-global-command-timeout",
	    MPTSAS_DEFAULT_GLOBAL_COMMAND_TIMEOUT);

#ifdef AUTO_OFFLINE_TARGETS
	mptsas_timeout_cmd_retries = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    0, "mptsas-timeout-command-retries",
	    MPTSAS_DEFAULT_TIMEOUT_COMMAND_RETRY);

	mptsas_tgt_offline_timeout = ((mptsas_global_cmd_timeout *
	    mptsas_timeout_cmd_retries) + mptsas_tgt_offline_timeout_grace);
#endif

	if (scsi_hba_iport_unit_address(dip)) {
		return (mptsas_iport_attach(dip, cmd));
	}

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if ((hba_tran = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		mpt = TRAN2MPT(hba_tran);

		if (!mpt) {
			return (DDI_FAILURE);
		}

		/*
		 * Reset hardware and softc to "no outstanding commands"
		 * Note	that a check condition can result on first command
		 * to a	target.
		 */
		mutex_enter(&mpt->m_mutex);

		/*
		 * raise power.
		 */
		if (mpt->m_options & MPTSAS_OPT_PM) {
			mutex_exit(&mpt->m_mutex);
			(void) pm_busy_component(dip, 0);
			rval = pm_power_has_changed(dip, 0, PM_LEVEL_D0);
			if (rval == DDI_SUCCESS) {
				mutex_enter(&mpt->m_mutex);
			} else {
				/*
				 * The pm_raise_power() call above failed,
				 * and that can only occur if we were unable
				 * to reset the hardware.  This is probably
				 * due to unhealty hardware, and because
				 * important filesystems(such as the root
				 * filesystem) could be on the attached disks,
				 * it would not be a good idea to continue,
				 * as we won't be entirely certain we are
				 * writing correct data.  So we panic() here
				 * to not only prevent possible data corruption,
				 * but to give developers or end users a hope
				 * of identifying and correcting any problems.
				 */
				fm_panic("mptsas could not reset hardware "
				    "during resume");
			}
		}

		mpt->m_suspended = 0;

		/*
		 * Reinitialize ioc
		 */
		mpt->m_softstate |= MPTSAS_SS_MSG_UNIT_RESET;
		if (mptsas_init_chip(mpt, FALSE) == DDI_FAILURE) {
			mutex_exit(&mpt->m_mutex);
			if (mpt->m_options & MPTSAS_OPT_PM) {
				(void) pm_idle_component(dip, 0);
			}
			fm_panic("mptsas init chip fail during resume");
		}
		/*
		 * mptsas_update_driver_data needs interrupts so enable them
		 * first.
		 */
		MPTSAS_ENABLE_INTR(mpt);
		mptsas_update_driver_data(mpt);

		/* start requests, if possible */
		mptsas_restart_hba(mpt);

		mutex_exit(&mpt->m_mutex);

		/*
		 * Restart watch thread
		 */
		mutex_enter(&mptsas_global_mutex);
		if (mptsas_timeout_id == 0) {
			mptsas_timeout_id = timeout(mptsas_watch, NULL,
			    mptsas_tick);
			mptsas_timeouts_enabled = 1;
		}
		mutex_exit(&mptsas_global_mutex);

		/* report idle status to pm framework */
		if (mpt->m_options & MPTSAS_OPT_PM) {
			(void) pm_idle_component(dip, 0);
		}

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	}

	instance = ddi_get_instance(dip);

	/*
	 * Allocate softc information.
	 */
	if (ddi_soft_state_zalloc(mptsas3_state, instance) != DDI_SUCCESS) {
		mptsas_log(NULL, CE_WARN,
		    "mptsas3%d: cannot allocate soft state", instance);
		goto fail;
	}

	mpt = ddi_get_soft_state(mptsas3_state, instance);

	if (mpt == NULL) {
		mptsas_log(NULL, CE_WARN,
		    "mptsas3%d: cannot get soft state", instance);
		goto fail;
	}

	/* Indicate that we are 'sizeof (scsi_*(9S))' clean. */
	scsi_size_clean(dip);

	mpt->m_dip = dip;
	mpt->m_instance = instance;

	/* Make a per-instance copy of the structures */
	mpt->m_io_dma_attr = mptsas_dma_attrs64;
	if (mptsas_use_64bit_msgaddr) {
		mpt->m_msg_dma_attr = mptsas_dma_attrs64;
	} else {
		mpt->m_msg_dma_attr = mptsas_dma_attrs;
	}
	mpt->m_reg_acc_attr = mptsas_dev_attr;
	mpt->m_dev_acc_attr = mptsas_dev_attr;

	/*
	 * Round down the arq sense buffer size to nearest 16 bytes.
	 */
	mpt->m_req_sense_size = EXTCMDS_STATUS_SIZE;

	/*
	 * Initialize FMA
	 */
	mpt->m_fm_capabilities = ddi_getprop(DDI_DEV_T_ANY, mpt->m_dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	mptsas_fm_init(mpt);

	if (mptsas_alloc_handshake_msg(mpt,
	    sizeof (Mpi2SCSITaskManagementRequest_t)) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "cannot initialize handshake msg.");
		goto fail;
	}

	/*
	 * Setup configuration space
	 */
	if (mptsas_config_space_init(mpt) == FALSE) {
		mptsas_log(mpt, CE_WARN, "mptsas_config_space_init failed");
		goto fail;
	}
	config_setup++;

	if (ddi_regs_map_setup(dip, mem_bar, (caddr_t *)&mpt->m_reg,
	    0, 0, &mpt->m_reg_acc_attr, &mpt->m_datap) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "map setup failed");
		goto fail;
	}
	map_setup++;

	/*
	 * A taskq is created for dealing with resets.
	 */
	if ((mpt->m_reset_taskq = ddi_taskq_create(dip, "mptsas_reset_taskq",
	    1, TASKQ_DEFAULTPRI, 0)) == NULL) {
		mptsas_log(mpt, CE_NOTE, "ddi_taskq_create for reset failed");
		goto fail;
	}
	reset_taskq_create++;

	/*
	 * A taskq is created for dealing with the event handler
	 */
	if ((mpt->m_event_taskq = ddi_taskq_create(dip, "mptsas_event_taskq",
	    1, TASKQ_DEFAULTPRI, 0)) == NULL) {
		mptsas_log(mpt, CE_NOTE, "ddi_taskq_create for events failed");
		goto fail;
	}
	event_taskq_create++;

	/*
	 * A taskq is created for dealing with dr events
	 */
	if ((mpt->m_dr_taskq = ddi_taskq_create(dip,
	    "mptsas_dr_taskq",
	    1, TASKQ_DEFAULTPRI, 0)) == NULL) {
		mptsas_log(mpt, CE_NOTE, "ddi_taskq_create for discovery "
		    "failed");
		goto fail;
	}
	dr_taskq_create++;

	cv_init(&mpt->m_qthread_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&mpt->m_qthread_mutex, NULL, MUTEX_DRIVER, NULL);

	mpt->m_doneq_thread_threshold = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    0, "mptsas_doneq_thread_threshold_prop", 10);
	mpt->m_doneq_length_threshold = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    0, "mptsas_doneq_length_threshold_prop", 8);
	mpt->m_doneq_thread_n = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    0, "mptsas_doneq_thread_n_prop", min(NCPUS, 8));

	if (mpt->m_doneq_thread_n) {
		mutex_enter(&mpt->m_qthread_mutex);
		mpt->m_doneq_thread_id =
		    kmem_zalloc(sizeof (mptsas_doneq_thread_list_t)
		    * mpt->m_doneq_thread_n, KM_SLEEP);

		for (j = 0; j < mpt->m_doneq_thread_n; j++) {
			cv_init(&mpt->m_doneq_thread_id[j].cv, NULL,
			    CV_DRIVER, NULL);
			mutex_init(&mpt->m_doneq_thread_id[j].mutex, NULL,
			    MUTEX_DRIVER, NULL);
			mutex_enter(&mpt->m_doneq_thread_id[j].mutex);
			mpt->m_doneq_thread_id[j].flag |=
			    MPTSAS_DONEQ_THREAD_ACTIVE;
			mpt->m_doneq_thread_id[j].arg.mpt = mpt;
			mpt->m_doneq_thread_id[j].arg.t = j;
			mpt->m_doneq_thread_id[j].threadp =
			    thread_create(NULL, 0, mptsas_doneq_thread,
			    &mpt->m_doneq_thread_id[j].arg,
			    0, &p0, TS_RUN, maxclsyspri - 10);
			STAILQ_INIT(&mpt->m_doneq_thread_id[j].done.cl_q);
			mutex_exit(&mpt->m_doneq_thread_id[j].mutex);
		}
		mutex_exit(&mpt->m_qthread_mutex);
		doneq_thread_create++;
	}

	/*
	 * Allocate the cpu to replyq map and initialize to
	 * unknown.
	 */
	mpt->m_cpu_to_repq = kmem_zalloc(NCPUS * sizeof (*mpt->m_cpu_to_repq),
	    KM_SLEEP);
	for (i = 0; i < NCPUS; i++) {
		mpt->m_cpu_to_repq[i] = -1;
	}

	/*
	 * Disable hardware interrupt since we're not ready to
	 * handle it yet.
	 */
	MPTSAS_DISABLE_INTR(mpt);

	/*
	 * Initialize mutex used in interrupt handler.
	 * We don't support hi-level so the mutex's are all adaptive
	 * and we don't want to register the interrupts until we get
	 * the chip type information from _init_chip() below.
	 * Otherwise we would use DDI_INTR_PRI(mpt->m_intr_pri)
	 * rather than NULL in the mutex_init() calls.
	 */
	mutex_init(&mpt->m_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&mpt->m_passthru_mutex, NULL, MUTEX_DRIVER, NULL);
	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		mutex_init(&mpt->m_phy_info[i].smhba_info.phy_mutex,
		    NULL, MUTEX_DRIVER, NULL);
	}

	cv_init(&mpt->m_cv, NULL, CV_DRIVER, NULL);
	cv_init(&mpt->m_passthru_cv, NULL, CV_DRIVER, NULL);
	cv_init(&mpt->m_fw_cv, NULL, CV_DRIVER, NULL);
	cv_init(&mpt->m_tm_cv, NULL, CV_DRIVER, NULL);
	cv_init(&mpt->m_config_cv, NULL, CV_DRIVER, NULL);
	cv_init(&mpt->m_fw_diag_cv, NULL, CV_DRIVER, NULL);
	mutex_init_done++;

	mutex_enter(&mpt->m_mutex);
	/*
	 * Initialize power management component
	 */
	if (mpt->m_options & MPTSAS_OPT_PM) {
		if (mptsas_init_pm(mpt)) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "mptsas pm initialization "
			    "failed");
			goto fail;
		}
	}

	/*
	 * Initialize chip using Message Unit Reset, if allowed
	 */
	mpt->m_softstate |= MPTSAS_SS_MSG_UNIT_RESET;
	if (mptsas_init_chip(mpt, TRUE) == DDI_FAILURE) {
		mutex_exit(&mpt->m_mutex);
		mptsas_log(mpt, CE_WARN, "mptsas chip initialization failed");
		goto fail;
	}

	/*
	 * Fill in the phy_info structure and get the base WWID
	 */
	if (mptsas_get_manufacture_page5(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN,
		    "mptsas_get_manufacture_page5 failed!");
		goto fail;
	}

	if (mptsas_get_sas_io_unit_page_hndshk(mpt)) {
		mptsas_log(mpt, CE_WARN,
		    "mptsas_get_sas_io_unit_page_hndshk failed!");
		goto fail;
	}

	if (mptsas_get_manufacture_page0(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN,
		    "mptsas_get_manufacture_page0 failed!");
		goto fail;
	}

	/*
	 * If we only have one interrupt the default for doneq_thread_threshold
	 * should be 0 so that all completion processing goes to the threads.
	 * Only change it if it wasn't set from .conf file.
	 */
	if (mpt->m_doneq_thread_n != 0 &&
	    ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    0, "mptsas_doneq_length_threshold_prop") == 0 &&
	    mpt->m_intr_cnt == 1) {
		mpt->m_doneq_length_threshold = 0;
	}


	mutex_exit(&mpt->m_mutex);

	/*
	 * Register the iport for multiple port HBA
	 */
	mptsas_iport_register(mpt);

	/*
	 * initialize SCSI HBA transport structure
	 */
	if (mptsas_hba_setup(mpt) == FALSE)
		goto fail;
	hba_attach_setup++;

	if (mptsas_smp_setup(mpt) == FALSE)
		goto fail;
	smp_attach_setup++;

	if (mptsas_cache_create(mpt) == FALSE)
		goto fail;

	mpt->m_scsi_reset_delay	= ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, 0, "scsi-reset-delay",	SCSI_DEFAULT_RESET_DELAY);
	if (mpt->m_scsi_reset_delay == 0) {
		mptsas_log(mpt, CE_NOTE,
		    "scsi_reset_delay of 0 is not recommended,"
		    " resetting to SCSI_DEFAULT_RESET_DELAY\n");
		mpt->m_scsi_reset_delay = SCSI_DEFAULT_RESET_DELAY;
	}

	/*
	 * Initialize the wait and done FIFO queue
	 */
	TAILQ_INIT(&mpt->m_active_ioccmdq);
	STAILQ_INIT(&mpt->m_wait.cl_q);
	STAILQ_INIT(&mpt->m_done.cl_q);

	/*
	 * ioc cmd queue initialize
	 */
	mpt->m_ioc_event_cmdtail = &mpt->m_ioc_event_cmdq;
	mpt->m_dev_handle = MPTSAS_INVALID_DEVHDL;

	MPTSAS_ENABLE_INTR(mpt);

	/*
	 * enable event notification
	 */
	mutex_enter(&mpt->m_mutex);
	if (mptsas_ioc_enable_event_notification(mpt)) {
		mutex_exit(&mpt->m_mutex);
		goto fail;
	}
	mutex_exit(&mpt->m_mutex);

	/*
	 * used for mptsas_watch
	 */
	mptsas_list_add(mpt);

	mutex_enter(&mptsas_global_mutex);
	if (mptsas_timeouts_enabled == 0) {
		mptsas_scsi_watchdog_tick = ddi_prop_get_int(DDI_DEV_T_ANY,
		    dip, 0, "scsi-watchdog-tick", DEFAULT_WD_TICK);

		mptsas_tick = mptsas_scsi_watchdog_tick *
		    drv_usectohz((clock_t)1000000);

		mptsas_timeout_id = timeout(mptsas_watch, NULL, mptsas_tick);
		mptsas_timeouts_enabled = 1;
	}
	mutex_exit(&mptsas_global_mutex);
	added_watchdog++;

	/*
	 * Initialize PHY info for smhba.
	 * This requires watchdog to be enabled otherwise if interrupts
	 * don't work the system will hang.
	 */
	if (mptsas_smhba_setup(mpt)) {
		mptsas_log(mpt, CE_WARN, "mptsas phy initialization "
		    "failed");
		goto fail;
	}

	/* Check all dma handles allocated in attach */
	if ((mptsas_check_dma_handle(mpt->m_dma_req_frame_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_req_sense_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_reply_frame_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_free_queue_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_post_queue_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_hshk_dma_hdl)
	    != DDI_SUCCESS)) {
		goto fail;
	}

	/* Check all acc handles allocated in attach */
	if ((mptsas_check_acc_handle(mpt->m_datap) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_req_frame_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_req_sense_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_reply_frame_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_free_queue_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_post_queue_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_hshk_acc_hdl)
	    != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_config_handle)
	    != DDI_SUCCESS)) {
		goto fail;
	}

	/*
	 * After this point, we are not going to fail the attach.
	 */

	/* Print message of HBA present */
	ddi_report_dev(dip);

	/* report idle status to pm framework */
	if (mpt->m_options & MPTSAS_OPT_PM) {
		(void) pm_idle_component(dip, 0);
	}

	return (DDI_SUCCESS);

fail:
	if (mpt) {
		mptsas_log(mpt, CE_WARN, "attach failed");
		mptsas_fm_ereport(mpt, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_LOST);
		/* deallocate in reverse order */
		if (added_watchdog) {
			mptsas_list_del(mpt);
			mutex_enter(&mptsas_global_mutex);

			if (mptsas_timeout_id && (mptsas_head == NULL)) {
				timeout_id_t tid = mptsas_timeout_id;
				mptsas_timeouts_enabled = 0;
				mptsas_timeout_id = 0;
				mutex_exit(&mptsas_global_mutex);
				(void) untimeout(tid);
				mutex_enter(&mptsas_global_mutex);
			}
			mutex_exit(&mptsas_global_mutex);
		}

		mptsas_cache_destroy(mpt);

		if (smp_attach_setup) {
			mptsas_smp_teardown(mpt);
		}
		if (hba_attach_setup) {
			mptsas_hba_teardown(mpt);
		}

		if (mpt->m_targets)
			refhash_destroy(mpt->m_targets);
		if (mpt->m_smp_targets)
			refhash_destroy(mpt->m_smp_targets);

		if (mpt->m_active) {
			mptsas_free_active_slots(mpt);
		}
		if (mpt->m_intr_cnt) {
			mptsas_unregister_intrs(mpt);
		}

		if (doneq_thread_create) {
			mutex_enter(&mpt->m_qthread_mutex);
			q_thread_num = mpt->m_doneq_thread_n;
			for (j = 0; j < q_thread_num; j++) {
				mutex_enter(&mpt->m_doneq_thread_id[j].mutex);
				mpt->m_doneq_thread_id[j].flag &=
				    (~MPTSAS_DONEQ_THREAD_ACTIVE);
				cv_signal(&mpt->m_doneq_thread_id[j].cv);
				mutex_exit(&mpt->m_doneq_thread_id[j].mutex);
			}
			while (mpt->m_doneq_thread_n) {
				cv_wait(&mpt->m_qthread_cv,
				    &mpt->m_qthread_mutex);
			}
			for (j = 0; j < q_thread_num; j++) {
				cv_destroy(&mpt->m_doneq_thread_id[j].cv);
				mutex_destroy(&mpt->m_doneq_thread_id[j].mutex);
			}
			kmem_free(mpt->m_doneq_thread_id,
			    sizeof (mptsas_doneq_thread_list_t)
			    * q_thread_num);
			mutex_exit(&mpt->m_qthread_mutex);
		}
		if (event_taskq_create) {
			ddi_taskq_destroy(mpt->m_event_taskq);
		}
		if (dr_taskq_create) {
			ddi_taskq_destroy(mpt->m_dr_taskq);
		}
		if (reset_taskq_create) {
			ddi_taskq_destroy(mpt->m_reset_taskq);
		}
		if (mpt->m_cpu_to_repq != NULL) {
			kmem_free(mpt->m_cpu_to_repq,
			    NCPUS * sizeof (*mpt->m_cpu_to_repq));
			mpt->m_cpu_to_repq = NULL;
		}
		if (mutex_init_done) {
			mutex_destroy(&mpt->m_qthread_mutex);
			mutex_destroy(&mpt->m_passthru_mutex);
			mutex_destroy(&mpt->m_mutex);
			for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
				mutex_destroy(
				    &mpt->m_phy_info[i].smhba_info.phy_mutex);
			}
			cv_destroy(&mpt->m_qthread_cv);
			cv_destroy(&mpt->m_cv);
			cv_destroy(&mpt->m_passthru_cv);
			cv_destroy(&mpt->m_fw_cv);
			cv_destroy(&mpt->m_tm_cv);
			cv_destroy(&mpt->m_config_cv);
			cv_destroy(&mpt->m_fw_diag_cv);
		}

		if (map_setup) {
			mptsas_cfg_fini(mpt);
		}
		if (config_setup) {
			mptsas_config_space_fini(mpt);
		}
		mptsas_free_handshake_msg(mpt);
		mptsas_hba_fini(mpt);

		mptsas_fm_fini(mpt);
		ddi_soft_state_free(mptsas3_state, instance);
		ddi_prop_remove_all(dip);
	}
	return (DDI_FAILURE);
}

static int
mptsas_suspend(dev_info_t *devi)
{
	mptsas_t	*mpt, *g;
	scsi_hba_tran_t	*tran;

	if (scsi_hba_iport_unit_address(devi)) {
		return (DDI_SUCCESS);
	}

	if ((tran = ddi_get_driver_private(devi)) == NULL)
		return (DDI_SUCCESS);

	mpt = TRAN2MPT(tran);
	if (!mpt) {
		return (DDI_SUCCESS);
	}

	mutex_enter(&mpt->m_mutex);

	if (mpt->m_suspended++) {
		mutex_exit(&mpt->m_mutex);
		return (DDI_SUCCESS);
	}

	/*
	 * Cancel timeout threads for this mpt
	 */
	if (mpt->m_quiesce_timeid) {
		timeout_id_t tid = mpt->m_quiesce_timeid;
		mpt->m_quiesce_timeid = 0;
		mutex_exit(&mpt->m_mutex);
		(void) untimeout(tid);
		mutex_enter(&mpt->m_mutex);
	}

	if (mpt->m_restart_cmd_timeid) {
		timeout_id_t tid = mpt->m_restart_cmd_timeid;
		mpt->m_restart_cmd_timeid = 0;
		mutex_exit(&mpt->m_mutex);
		(void) untimeout(tid);
		mutex_enter(&mpt->m_mutex);
	}

	mutex_exit(&mpt->m_mutex);

	(void) pm_idle_component(mpt->m_dip, 0);

	/*
	 * Cancel watch threads if all mpts suspended
	 */
	rw_enter(&mptsas_global_rwlock, RW_WRITER);
	for (g = mptsas_head; g != NULL; g = g->m_next) {
		if (!g->m_suspended)
			break;
	}
	rw_exit(&mptsas_global_rwlock);

	mutex_enter(&mptsas_global_mutex);
	if (g == NULL) {
		timeout_id_t tid;

		mptsas_timeouts_enabled = 0;
		if (mptsas_timeout_id) {
			tid = mptsas_timeout_id;
			mptsas_timeout_id = 0;
			mutex_exit(&mptsas_global_mutex);
			(void) untimeout(tid);
			mutex_enter(&mptsas_global_mutex);
		}
		if (mptsas_reset_watch) {
			tid = mptsas_reset_watch;
			mptsas_reset_watch = 0;
			mutex_exit(&mptsas_global_mutex);
			(void) untimeout(tid);
			mutex_enter(&mptsas_global_mutex);
		}
	}
	mutex_exit(&mptsas_global_mutex);

	mutex_enter(&mpt->m_mutex);

	/*
	 * If this mpt is not in full power(PM_LEVEL_D0), just return.
	 */
	if ((mpt->m_options & MPTSAS_OPT_PM) &&
	    (mpt->m_power_level != PM_LEVEL_D0)) {
		mutex_exit(&mpt->m_mutex);
		return (DDI_SUCCESS);
	}

	/* Disable HBA interrupts in hardware */
	MPTSAS_DISABLE_INTR(mpt);
	/*
	 * Send RAID action system shutdown to sync IR
	 */
	mptsas_raid_action_system_shutdown(mpt);

	mutex_exit(&mpt->m_mutex);

	/* drain the taskq */
	ddi_taskq_wait(mpt->m_event_taskq);
	ddi_taskq_wait(mpt->m_dr_taskq);

	return (DDI_SUCCESS);
}

#ifdef	__sparc
/*ARGSUSED*/
static int
mptsas_reset(dev_info_t *devi, ddi_reset_cmd_t cmd)
{
	mptsas_t	*mpt;
	scsi_hba_tran_t *tran;

	/*
	 * If this call is for iport, just return.
	 */
	if (scsi_hba_iport_unit_address(devi))
		return (DDI_SUCCESS);

	if ((tran = ddi_get_driver_private(devi)) == NULL)
		return (DDI_SUCCESS);

	if ((mpt = TRAN2MPT(tran)) == NULL)
		return (DDI_SUCCESS);

	/*
	 * Send RAID action system shutdown to sync IR.  Disable HBA
	 * interrupts in hardware first.
	 */
	MPTSAS_DISABLE_INTR(mpt);
	mptsas_raid_action_system_shutdown(mpt);

	return (DDI_SUCCESS);
}
#else /* __sparc */
/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
mptsas_quiesce(dev_info_t *devi)
{
	mptsas_t	*mpt;
	scsi_hba_tran_t *tran;

#if defined(MPTSAS_DEBUG)
	prom_printf("%d: mptsas_quiesce\n", ddi_get_instance(devi));
#endif

	/*
	 * If this call is for iport, just return.
	 */
	if (scsi_hba_iport_unit_address(devi))
		return (DDI_SUCCESS);

	if ((tran = ddi_get_driver_private(devi)) == NULL)
		return (DDI_SUCCESS);

	if ((mpt = TRAN2MPT(tran)) == NULL)
		return (DDI_SUCCESS);

#if defined(MPTSAS_DEBUG)
	prom_printf("%d: quiesce\n", mpt->m_instance);
#endif

	/* Disable HBA interrupts in hardware */
	MPTSAS_DISABLE_INTR(mpt);

	/* Send RAID action system shutdown to sync IR */
	mptsas_raid_action_system_shutdown(mpt);

	/*
	 * Reset the chip so that it does not continue to access memory
	 * structures.
	 */
	if (mptsas_ioc_reset(mpt, FALSE) == MPTSAS_RESET_FAIL) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}
#endif	/* __sparc */

/*
 * detach(9E).	Remove all device allocations and system resources;
 * disable device interrupts.
 * Return DDI_SUCCESS if done; DDI_FAILURE if there's a problem.
 */
static int
mptsas_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);
	NDBG0(("mptsas_detach: dip=0x%p cmd=0x%p", (void *)devi, (void *)cmd));

	switch (cmd) {
	case DDI_DETACH:
		return (mptsas_do_detach(devi));

	case DDI_SUSPEND:
		return (mptsas_suspend(devi));

	default:
		return (DDI_FAILURE);
	}
	/* NOTREACHED */
}

static int
mptsas_do_detach(dev_info_t *dip)
{
	mptsas_t	*mpt;
	scsi_hba_tran_t	*tran;
	int		circ = 0;
	int		circ1 = 0;
	mdi_pathinfo_t	*pip = NULL;
	int		i;
	int		q_thread_num = 0;

	NDBG0(("mptsas_do_detach: dip=0x%p", (void *)dip));

	if ((tran = ndi_flavorv_get(dip, SCSA_FLAVOR_SCSI_DEVICE)) == NULL)
		return (DDI_FAILURE);

	mpt = TRAN2MPT(tran);
	if (!mpt) {
		return (DDI_FAILURE);
	}
	/*
	 * Still have pathinfo child, should not detach mpt driver
	 */
	if (scsi_hba_iport_unit_address(dip)) {
		if (mpt->m_mpxio_enable) {
			/*
			 * MPxIO enabled for the iport
			 */
			ndi_devi_enter(scsi_vhci_dip, &circ1);
			ndi_devi_enter(dip, &circ);
			while ((pip = mdi_get_next_client_path(dip, NULL)) !=
			    NULL) {
				if (mdi_pi_free(pip, 0) == MDI_SUCCESS) {
					continue;
				}
				ndi_devi_exit(dip, circ);
				ndi_devi_exit(scsi_vhci_dip, circ1);
				NDBG12(("%d: detach failed because of "
				    "outstanding path info", mpt->m_instance));
				return (DDI_FAILURE);
			}
			ndi_devi_exit(dip, circ);
			ndi_devi_exit(scsi_vhci_dip, circ1);
			(void) mdi_phci_unregister(dip, 0);
		}

		ddi_prop_remove_all(dip);

		return (DDI_SUCCESS);
	}

	/* Make sure power level is D0 before accessing registers */
	if (mpt->m_options & MPTSAS_OPT_PM) {
		(void) pm_busy_component(dip, 0);
		if (mpt->m_power_level != PM_LEVEL_D0) {
			if (pm_raise_power(dip, 0, PM_LEVEL_D0) !=
			    DDI_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "mptsas3%d: Raise power request failed.",
				    mpt->m_instance);
				(void) pm_idle_component(dip, 0);
				return (DDI_FAILURE);
			}
		}
	}

	mutex_enter(&mpt->m_mutex);
	/*
	 * Error any further command requests and flush everything.
	 */
	mpt->m_softstate |= MPTSAS_SS_INIT_FAILED;
	MPTSAS_DISABLE_INTR(mpt);
	mutex_exit(&mpt->m_mutex);
	mptsas_rpqlock_chkpoint(mpt);
	mptsas_rem_intrs(mpt);
	mutex_enter(&mpt->m_mutex);
	mptsas_flush_hba(mpt);
	mptsas_flush_alltarg_waitqs(mpt, B_FALSE, B_FALSE, 0, 0, STAT_ABORTED,
	    CMD_DEV_GONE);
	mptsas_flush_waitq(mpt, B_FALSE);
	mptsas_doneq_empty(mpt);

	/*
	 * Send RAID action system shutdown to sync IR.  After action, send a
	 * Message Unit Reset. Since after that DMA resource will be freed,
	 * set ioc to READY state will avoid HBA initiated DMA operation.
	 */
	mptsas_raid_action_system_shutdown(mpt);
	mpt->m_softstate |= MPTSAS_SS_MSG_UNIT_RESET;
	(void) mptsas_ioc_reset(mpt, FALSE);
	mutex_exit(&mpt->m_mutex);
	ddi_taskq_destroy(mpt->m_reset_taskq);
	ddi_taskq_destroy(mpt->m_event_taskq);
	ddi_taskq_destroy(mpt->m_dr_taskq);

	if (mpt->m_doneq_thread_n) {
		mutex_enter(&mpt->m_qthread_mutex);
		q_thread_num = mpt->m_doneq_thread_n;
		for (i = 0; i < mpt->m_doneq_thread_n; i++) {
			mutex_enter(&mpt->m_doneq_thread_id[i].mutex);
			mpt->m_doneq_thread_id[i].flag &=
			    (~MPTSAS_DONEQ_THREAD_ACTIVE);
			cv_signal(&mpt->m_doneq_thread_id[i].cv);
			mutex_exit(&mpt->m_doneq_thread_id[i].mutex);
		}
		while (mpt->m_doneq_thread_n) {
			cv_wait(&mpt->m_qthread_cv,
			    &mpt->m_qthread_mutex);
		}
		for (i = 0;  i < q_thread_num; i++) {
			cv_destroy(&mpt->m_doneq_thread_id[i].cv);
			mutex_destroy(&mpt->m_doneq_thread_id[i].mutex);
		}
		kmem_free(mpt->m_doneq_thread_id,
		    sizeof (mptsas_doneq_thread_list_t)
		    * q_thread_num);
		mutex_exit(&mpt->m_qthread_mutex);
	}

	scsi_hba_reset_notify_tear_down(mpt->m_reset_notify_listf);

	mptsas_list_del(mpt);

	/*
	 * Cancel timeout threads for this mpt
	 */
	mutex_enter(&mpt->m_mutex);
	if (mpt->m_quiesce_timeid) {
		timeout_id_t tid = mpt->m_quiesce_timeid;
		mpt->m_quiesce_timeid = 0;
		mutex_exit(&mpt->m_mutex);
		(void) untimeout(tid);
		mutex_enter(&mpt->m_mutex);
	}

	if (mpt->m_restart_cmd_timeid) {
		timeout_id_t tid = mpt->m_restart_cmd_timeid;
		mpt->m_restart_cmd_timeid = 0;
		mutex_exit(&mpt->m_mutex);
		(void) untimeout(tid);
		mutex_enter(&mpt->m_mutex);
	}

	mutex_exit(&mpt->m_mutex);

	/*
	 * last mpt? ... if active, CANCEL watch threads.
	 */
	mutex_enter(&mptsas_global_mutex);
	if (mptsas_head == NULL) {
		timeout_id_t tid;
		/*
		 * Clear mptsas_timeouts_enable so that the watch thread
		 * gets restarted on DDI_ATTACH
		 */
		mptsas_timeouts_enabled = 0;
		if (mptsas_timeout_id) {
			tid = mptsas_timeout_id;
			mptsas_timeout_id = 0;
			mutex_exit(&mptsas_global_mutex);
			(void) untimeout(tid);
			mutex_enter(&mptsas_global_mutex);
		}
		if (mptsas_reset_watch) {
			tid = mptsas_reset_watch;
			mptsas_reset_watch = 0;
			mutex_exit(&mptsas_global_mutex);
			(void) untimeout(tid);
			mutex_enter(&mptsas_global_mutex);
		}
	}
	mutex_exit(&mptsas_global_mutex);

	/*
	 * Delete Phy stats
	 */
	mptsas_destroy_phy_stats(mpt);

	mptsas_destroy_hashes(mpt);

	/*
	 * Delete nt_active.
	 */
	mutex_enter(&mpt->m_mutex);
	mptsas_free_active_slots(mpt);
	mutex_exit(&mpt->m_mutex);

	/* deallocate everything that was allocated in mptsas_attach */
	mptsas_cache_destroy(mpt);

	mptsas_hba_fini(mpt);
	mptsas_cfg_fini(mpt);

	/* Lower the power informing PM Framework */
	if (mpt->m_options & MPTSAS_OPT_PM) {
		if (pm_lower_power(dip, 0, PM_LEVEL_D3) != DDI_SUCCESS)
			mptsas_log(mpt, CE_WARN,
			    "!mptsas3%d: Lower power request failed "
			    "during detach, ignoring.",
			    mpt->m_instance);
	}

	if (mpt->m_cpu_to_repq != NULL) {
		kmem_free(mpt->m_cpu_to_repq,
		    NCPUS * sizeof (*mpt->m_cpu_to_repq));
		mpt->m_cpu_to_repq = NULL;
	}
	mutex_destroy(&mpt->m_qthread_mutex);
	mutex_destroy(&mpt->m_passthru_mutex);
	mutex_destroy(&mpt->m_mutex);
	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		mutex_destroy(&mpt->m_phy_info[i].smhba_info.phy_mutex);
	}
	cv_destroy(&mpt->m_qthread_cv);
	cv_destroy(&mpt->m_cv);
	cv_destroy(&mpt->m_passthru_cv);
	cv_destroy(&mpt->m_fw_cv);
	cv_destroy(&mpt->m_tm_cv);
	cv_destroy(&mpt->m_config_cv);
	cv_destroy(&mpt->m_fw_diag_cv);


	mptsas_smp_teardown(mpt);
	mptsas_hba_teardown(mpt);

	mptsas_config_space_fini(mpt);

	mptsas_free_handshake_msg(mpt);

	mptsas_fm_fini(mpt);
	ddi_soft_state_free(mptsas3_state, ddi_get_instance(dip));
	ddi_prop_remove_all(dip);

	return (DDI_SUCCESS);
}

static void
mptsas_list_add(mptsas_t *mpt)
{
	rw_enter(&mptsas_global_rwlock, RW_WRITER);

	if (mptsas_head == NULL) {
		mptsas_head = mpt;
	} else {
		mptsas_tail->m_next = mpt;
	}
	mptsas_tail = mpt;
	rw_exit(&mptsas_global_rwlock);
}

static void
mptsas_list_del(mptsas_t *mpt)
{
	mptsas_t *m;
	/*
	 * Remove device instance from the global linked list
	 */
	rw_enter(&mptsas_global_rwlock, RW_WRITER);
	if (mptsas_head == mpt) {
		m = mptsas_head = mpt->m_next;
	} else {
		for (m = mptsas_head; m != NULL; m = m->m_next) {
			if (m->m_next == mpt) {
				m->m_next = mpt->m_next;
				break;
			}
		}
		if (m == NULL) {
			mptsas_log(mpt, CE_PANIC, "Not in softc list!");
		}
	}

	if (mptsas_tail == mpt) {
		mptsas_tail = m;
	}
	rw_exit(&mptsas_global_rwlock);
}

static int
mptsas_alloc_handshake_msg(mptsas_t *mpt, size_t alloc_size)
{
	ddi_dma_attr_t	task_dma_attrs;

	mpt->m_hshk_dma_size = 0;
	task_dma_attrs = mpt->m_msg_dma_attr;
	task_dma_attrs.dma_attr_sgllen = 1;
	task_dma_attrs.dma_attr_granular = (uint32_t)(alloc_size);

	/* allocate Task Management ddi_dma resources */
	if (mptsas_dma_addr_create(mpt, task_dma_attrs,
	    &mpt->m_hshk_dma_hdl, &mpt->m_hshk_acc_hdl, &mpt->m_hshk_memp,
	    alloc_size, NULL) == FALSE) {
		return (DDI_FAILURE);
	}
	mpt->m_hshk_dma_size = alloc_size;

	return (DDI_SUCCESS);
}

static void
mptsas_free_handshake_msg(mptsas_t *mpt)
{
	if (mpt->m_hshk_dma_size == 0)
		return;
	mptsas_dma_addr_destroy(&mpt->m_hshk_dma_hdl, &mpt->m_hshk_acc_hdl);
	mpt->m_hshk_dma_size = 0;
}

static int
mptsas_hba_setup(mptsas_t *mpt)
{
	scsi_hba_tran_t		*hba_tran;
	int			tran_flags;

	/* Allocate a transport structure */
	hba_tran = mpt->m_tran = scsi_hba_tran_alloc(mpt->m_dip,
	    SCSI_HBA_CANSLEEP);
	ASSERT(mpt->m_tran != NULL);

	hba_tran->tran_hba_private	= mpt;
	hba_tran->tran_tgt_private	= NULL;

	hba_tran->tran_tgt_init		= mptsas_scsi_tgt_init;
	hba_tran->tran_tgt_free		= mptsas_scsi_tgt_free;

	hba_tran->tran_start		= mptsas_scsi_start;
	hba_tran->tran_reset		= mptsas_scsi_reset;
	hba_tran->tran_abort		= mptsas_scsi_abort;
	hba_tran->tran_getcap		= mptsas_scsi_getcap;
	hba_tran->tran_setcap		= mptsas_scsi_setcap;
	hba_tran->tran_init_pkt		= mptsas_scsi_init_pkt;
	hba_tran->tran_destroy_pkt	= mptsas_scsi_destroy_pkt;

	hba_tran->tran_dmafree		= mptsas_scsi_dmafree;
	hba_tran->tran_sync_pkt		= mptsas_scsi_sync_pkt;
	hba_tran->tran_reset_notify	= mptsas_scsi_reset_notify;

	hba_tran->tran_get_bus_addr	= mptsas_get_bus_addr;
	hba_tran->tran_get_name		= mptsas_get_name;

	hba_tran->tran_quiesce		= mptsas_scsi_quiesce;
	hba_tran->tran_unquiesce	= mptsas_scsi_unquiesce;
	hba_tran->tran_bus_reset	= NULL;

	hba_tran->tran_add_eventcall	= NULL;
	hba_tran->tran_get_eventcookie	= NULL;
	hba_tran->tran_post_event	= NULL;
	hba_tran->tran_remove_eventcall	= NULL;

	hba_tran->tran_bus_config	= mptsas_bus_config;

	hba_tran->tran_interconnect_type = INTERCONNECT_SAS;

	/*
	 * All children of the HBA are iports. We need tran was cloned.
	 * So we pass the flags to SCSA. SCSI_HBA_TRAN_CLONE will be
	 * inherited to iport's tran vector.
	 */
	tran_flags = (SCSI_HBA_HBA | SCSI_HBA_TRAN_CLONE);

	if (scsi_hba_attach_setup(mpt->m_dip, &mpt->m_msg_dma_attr,
	    hba_tran, tran_flags) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "hba attach setup failed");
		scsi_hba_tran_free(hba_tran);
		mpt->m_tran = NULL;
		return (FALSE);
	}
	return (TRUE);
}

static void
mptsas_hba_teardown(mptsas_t *mpt)
{
	(void) scsi_hba_detach(mpt->m_dip);
	if (mpt->m_tran != NULL) {
		scsi_hba_tran_free(mpt->m_tran);
		mpt->m_tran = NULL;
	}
}

static void
mptsas_iport_register(mptsas_t *mpt)
{
	int i, j;
	mptsas_phymask_t	mask = 0x0;
	/*
	 * initial value of mask is 0
	 */
	mutex_enter(&mpt->m_mutex);
	for (i = 0; i < mpt->m_num_phys; i++) {
		mptsas_phymask_t phy_mask = 0x0;
		char phy_mask_name[MPTSAS_MAX_PHYS];
		uint8_t current_port;

		if (mpt->m_phy_info[i].attached_devhdl == 0)
			continue;

		bzero(phy_mask_name, sizeof (phy_mask_name));

		current_port = mpt->m_phy_info[i].port_num;

		if ((mask & (1 << i)) != 0)
			continue;

		for (j = 0; j < mpt->m_num_phys; j++) {
			if (mpt->m_phy_info[j].attached_devhdl &&
			    (mpt->m_phy_info[j].port_num == current_port)) {
				phy_mask |= (1 << j);
			}
		}
		mask = mask | phy_mask;

		for (j = 0; j < mpt->m_num_phys; j++) {
			if ((phy_mask >> j) & 0x01) {
				mpt->m_phy_info[j].phy_mask = phy_mask;
			}
		}

		(void) sprintf(phy_mask_name, "%x", phy_mask);

		mutex_exit(&mpt->m_mutex);
		/*
		 * register a iport
		 */
		(void) scsi_hba_iport_register(mpt->m_dip, phy_mask_name);
		mutex_enter(&mpt->m_mutex);
	}
	mutex_exit(&mpt->m_mutex);
	/*
	 * register a virtual port for RAID volume always
	 */
	(void) scsi_hba_iport_register(mpt->m_dip, "v0");

}

static int
mptsas_smp_setup(mptsas_t *mpt)
{
	mpt->m_smptran = smp_hba_tran_alloc(mpt->m_dip);
	ASSERT(mpt->m_smptran != NULL);
	mpt->m_smptran->smp_tran_hba_private = mpt;
	mpt->m_smptran->smp_tran_start = mptsas_smp_start;
	if (smp_hba_attach_setup(mpt->m_dip, mpt->m_smptran) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "smp attach setup failed");
		smp_hba_tran_free(mpt->m_smptran);
		mpt->m_smptran = NULL;
		return (FALSE);
	}
	/*
	 * Initialize smp hash table
	 */
	mpt->m_smp_targets = refhash_create(MPTSAS_SMP_BUCKET_COUNT,
	    mptsas_target_addr_hash, mptsas_target_addr_cmp,
	    mptsas_smp_free, sizeof (mptsas_smp_t),
	    offsetof(mptsas_smp_t, m_link), offsetof(mptsas_smp_t, m_addr),
	    KM_SLEEP);
	mpt->m_smp_devhdl = 0xFFFF;

	return (TRUE);
}

static void
mptsas_smp_teardown(mptsas_t *mpt)
{
	(void) smp_hba_detach(mpt->m_dip);
	if (mpt->m_smptran != NULL) {
		smp_hba_tran_free(mpt->m_smptran);
		mpt->m_smptran = NULL;
	}
	mpt->m_smp_devhdl = 0;
}

static int
mptsas_cache_create(mptsas_t *mpt)
{
	int instance = mpt->m_instance;
	char buf[64];

	/*
	 * create kmem cache for packets
	 */
	(void) sprintf(buf, "mptsas3%d_cache", instance);
	mpt->m_kmem_cache = kmem_cache_create(buf,
	    sizeof (struct mptsas_cmd) + scsi_pkt_size(), 16,
	    mptsas_kmem_cache_constructor, mptsas_kmem_cache_destructor,
	    NULL, (void *)mpt, NULL, 0);

	if (mpt->m_kmem_cache == NULL) {
		mptsas_log(mpt, CE_WARN, "creating kmem cache failed");
		return (FALSE);
	}

	/*
	 * create kmem cache for extra SGL frames if SGL cannot
	 * be accomodated into main request frame.
	 */
	(void) sprintf(buf, "mptsas3%d_cache_frames", instance);
	mpt->m_cache_frames = kmem_cache_create(buf,
	    sizeof (mptsas_cache_frames_t), 16,
	    mptsas_cache_frames_constructor, mptsas_cache_frames_destructor,
	    NULL, (void *)mpt, NULL, 0);

	if (mpt->m_cache_frames == NULL) {
		mptsas_log(mpt, CE_WARN, "creating cache for frames failed");
		return (FALSE);
	}

	return (TRUE);
}

static void
mptsas_cache_destroy(mptsas_t *mpt)
{
	/* deallocate in reverse order */
	if (mpt->m_cache_frames) {
		kmem_cache_destroy(mpt->m_cache_frames);
		mpt->m_cache_frames = NULL;
	}
	if (mpt->m_kmem_cache) {
		kmem_cache_destroy(mpt->m_kmem_cache);
		mpt->m_kmem_cache = NULL;
	}
}

static int
mptsas_power(dev_info_t *dip, int component, int level)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(component))
#endif
	mptsas_t	*mpt;
	int		rval = DDI_SUCCESS;
	int		polls = 0;
	uint32_t	ioc_status;

	if (scsi_hba_iport_unit_address(dip) != 0)
		return (DDI_SUCCESS);

	mpt = ddi_get_soft_state(mptsas3_state, ddi_get_instance(dip));
	if (mpt == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&mpt->m_mutex);

	/*
	 * If the device is busy, don't lower its power level
	 */
	if (mpt->m_busy && (mpt->m_power_level > level)) {
		mutex_exit(&mpt->m_mutex);
		return (DDI_FAILURE);
	}
	switch (level) {
	case PM_LEVEL_D0:
		NDBG11(("%d: turning power ON.", mpt->m_instance));
		MPTSAS_POWER_ON(mpt);
		/*
		 * Wait up to 30 seconds for IOC to come out of reset.
		 */
		while (((ioc_status = ddi_get32(mpt->m_datap,
		    &mpt->m_reg->Doorbell)) &
		    MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_RESET) {
			if (polls++ > 3000) {
				break;
			}
			delay(drv_usectohz(10000));
		}
		/*
		 * If IOC is not in operational state, try to hard reset it.
		 */
		if ((ioc_status & MPI2_IOC_STATE_MASK) !=
		    MPI2_IOC_STATE_OPERATIONAL) {
			mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
			if (mptsas_restart_ioc(mpt, "PM_LEVEL_D0") ==
			    DDI_FAILURE) {
				mptsas_log(mpt, CE_WARN,
				    "mptsas_power: hard reset failed");
				mutex_exit(&mpt->m_mutex);
				return (DDI_FAILURE);
			}
		}
		mpt->m_power_level = PM_LEVEL_D0;
		break;
	case PM_LEVEL_D3:
		NDBG11(("%d: turning power OFF.", mpt->m_instance));
		MPTSAS_POWER_OFF(mpt);
		break;
	default:
		mptsas_log(mpt, CE_WARN, "mptsas3%d: unknown power level <%x>.",
		    mpt->m_instance, level);
		rval = DDI_FAILURE;
		break;
	}
	mutex_exit(&mpt->m_mutex);
	return (rval);
}

/*
 * Initialize configuration space and figure out which
 * chip and revison of the chip the mpt driver is using.
 */
static int
mptsas_config_space_init(mptsas_t *mpt)
{
	NDBG0(("%d: config_space_init", mpt->m_instance));

	if (mpt->m_config_handle != NULL)
		return (TRUE);

	if (pci_config_setup(mpt->m_dip,
	    &mpt->m_config_handle) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "cannot map configuration space.");
		return (FALSE);
	}

	/*
	 * This is a workaround for a XMITS ASIC bug which does not
	 * drive the CBE upper bits.
	 */
	if (pci_config_get16(mpt->m_config_handle, PCI_CONF_STAT) &
	    PCI_STAT_PERROR) {
		pci_config_put16(mpt->m_config_handle, PCI_CONF_STAT,
		    PCI_STAT_PERROR);
	}

	mptsas_setup_cmd_reg(mpt);

	/*
	 * Get the chip device id:
	 */
	mpt->m_devid = pci_config_get16(mpt->m_config_handle, PCI_CONF_DEVID);

	/*
	 * Save the revision.
	 */
	mpt->m_revid = pci_config_get8(mpt->m_config_handle, PCI_CONF_REVID);

	/*
	 * Save the SubSystem Vendor and Device IDs
	 */
	mpt->m_svid = pci_config_get16(mpt->m_config_handle, PCI_CONF_SUBVENID);
	mpt->m_ssid = pci_config_get16(mpt->m_config_handle, PCI_CONF_SUBSYSID);

	/*
	 * Set the latency timer to 0x40 as specified by the upa -> pci
	 * bridge chip design team.  This may be done by the sparc pci
	 * bus nexus driver, but the driver should make sure the latency
	 * timer is correct for performance reasons.
	 */
	pci_config_put8(mpt->m_config_handle, PCI_CONF_LATENCY_TIMER,
	    MPTSAS_LATENCY_TIMER);

	(void) mptsas_get_pci_cap(mpt);
	return (TRUE);
}

static void
mptsas_config_space_fini(mptsas_t *mpt)
{
	if (mpt->m_config_handle != NULL) {
		mptsas_disable_bus_master(mpt);
		pci_config_teardown(&mpt->m_config_handle);
		mpt->m_config_handle = NULL;
	}
}

static void
mptsas_setup_cmd_reg(mptsas_t *mpt)
{
	ushort_t	cmdreg;

	/*
	 * Set the command register to the needed values.
	 */
	cmdreg = pci_config_get16(mpt->m_config_handle, PCI_CONF_COMM);
	cmdreg |= (PCI_COMM_ME | PCI_COMM_SERR_ENABLE |
	    PCI_COMM_PARITY_DETECT | PCI_COMM_MAE);
	cmdreg &= ~PCI_COMM_IO;
	pci_config_put16(mpt->m_config_handle, PCI_CONF_COMM, cmdreg);
}

static void
mptsas_disable_bus_master(mptsas_t *mpt)
{
	ushort_t	cmdreg;

	/*
	 * Clear the master enable bit in the PCI command register.
	 * This prevents any bus mastering activity like DMA.
	 */
	cmdreg = pci_config_get16(mpt->m_config_handle, PCI_CONF_COMM);
	cmdreg &= ~PCI_COMM_ME;
	pci_config_put16(mpt->m_config_handle, PCI_CONF_COMM, cmdreg);
}

int
mptsas_dma_alloc(mptsas_t *mpt, mptsas_dma_alloc_state_t *dma_statep)
{
	ddi_dma_attr_t	attrs;

	attrs = mpt->m_io_dma_attr;
	attrs.dma_attr_sgllen = 1;

	ASSERT(dma_statep != NULL);

	if (mptsas_dma_addr_create(mpt, attrs, &dma_statep->handle,
	    &dma_statep->accessp, &dma_statep->memp, dma_statep->size,
	    &dma_statep->cookie) == FALSE) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
mptsas_dma_free(mptsas_dma_alloc_state_t *dma_statep)
{
	ASSERT(dma_statep != NULL);
	mptsas_dma_addr_destroy(&dma_statep->handle, &dma_statep->accessp);
	dma_statep->size = 0;
}

int
mptsas_do_dma(mptsas_t *mpt, uint32_t size, int var, int (*callback)())
{
	ddi_dma_attr_t		attrs;
	ddi_dma_handle_t	dma_handle;
	caddr_t			memp;
	ddi_acc_handle_t	accessp;
	int			rval;

	ASSERT(mutex_owned(&mpt->m_mutex));

	attrs = mpt->m_msg_dma_attr;
	attrs.dma_attr_sgllen = 1;
	attrs.dma_attr_granular = size;

	if (mptsas_dma_addr_create(mpt, attrs, &dma_handle,
	    &accessp, &memp, size, NULL) == FALSE) {
		return (DDI_FAILURE);
	}

	rval = (*callback) (mpt, memp, var, accessp);

	if ((mptsas_check_dma_handle(dma_handle) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(accessp) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		rval = DDI_FAILURE;
	}

	mptsas_dma_addr_destroy(&dma_handle, &accessp);
	return (rval);

}

static int
mptsas_alloc_request_frames(mptsas_t *mpt)
{
	ddi_dma_attr_t		frame_dma_attrs;
	caddr_t			memp;
	ddi_dma_cookie_t	cookie;
	size_t			mem_size;

	/*
	 * re-alloc when it has already alloced
	 */
	if (mpt->m_dma_flags & MPTSAS_REQ_FRAME) {
		mptsas_dma_addr_destroy(&mpt->m_dma_req_frame_hdl,
		    &mpt->m_acc_req_frame_hdl);
		mpt->m_dma_flags &= ~MPTSAS_REQ_FRAME;
	}

	/*
	 * The size of the request frame pool is:
	 *   Number of Request Frames * Request Frame Size
	 */
	mem_size = mpt->m_max_requests * mpt->m_req_frame_size;

	/*
	 * set the DMA attributes.  System Request Message Frames must be
	 * aligned on a 16-byte boundry.
	 */
	frame_dma_attrs = mpt->m_msg_dma_attr;
	frame_dma_attrs.dma_attr_align = 16;
	frame_dma_attrs.dma_attr_sgllen = 1;

	/*
	 * allocate the request frame pool.
	 */
	if (mptsas_dma_addr_create(mpt, frame_dma_attrs,
	    &mpt->m_dma_req_frame_hdl, &mpt->m_acc_req_frame_hdl, &memp,
	    mem_size, &cookie) == FALSE) {
		return (DDI_FAILURE);
	}

	/*
	 * Store the request frame memory address.  This chip uses this
	 * address to dma to and from the driver's frame.  The second
	 * address is the address mpt uses to fill in the frame.
	 */
	mpt->m_req_frame_dma_addr = cookie.dmac_laddress;
	mpt->m_req_frame = memp;

	/*
	 * Clear the request frame pool.
	 */
	bzero(mpt->m_req_frame, mem_size);

	mpt->m_dma_flags |= MPTSAS_REQ_FRAME;
	return (DDI_SUCCESS);
}

static int
mptsas_alloc_sense_bufs(mptsas_t *mpt)
{
	ddi_dma_attr_t		sense_dma_attrs;
	caddr_t			memp;
	ddi_dma_cookie_t	cookie;
	size_t			mem_size;
	int			num_extrqsense_bufs;

	/*
	 * re-alloc when it has already alloced
	 */
	if (mpt->m_dma_flags & MPTSAS_REQ_SENSE) {
		mptsas_dma_addr_destroy(&mpt->m_dma_req_sense_hdl,
		    &mpt->m_acc_req_sense_hdl);
		mpt->m_dma_flags &= ~MPTSAS_REQ_SENSE;
	}

	/*
	 * The size of the request sense pool is:
	 *   (Number of Request Frames - 2 ) * Request Sense Size +
	 *   extra memory for extended sense requests.
	 */
	mem_size = ((mpt->m_max_requests - 2) * mpt->m_req_sense_size) +
	    mptsas_extreq_sense_bufsize;

	/*
	 * set the DMA attributes.  ARQ buffers
	 * aligned on a 16-byte boundry.
	 */
	sense_dma_attrs = mpt->m_msg_dma_attr;
	sense_dma_attrs.dma_attr_align = 16;
	sense_dma_attrs.dma_attr_sgllen = 1;

	/*
	 * allocate the request sense buffer pool.
	 */
	if (mptsas_dma_addr_create(mpt, sense_dma_attrs,
	    &mpt->m_dma_req_sense_hdl, &mpt->m_acc_req_sense_hdl, &memp,
	    mem_size, &cookie) == FALSE) {
		return (DDI_FAILURE);
	}

	/*
	 * Store the request sense base memory address.  This chip uses this
	 * address to dma the request sense data.  The second
	 * address is the address mpt uses to access the data.
	 * The third is the base for the extended rqsense buffers.
	 */
	mpt->m_req_sense_dma_addr = cookie.dmac_laddress;
	mpt->m_req_sense = memp;
	memp += (mpt->m_max_requests - 2) * mpt->m_req_sense_size;
	mpt->m_extreq_sense = memp;

	if (mpt->m_erqsense_map == NULL) {
		/*
		 * The extra memory is divided up into multiples of the base
		 * buffer size in order to allocate via rmalloc().
		 * Note that the rmallocmap cannot start at zero!
		 */
		num_extrqsense_bufs = mptsas_extreq_sense_bufsize /
		    mpt->m_req_sense_size;
		mpt->m_erqsense_map = rmallocmap_wait(num_extrqsense_bufs);
		rmfree(mpt->m_erqsense_map, num_extrqsense_bufs, 1);
	}

	/*
	 * Clear the pool.
	 */
	bzero(mpt->m_req_sense, mem_size);

	mpt->m_dma_flags |= MPTSAS_REQ_SENSE;
	return (DDI_SUCCESS);
}

static int
mptsas_alloc_reply_frames(mptsas_t *mpt)
{
	ddi_dma_attr_t		frame_dma_attrs;
	caddr_t			memp;
	ddi_dma_cookie_t	cookie;
	size_t			mem_size;

	/*
	 * re-alloc when it has already alloced
	 */
	if (mpt->m_dma_flags & MPTSAS_REPLY_FRAME) {
		mptsas_dma_addr_destroy(&mpt->m_dma_reply_frame_hdl,
		    &mpt->m_acc_reply_frame_hdl);
		mpt->m_dma_flags &= ~MPTSAS_REPLY_FRAME;
	}

	/*
	 * The size of the reply frame pool is:
	 *   Number of Reply Frames * Reply Frame Size
	 */
	mem_size = mpt->m_max_replies * mpt->m_reply_frame_size;

	/*
	 * set the DMA attributes.   System Reply Message Frames must be
	 * aligned on a 4-byte boundry.  This is the default.
	 */
	frame_dma_attrs = mpt->m_msg_dma_attr;
	frame_dma_attrs.dma_attr_sgllen = 1;

	/*
	 * allocate the reply frame pool
	 */
	if (mptsas_dma_addr_create(mpt, frame_dma_attrs,
	    &mpt->m_dma_reply_frame_hdl, &mpt->m_acc_reply_frame_hdl, &memp,
	    mem_size, &cookie) == FALSE) {
		return (DDI_FAILURE);
	}

	/*
	 * Store the reply frame memory address.  This chip uses this
	 * address to dma to and from the driver's frame.  The second
	 * address is the address mpt uses to process the frame.
	 */
	mpt->m_reply_frame_dma_addr = cookie.dmac_laddress;
	mpt->m_reply_frame = memp;

	/*
	 * Clear the reply frame pool.
	 */
	bzero(mpt->m_reply_frame, mem_size);

	mpt->m_dma_flags |= MPTSAS_REPLY_FRAME;
	return (DDI_SUCCESS);
}

static int
mptsas_alloc_free_queue(mptsas_t *mpt)
{
	ddi_dma_attr_t		frame_dma_attrs;
	caddr_t			memp;
	ddi_dma_cookie_t	cookie;
	size_t			mem_size;

	/*
	 * re-alloc when it has already alloced
	 */
	if (mpt->m_dma_flags & MPTSAS_FREE_QUEUE) {
		mptsas_dma_addr_destroy(&mpt->m_dma_free_queue_hdl,
		    &mpt->m_acc_free_queue_hdl);
		mpt->m_dma_flags &= ~MPTSAS_FREE_QUEUE;
	}

	/*
	 * The reply free queue size is:
	 *   Reply Free Queue Depth * 4
	 * The "4" is the size of one 32 bit address (low part of 64-bit
	 *   address)
	 */
	mem_size = mpt->m_free_queue_depth * 4;

	/*
	 * set the DMA attributes  The Reply Free Queue must be aligned on a
	 * 16-byte boundry.
	 */
	frame_dma_attrs = mpt->m_msg_dma_attr;
	frame_dma_attrs.dma_attr_align = 16;
	frame_dma_attrs.dma_attr_sgllen = 1;

	/*
	 * allocate the reply free queue
	 */
	if (mptsas_dma_addr_create(mpt, frame_dma_attrs,
	    &mpt->m_dma_free_queue_hdl, &mpt->m_acc_free_queue_hdl, &memp,
	    mem_size, &cookie) == FALSE) {
		return (DDI_FAILURE);
	}

	/*
	 * Store the reply free queue memory address.  This chip uses this
	 * address to read from the reply free queue.  The second address
	 * is the address mpt uses to manage the queue.
	 */
	mpt->m_free_queue_dma_addr = cookie.dmac_laddress;
	mpt->m_free_queue = memp;

	/*
	 * Clear the reply free queue memory.
	 */
	bzero(mpt->m_free_queue, mem_size);

	mpt->m_dma_flags |= MPTSAS_FREE_QUEUE;
	return (DDI_SUCCESS);
}

static void
mptsas_free_post_queue(mptsas_t *mpt)
{
	mptsas_reply_pqueue_t	*rpqp;
	int			i;

	if (mpt->m_dma_flags & MPTSAS_POST_QUEUE) {
		mptsas_dma_addr_destroy(&mpt->m_dma_post_queue_hdl,
		    &mpt->m_acc_post_queue_hdl);
		rpqp = mpt->m_rep_post_queues;
		for (i = 0; i < mpt->m_post_reply_qcount; i++) {
			mutex_destroy(&rpqp->rpq_mutex);
			rpqp++;
		}
		kmem_free(mpt->m_rep_post_queues,
		    sizeof (mptsas_reply_pqueue_t) *
		    mpt->m_post_reply_qcount);
		mpt->m_dma_flags &= ~MPTSAS_POST_QUEUE;
	}
}

static int
mptsas_alloc_post_queue(mptsas_t *mpt)
{
	ddi_dma_attr_t		frame_dma_attrs;
	caddr_t			memp;
	ddi_dma_cookie_t	cookie;
	size_t			mem_size;
	mptsas_reply_pqueue_t	*rpqp;
	int			i;

	/*
	 * re-alloc when it has already alloced
	 */
	mptsas_free_post_queue(mpt);

	/*
	 * The reply descriptor post queue size is:
	 *   Reply Descriptor Post Queue Depth * 8
	 * The "8" is the size of each descriptor (8 bytes or 64 bits).
	 */
	mpt->m_post_reply_qcount = mpt->m_intr_cnt;
	mem_size = mpt->m_post_queue_depth * 8 * mpt->m_post_reply_qcount;

	/*
	 * set the DMA attributes.  The Reply Descriptor Post Queue must be
	 * aligned on a 16-byte boundry.
	 */
	frame_dma_attrs = mpt->m_msg_dma_attr;
	frame_dma_attrs.dma_attr_align = 16;
	frame_dma_attrs.dma_attr_sgllen = 1;

	/*
	 * Allocate the reply post queue(s).
	 * MPI2.5 introduces a method to allocate multiple queues
	 * using a redirect table. For now stick to one contiguous
	 * chunck. This can get as big as 1Mbyte for 16 queues.
	 * The spec gives no indication that the queue size can be
	 * reduced if you have many of them.
	 */
	if (mptsas_dma_addr_create(mpt, frame_dma_attrs,
	    &mpt->m_dma_post_queue_hdl, &mpt->m_acc_post_queue_hdl, &memp,
	    mem_size, &cookie) == FALSE) {
		return (DDI_FAILURE);
	}

	/*
	 * Store the reply descriptor post queue memory address.  This chip
	 * uses this address to write to the reply descriptor post queue.  The
	 * second address is the address mpt uses to manage the queue.
	 */
	mpt->m_post_queue_dma_addr = cookie.dmac_laddress;
	mpt->m_post_queue = memp;

	mpt->m_rep_post_queues = kmem_zalloc(sizeof (mptsas_reply_pqueue_t) *
	    mpt->m_post_reply_qcount, KM_SLEEP);
	rpqp = mpt->m_rep_post_queues;
	for (i = 0; i < mpt->m_post_reply_qcount; i++) {
		rpqp->rpq_queue = memp;
		mutex_init(&rpqp->rpq_mutex, NULL, MUTEX_DRIVER, NULL);
		STAILQ_INIT(&rpqp->rpq_done.cl_q);
		STAILQ_INIT(&rpqp->rpq_idone.cl_q);
		rpqp->rpq_num = (uint8_t)i;
		memp += (mpt->m_post_queue_depth * 8);
		rpqp++;
	}

	/*
	 * Clear the reply post queue memory.
	 */
	bzero(mpt->m_post_queue, mem_size);

	mpt->m_dma_flags |= MPTSAS_POST_QUEUE;
	return (DDI_SUCCESS);
}

static void
mptsas_alloc_reply_args(mptsas_t *mpt)
{
	ASSERT(mpt->m_replyh_args == NULL);
	mpt->m_replyh_args = kmem_zalloc(sizeof (m_replyh_arg_t) *
	    mpt->m_max_replies, KM_SLEEP);
}

static int
mptsas_alloc_extra_sgl_frame(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	mptsas_cache_frames_t	*frames = NULL;
	if (cmd->cmd_extra_frames == NULL) {
		frames = kmem_cache_alloc(mpt->m_cache_frames, KM_NOSLEEP);
		if (frames == NULL) {
			return (DDI_FAILURE);
		}
		cmd->cmd_extra_frames = frames;
	}
	return (DDI_SUCCESS);
}

static void
mptsas_free_extra_sgl_frame(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	if (cmd->cmd_extra_frames) {
		kmem_cache_free(mpt->m_cache_frames,
		    (void *)cmd->cmd_extra_frames);
		cmd->cmd_extra_frames = NULL;
	}
}

static void
mptsas_cfg_fini(mptsas_t *mpt)
{
	NDBG0(("%d: cfg_fini", mpt->m_instance));
	ddi_regs_map_free(&mpt->m_datap);
}

static void
mptsas_hba_fini(mptsas_t *mpt)
{
	NDBG0(("%d: hba_fini", mpt->m_instance));

	/*
	 * Free up any allocated memory
	 */
	if (mpt->m_dma_flags & MPTSAS_REQ_FRAME) {
		mptsas_dma_addr_destroy(&mpt->m_dma_req_frame_hdl,
		    &mpt->m_acc_req_frame_hdl);
	}

	if (mpt->m_dma_flags & MPTSAS_REQ_SENSE) {
		rmfreemap(mpt->m_erqsense_map);
		mptsas_dma_addr_destroy(&mpt->m_dma_req_sense_hdl,
		    &mpt->m_acc_req_sense_hdl);
	}

	if (mpt->m_dma_flags & MPTSAS_REPLY_FRAME) {
		mptsas_dma_addr_destroy(&mpt->m_dma_reply_frame_hdl,
		    &mpt->m_acc_reply_frame_hdl);
	}

	if (mpt->m_dma_flags & MPTSAS_FREE_QUEUE) {
		mptsas_dma_addr_destroy(&mpt->m_dma_free_queue_hdl,
		    &mpt->m_acc_free_queue_hdl);
	}

	mptsas_free_post_queue(mpt);

	if (mpt->m_replyh_args != NULL) {
		kmem_free(mpt->m_replyh_args, sizeof (m_replyh_arg_t)
		    * mpt->m_max_replies);
	}
}

static int
mptsas_name_child(dev_info_t *lun_dip, char *name, int len)
{
	int		lun = 0;
	char		*sas_wwn = NULL;
	int		phynum = -1;
	int		reallen = 0;

	/* Get the target num */
	lun = ddi_prop_get_int(DDI_DEV_T_ANY, lun_dip, DDI_PROP_DONTPASS,
	    LUN_PROP, 0);

	if ((phynum = ddi_prop_get_int(DDI_DEV_T_ANY, lun_dip,
	    DDI_PROP_DONTPASS, "sata-phy", -1)) != -1) {
		/*
		 * Stick in the address of form "pPHY,LUN"
		 */
		reallen = snprintf(name, len, "p%x,%x", phynum, lun);
	} else if (ddi_prop_lookup_string(DDI_DEV_T_ANY, lun_dip,
	    DDI_PROP_DONTPASS, SCSI_ADDR_PROP_TARGET_PORT, &sas_wwn)
	    == DDI_PROP_SUCCESS) {
		/*
		 * Stick in the address of the form "wWWN,LUN"
		 */
		reallen = snprintf(name, len, "%s,%x", sas_wwn, lun);
		ddi_prop_free(sas_wwn);
	} else {
		return (DDI_FAILURE);
	}

	ASSERT(reallen < len);
	if (reallen >= len) {
		mptsas_log(0, CE_WARN, "!mptsas_get_name: name parameter "
		    "length too small, it needs to be %d bytes", reallen + 1);
	}
	return (DDI_SUCCESS);
}

/*
 * tran_tgt_init(9E) - target device instance initialization
 */
static int
mptsas_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(hba_tran))
#endif

	/*
	 * At this point, the scsi_device structure already exists
	 * and has been initialized.
	 *
	 * Use this function to allocate target-private data structures,
	 * if needed by this HBA.  Add revised flow-control and queue
	 * properties for child here, if desired and if you can tell they
	 * support tagged queueing by now.
	 */
	mptsas_t		*mpt;
	int			lun = sd->sd_address.a_lun;
	mdi_pathinfo_t		*pip = NULL;
	mptsas_tgt_private_t	*tgt_private = NULL;
	mptsas_target_t		*ptgt = NULL;
	char			*psas_wwn = NULL;
	mptsas_phymask_t	phymask = 0;
	uint64_t		sas_wwn = 0;
	mptsas_target_addr_t	addr;
	mpt = SDEV2MPT(sd);

	ASSERT(scsi_hba_iport_unit_address(hba_dip) != 0);

	NDBG0(("%d: scsi_tgt_init: hbadip=0x%p tgtdip=0x%p lun=%d",
	    mpt->m_instance, (void *)hba_dip, (void *)tgt_dip, lun));

	if (ndi_dev_is_persistent_node(tgt_dip) == 0) {
		(void) ndi_merge_node(tgt_dip, mptsas_name_child);
		ddi_set_name_addr(tgt_dip, NULL);
		return (DDI_FAILURE);
	}
	/*
	 * phymask is 0 means the virtual port for RAID
	 */
	phymask = (mptsas_phymask_t)ddi_prop_get_int(DDI_DEV_T_ANY, hba_dip, 0,
	    "phymask", 0);
	if (mdi_component_is_client(tgt_dip, NULL) == MDI_SUCCESS) {
		if ((pip = (void *)(sd->sd_private)) == NULL) {
			/*
			 * Very bad news if this occurs. Somehow scsi_vhci has
			 * lost the pathinfo node for this target.
			 */
			return (DDI_NOT_WELL_FORMED);
		}

		if (mdi_prop_lookup_int(pip, LUN_PROP, &lun) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "Get lun property failed\n");
			return (DDI_FAILURE);
		}

		if (mdi_prop_lookup_string(pip, SCSI_ADDR_PROP_TARGET_PORT,
		    &psas_wwn) == MDI_SUCCESS) {
			if (scsi_wwnstr_to_wwn(psas_wwn, &sas_wwn)) {
				sas_wwn = 0;
			}
			(void) mdi_prop_free(psas_wwn);
		}
	} else {
		lun = ddi_prop_get_int(DDI_DEV_T_ANY, tgt_dip,
		    DDI_PROP_DONTPASS, LUN_PROP, 0);
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, tgt_dip,
		    DDI_PROP_DONTPASS, SCSI_ADDR_PROP_TARGET_PORT, &psas_wwn) ==
		    DDI_PROP_SUCCESS) {
			if (scsi_wwnstr_to_wwn(psas_wwn, &sas_wwn)) {
				sas_wwn = 0;
			}
			ddi_prop_free(psas_wwn);
		} else {
			sas_wwn = 0;
		}
	}

	ASSERT((sas_wwn != 0) || (phymask != 0));
	addr.mta_wwn = sas_wwn;
	addr.mta_phymask = phymask;
	mutex_enter(&mpt->m_mutex);
	ptgt = refhash_lookup(mpt->m_targets, &addr);
	mutex_exit(&mpt->m_mutex);
	if (ptgt == NULL) {
		mptsas_log(mpt, CE_WARN, "!tgt_init: target doesn't exist or "
		    "gone already! phymask:%x, saswwn %"PRIx64, phymask,
		    sas_wwn);
		return (DDI_FAILURE);
	}
	if (hba_tran->tran_tgt_private == NULL) {
		tgt_private = kmem_zalloc(sizeof (mptsas_tgt_private_t),
		    KM_SLEEP);
		tgt_private->t_lun = lun;
		tgt_private->t_private = ptgt;
		hba_tran->tran_tgt_private = tgt_private;
	}


	if (mdi_component_is_client(tgt_dip, NULL) == MDI_SUCCESS) {
		return (DDI_SUCCESS);
	}

	if (ptgt->m_deviceinfo & (MPI2_SAS_DEVICE_INFO_SATA_DEVICE |
	    MPI2_SAS_DEVICE_INFO_ATAPI_DEVICE)) {
		uchar_t *inq89;
		struct sata_id *sid = NULL;
		char model[SATA_ID_MODEL_LEN + 1];
		char fw[SATA_ID_FW_LEN + 1];
		char *vid, *pid;

		/*
		 * According SCSI/ATA Translation -2 (SAT-2) revision 01a
		 * chapter 12.4.2 VPD page 89h includes 512 bytes ATA IDENTIFY
		 * DEVICE data or ATA IDENTIFY PACKET DEVICE data.
		 */
		inq89 = ptgt->m_t_luns[0].l_inqp89;
		sid = (void *)(&inq89[60]);

		swab(sid->ai_model, model, SATA_ID_MODEL_LEN);
		swab(sid->ai_fw, fw, SATA_ID_FW_LEN);

		model[SATA_ID_MODEL_LEN] = 0;
		fw[SATA_ID_FW_LEN] = 0;

		if (model[0] != '\0') {
			sata_split_model(model, &vid, &pid);

			/*
			 * override SCSA "inquiry-*" properties
			 */
			if (vid)
				(void) scsi_device_prop_update_inqstring(sd,
				    INQUIRY_VENDOR_ID, vid, strlen(vid));
			if (pid)
				(void) scsi_device_prop_update_inqstring(sd,
				    INQUIRY_PRODUCT_ID, pid, strlen(pid));
		}
		if (fw[0] != '\0') {
			(void) scsi_device_prop_update_inqstring(sd,
			    INQUIRY_REVISION_ID, fw, strlen(fw));
		}
	}

	return (DDI_SUCCESS);
}

/*
 * tran_tgt_free(9E) - target device instance deallocation
 */
static void
mptsas_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(hba_dip, tgt_dip, hba_tran, sd))
#endif

	mptsas_tgt_private_t	*tgt_private = hba_tran->tran_tgt_private;

	if (tgt_private != NULL) {
		kmem_free(tgt_private, sizeof (mptsas_tgt_private_t));
		hba_tran->tran_tgt_private = NULL;
	}
}

/*
 * scsi_pkt handling
 *
 * Visible to the external world via the transport structure.
 */

/*
 * Notes:
 *	- transport the command to the addressed SCSI target/lun device
 *	- normal operation is to schedule the command to be transported,
 *	  and return TRAN_ACCEPT if this is successful.
 *	- if NO_INTR, tran_start must poll device for command completion
 */
static int
mptsas_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(ap))
#endif
	mptsas_t	*mpt = PKT2MPT(pkt);
	mptsas_cmd_t	*cmd = PKT2CMD(pkt);
	int		rval;
	mptsas_target_t	*ptgt = cmd->cmd_tgt_addr;

	ASSERT(ptgt != NULL);
	NDBG1(("%d: scsi_start: targ %d, pkt=0x%p", mpt->m_instance,
	    ptgt->m_devhdl, (void *)pkt));

	/*
	 * prepare the pkt.
	 */
	mptsas_prepare_pkt(cmd);

	/*
	 * Send the command to target/lun, however your HBA requires it.
	 * If busy, return TRAN_BUSY; if there's some other formatting error
	 * in the packet, return TRAN_BADPKT; otherwise, fall through to the
	 * return of TRAN_ACCEPT.
	 *
	 * Remember that access to shared resources, including the mptsas_t
	 * data structure and the HBA hardware registers, must be protected
	 * with mutexes, here and everywhere.
	 *
	 * Also remember that at interrupt time, you'll get an argument
	 * to the interrupt handler which is a pointer to your mptsas_t
	 * structure; you'll have to remember which commands are outstanding
	 * and which scsi_pkt is the currently-running command so the
	 * interrupt handler can refer to the pkt to set completion
	 * status, call the target driver back through pkt_comp, etc.
	 *
	 * The normal path through here does not now need to take the
	 * per mpt instance lock. This should speed things up a lot.
	 */

	if (mpt->m_softstate & MPTSAS_SS_INIT_FAILED) {
		rval = TRAN_FATAL_ERROR;
	} else {
		if (ptgt->m_dr_flag == MPTSAS_DR_INTRANSITION) {
			mptsas_set_pkt_reason(mpt, cmd, CMD_DEV_GONE,
			    STAT_ABORTED);
			mutex_enter(&mpt->m_mutex);
			mptsas_doneq_add(mpt, cmd);
			mptsas_deliver_doneq_thread(mpt, &mpt->m_done);
			mutex_exit(&mpt->m_mutex);
			return (TRAN_ACCEPT);
		}
		rval = TRAN_ACCEPT;
	}
	if (rval == TRAN_ACCEPT) {
		rval = mptsas_accept_pkt(mpt, cmd);
	}

	return (rval);
}

static void
mptsas_dispatch_offline_tgt(mptsas_t *mpt, mptsas_target_t *ptgt,
    boolean_t reldevhdl)
{
	mptsas_topo_change_list_t	*topo_node;

	NDBG20(("%d: dispatch_offline_target: target %d, cnfg_luns 0x%x"
	    " rdh %s", mpt->m_instance, ptgt->m_devhdl, ptgt->m_cnfg_luns,
	    reldevhdl ? "True" : "False"));

	topo_node = kmem_zalloc(sizeof (mptsas_topo_change_list_t), KM_SLEEP);
	topo_node->mpt = mpt;
	topo_node->un.phymask = ptgt->m_addr.mta_phymask;
	topo_node->event = MPTSAS_DR_EVENT_OFFLINE_TARGET;
	topo_node->devhdl = ptgt->m_devhdl;
	if (reldevhdl)
		topo_node->object = (void *)ptgt;
	topo_node->flags = ptgt->m_deviceinfo & DEVINFO_DIRECT_ATTACHED ?
	    MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE :
	    MPTSAS_TOPO_FLAG_EXPANDER_ATTACHED_DEVICE;
	(void) ddi_taskq_dispatch(mpt->m_dr_taskq, mptsas_handle_dr,
	    (void *)topo_node, DDI_SLEEP);
}

static void
mptsas_dispatch_reconf_tgt(mptsas_t *mpt, mptsas_target_t *ptgt,
    uint16_t devhdl, uint_t dflags, uint8_t tflags)
{
	mptsas_topo_change_list_t	*topo_node;

	ASSERT(mutex_owned(&mpt->m_mutex));
	NDBG20(("%d: dispatch_reconf_target: target %d(%d)",
	    mpt->m_instance, devhdl, ptgt->m_devhdl));

	topo_node = kmem_zalloc(sizeof (mptsas_topo_change_list_t),
	    dflags == DDI_NOSLEEP ? KM_NOSLEEP : KM_SLEEP);
	if (topo_node == NULL) {
		mptsas_log(mpt, CE_NOTE, "No memory"
		    "resource to handle SAS dynamic reconfigure.");
		return;
	}

	topo_node->mpt = mpt;
	topo_node->event = MPTSAS_DR_EVENT_RECONFIG_TARGET;
	topo_node->flags = tflags;
	topo_node->devhdl = devhdl;

	if (tflags == MPTSAS_TOPO_FLAG_LUN_ASSOCIATED) {
		/*
		 * Called due to a unit attention from
		 * mptsas_check_scsi_io_error(). In this case we can supply
		 * the target pointer because it is not offline and does not
		 * need to be searched for.
		 */
		ASSERT(ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL);
		topo_node->object = (void *)ptgt;
		topo_node->un.phymask = ptgt->m_addr.mta_phymask;
	} else {
		int i;

		for (i = 0; i < mpt->m_num_phys; i++) {
			if (mpt->m_phy_info[i].phy_mask ==
			    ptgt->m_addr.mta_phymask)
				break;
		}
		if (i == mpt->m_num_phys) {
			kmem_free(topo_node,
			    sizeof (mptsas_topo_change_list_t));
			mptsas_log(mpt, CE_NOTE, "?mptsas3%d: No phymask match"
			    " for target %d online attempt.",
			    mpt->m_instance, devhdl);
			return;
		}
		topo_node->un.physport = mpt->m_phy_info[i].port_num;
	}
	if (ddi_taskq_dispatch(mpt->m_dr_taskq, mptsas_handle_dr,
	    (void *)topo_node, dflags) != DDI_SUCCESS) {
		kmem_free(topo_node, sizeof (mptsas_topo_change_list_t));
		mptsas_log(mpt, CE_NOTE, "?mptsas start taskq"
		    "for target %d ddi_taskq_dispatch failed.", devhdl);
	}
}

#ifdef AUTO_OFFLINE_TARGETS
/*
 * Check if we have overrun the cmd timeout max count before offlining.
 * If so schedule a task queue to actually do the offline. Calling
 * mptsas_offline_target() directly can hang as it will try to get the
 * ndi mutex which may already be acquired for a bus rescan.
 * A rescan invokes inquiry commands from within mpt_sas3.
 * If the watch routine is stuck here it cannot timeout those commands.
 * --> Function has the side effect of dropping the target mutex. <--
 */
static void
mptsas_target_cmds_expired(mptsas_t *mpt, mptsas_target_t *ptgt,
    mptsas_cmd_t *cmd)
{
	uint8_t				odr;

	ASSERT(mutex_owned(&mpt->m_mutex));
	ASSERT(mutex_owned(&ptgt->m_t_mutex));

	mptsas_log(mpt, CE_NOTE, "Timeout of %d seconds expired with %d "
	    "commands (flags:0x%x,0x%x idx %d,%d) on target %d lun %d.",
	    cmd->cmd_pkt->pkt_time, ptgt->m_t_ncmds, cmd->cmd_flags,
	    TAILQ_LAST(&ptgt->m_active_cmdq, mptsas_active_cmdq)->cmd_flags,
	    cmd->cmd_rpqidx,
	    TAILQ_LAST(&ptgt->m_active_cmdq, mptsas_active_cmdq)->cmd_rpqidx,
	    ptgt->m_devhdl, Lun(cmd));

	ptgt->m_timeout_ncmd++;

	/*
	 * If we have exhausted a set number of consecutive timeouts
	 * try to take the disk offline. However, we don't do this during
	 * an online attempt as seen by the cnfg_luns flag.
	 */
	if (ptgt->m_timeout_ncmd >= mptsas_timeout_cmd_retries &&
	    ptgt->m_cnfg_luns == 0) {
		mptsas_log(mpt, CE_WARN,
		    "watcher: offline target %d, sas-wwn:0x%016"PRIx64", "
		    "enclosure: %u, slotno: %u, phy-num: %u timeout:%u/%u.\n",
		    ptgt->m_devhdl, ptgt->m_addr.mta_wwn, ptgt->m_enclosure,
		    ptgt->m_slot_num, ptgt->m_phynum, ptgt->m_timeout_ncmd,
		    mptsas_timeout_cmd_retries);
		ptgt->m_timeout_ncmd = 0;
		odr = atomic_swap_8(&ptgt->m_dr_flag, MPTSAS_DR_INTRANSITION);
		NDBG28(("%d: targ %d dr_flag (%d) to intxtn-e.",
		    mpt->m_instance, ptgt->m_devhdl, odr));
		mutex_exit(&ptgt->m_t_mutex);

		/*
		 * If it isn't already in transition offline target.
		 * This should eventually clear out all active commands for
		 * this target as well.
		 */
		if (odr != MPTSAS_DR_INTRANSITION) {
			mptsas_dispatch_offline_tgt(mpt, ptgt, B_FALSE);
		}
	} else {
		mutex_exit(&ptgt->m_t_mutex);
		mptsas_cmd_timeout(mpt, ptgt);
	}
}
#endif /* AUTO_OFFLINE_TARGETS */

/*
 * mptsas_accept_pkt() - Primary objective is to get the command to the
 * controller through mptsas_start_cmd() as quickly as possible.
 * If something gets in the way add to the per target waitq.
 */
static int
mptsas_accept_pkt(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	int		rval = TRAN_ACCEPT;
	mptsas_target_t	*ptgt = cmd->cmd_tgt_addr;
#ifdef AUTO_OFFLINE_TARGETS
	struct scsi_pkt	*pkt = CMD2PKT(cmd);
#endif

	NDBG1(("%d: accept_pkt: cmd=0x%p", mpt->m_instance,
	    (void *)cmd));

	ASSERT((cmd->cmd_flags & CFLAG_TM_CMD) == 0);

#ifdef AUTO_OFFLINE_TARGETS
	if (pkt->pkt_time > mptsas_global_cmd_timeout &&
	    cmd->cmd_cdb[0] != SCMD_START_STOP) {
		NDBG3(("%d: reset command timeout: cmd=0x%p(0x%02x) "
		    "%u to %u ", mpt->m_instance, (void *)cmd, cmd->cmd_cdb[0],
		    pkt->pkt_time, mptsas_global_cmd_timeout));
		pkt->pkt_time = mptsas_global_cmd_timeout;
	}
#endif

	if ((cmd->cmd_flags & CFLAG_PREPARED) == 0) {
		mptsas_prepare_pkt(cmd);
	}

	mutex_enter(&ptgt->m_t_mutex);

	/*
	 * If device handle has been invalidated and the target is in
	 * init state CLEARED we are in the middle of updating the driver
	 * data. Allow commands to queue.
	 * The only other possibility is that we are offlining the target but
	 * in that case the dr_flag should be set and we shouldn't even get
	 * here.
	 */
	if (ptgt->m_devhdl == MPTSAS_INVALID_DEVHDL &&
	    ptgt->m_t_init != TINIT_UPDATE) {
		NDBG3(("%d: rejecting command for wwn %016"PRIx64", "
		    "invalid devhdl.", mpt->m_instance, ptgt->m_addr.mta_wwn));

		/*
		 * If HBA is being reset, the DevHandles are being
		 * re-initialized, which means that they could be invalid even
		 * if the target is still attached.  Check if being reset and
		 * if DevHandle is being re-initialized.  If this is the case,
		 * return BUSY so the I/O can be retried later.
		 */
		if (mpt->m_in_reset == TRUE) {
			mptsas_set_pkt_reason(mpt, cmd, CMD_RESET,
			    STAT_BUS_RESET);
			rval = TRAN_BUSY;
		} else {
			mptsas_set_pkt_reason(mpt, cmd, CMD_DEV_GONE,
			    STAT_TERMINATED);
			rval = TRAN_FATAL_ERROR;
		}
		mutex_exit(&ptgt->m_t_mutex);
		return (rval);
	}

	/*
	 * reset the throttle if we were draining
	 */
	if ((ptgt->m_t_ncmds == 0) &&
	    (ptgt->m_t_throttle == DRAIN_THROTTLE)) {
		NDBG23(("%d: reset throttle", mpt->m_instance));
		ASSERT(ptgt->m_reset_delay == 0);
		mptsas_set_throttle(mpt, ptgt, MAX_THROTTLE);
	}

	/*
	 * The first case is the normal case.  mpt gets a command from the
	 * target driver and starts it. mptsas_save_cmd_to_slot() will
	 * return FALSE if there is no space on the HBA.
	 */
	if ((ptgt->m_t_throttle > HOLD_THROTTLE) &&
	    (ptgt->m_t_ncmds < ptgt->m_t_throttle) &&
	    (ptgt->m_reset_delay == 0) && (mpt->m_polled_intr == 0) &&
	    (ptgt->m_t_wait.cl_len == 0 || (cmd->cmd_pkt_flags & FLAG_HEAD)) &&
	    ((cmd->cmd_pkt_flags & FLAG_NOINTR) == 0)) {
		ASSERT((cmd->cmd_flags & CFLAG_CMDIOC) == 0);
		if (mptsas_save_cmd_to_slot(mpt, cmd) == TRUE) {
			ptgt->m_t_ncmds++;
			cmd->cmd_active_expiration = 0;
			(void) mptsas_start_cmd(mpt, cmd);
			/* mptsas_start_cmd() releases the mutex */
		} else {
			mptsas_targwaitq_add(mpt, ptgt, cmd);
			mutex_exit(&ptgt->m_t_mutex);
		}
	} else {
		/*
		 * Take a copy of the do-as-polled flag for this command
		 * before releasing the target mutex. Once we add to the target
		 * wait q and release the target mutex the command structure
		 * can disappear unless it's polled.
		 */
		boolean_t do_polled = (cmd->cmd_pkt_flags & FLAG_NOINTR) != 0;

		/*
		 * If a target is undergoing reset it should be ok to not error
		 * commands immediately and allow them to be re-submitted when
		 * the reset delay is complete.
		 */
		if (ptgt->m_reset_delay == 0 && ptgt->m_cnfg_luns != 0 && !do_polled) {
			/*
			 * With cnfg_luns set it means we have the global
			 * ndi_devi locks and *nothing* else can proceed until
			 * whichever config this is has completed. Putting the
			 * command on the wait queue can easily deadlock the
			 * system. Need to be careful, however, the situation
			 * may not be the fault of this target.
			 * Check for IOPB commands or commands that have
			 * FLAG_NOQUEUE	set.
			 */
			if ((cmd->cmd_flags & CFLAG_CMDIOPB) == CFLAG_CMDIOPB ||
			    (cmd->cmd_pkt_flags & (FLAG_NOQUEUE|FLAG_SILENT)) ==
			    (FLAG_NOQUEUE|FLAG_SILENT)) {
				mptsas_log(mpt, CE_WARN,
				    "!Error %s cmd for targ %d",
				    (cmd->cmd_flags & CFLAG_CMDIOPB) ==
				    CFLAG_CMDIOPB ? "IOPB" : "NOQUEUE",
				    ptgt->m_devhdl);
				DTRACE_PROBE2(error__cfglun__cmd, mptsas_t *,
				    mpt, mptsas_cmd_t *, cmd);
				
				/*
				 * This is bad news. Most likely the command is
				 * from vhci or driver attach.
				 * There is a comment for the NOQUEUE flag in
				 * scsi_pkt.h. However if we return TRAN_BUSY
				 * sd gets stuck re-trying.
				 * Error the command as incomplete or reset
				 * according to the m_reset state.
				 * Also set the FLAG_DIAGNOSE bit to prevent
				 * retries.
				 */
				mutex_exit(&ptgt->m_t_mutex);
				mutex_enter(&mpt->m_mutex);
				mptsas_set_pkt_reason(mpt, cmd,
				    mpt->m_in_reset ? CMD_RESET :
				    CMD_INCOMPLETE,
				    mpt->m_in_reset ? STAT_BUS_RESET :
				    STAT_ABORTED);
				cmd->cmd_pkt->pkt_flags |= FLAG_DIAGNOSE;
				mptsas_doneq_add(mpt, cmd);
				mptsas_deliver_doneq_thread(mpt, &mpt->m_done);
				mutex_exit(&mpt->m_mutex);
				return (TRAN_ACCEPT);
			}
		}

		/*
		 * Add this pkt to the work queue
		 */
		mptsas_targwaitq_add(mpt, ptgt, cmd);
		mutex_exit(&ptgt->m_t_mutex);

		if (do_polled) {
			mutex_enter(&mpt->m_mutex);
			(void) mptsas_poll(mpt, cmd, MPTSAS_POLL_TIME);
			mptsas_pkt_comp(cmd);
			mptsas_doneq_apempty(mpt);
			mutex_exit(&mpt->m_mutex);
		}
	}
	return (rval);
}

static void
mptsas_retry_pkt(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	int		rval;

	ASSERT(MUTEX_HELD(&mpt->m_mutex));

	cmd->cmd_pkt_flags |= FLAG_HEAD;
	cmd->cmd_flags |= (CFLAG_RETRY|CFLAG_DIDRETRY);

	/*
	 * mptsas_accept_pkt() will allocate a new slot, remove this
	 * command from it's original slot. This also maintains counts.
	 */
	mptsas_deref_cmd(mpt, cmd);
	if (cmd->cmd_tgt_addr != NULL) {
		atomic_inc_32(&cmd->cmd_tgt_addr->m_retry_count);
	}
	mutex_exit(&mpt->m_mutex);
	rval = mptsas_accept_pkt(mpt, cmd);

	/*
	 * If there was a problem clear the retry flag so that the
	 * command will be completed with error rather than get lost!
	 */
	if (rval != TRAN_ACCEPT) {
		/* mptsas_accept_pkt() will already have set the pkt reason */
		cmd->cmd_flags &= ~CFLAG_RETRY;
	}
	mutex_enter(&mpt->m_mutex);
}

static int
mptsas_save_cmd_to_slot(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	mptsas_slots_t	*slots = mpt->m_active;
	uint16_t	slot, start_rotor, rotor, n_normal;
	void		*acres;
	int8_t		repq = 0;
#ifdef MPTSAS_DEBUG
	int		failcount = -1;
#endif

	/*
	 * Account for reserved TM request slot and reserved SMID of 0.
	 */
	ASSERT(slots->m_n_normal == (mpt->m_max_requests - 2));

	/*
	 * Find the next available slot, beginning at m_rotor.  If no slot is
	 * available, we'll return FALSE to indicate that.  This mechanism
	 * considers only the normal slots, not the reserved slot 0 nor the
	 * task management slot m_n_normal + 1.  The rotor is left to point to
	 * the normal slot after the one we select, unless we select the last
	 * normal slot in which case it returns to slot 1.
	 * There is no mutex protection here, we rely on the atomic
	 * operation to ensure multiple threads do not get the same slot.
	 * The fact that we may overwrite the rotor value isn't important,
	 * it's just a hint.
	 */
	start_rotor = rotor = slots->m_rotor;
	n_normal = slots->m_n_normal;
	do {
#ifdef MPTSAS_DEBUG
		failcount++;
#endif
		slot = rotor++;
		if (rotor > n_normal)
			rotor = 1;

		if (rotor == start_rotor)
			break;
		acres = atomic_cas_ptr(&slots->m_slot[slot], NULL, cmd);
	} while (acres != NULL);

	if (acres != NULL)
		return (FALSE);

	slots->m_rotor = rotor;
	ASSERT(slot != 0 && slot <= slots->m_n_normal);

#ifdef MPTSAS_DEBUG
	DTRACE_PROBE2(save__cmd__2slot, mptsas_t *, mpt, int, failcount);
#endif

	cmd->cmd_slot = slot;
	atomic_inc_32(&mpt->m_ncmds);

	/*
	 * Distribute the commands amongst the reply queues (Interrupt vectors).
	 * Stick to 0 for polled.
	 */
	if (!(cmd->cmd_pkt_flags & FLAG_NOINTR) &&
	    !(cmd->cmd_flags & (CFLAG_PASSTHRU|CFLAG_CONFIG|CFLAG_FW_DIAG))) {
		/*
		 * If we have a reply q on the cpu running the current
		 * thread use that queue to optimize cache hits during
		 * the completion processing. Otherwise just do round
		 * robin.
		 */
		repq = mpt->m_cpu_to_repq[CPU_SEQID];

		if (repq >= 0) {
			cmd->cmd_flags |= CFLAG_CPUONREPQ;
			atomic_inc_32(&mpt->m_rpqcpuhit_cmds);
		} else if (mpt->m_post_reply_qcount > 1) {
			repq = slot % mpt->m_post_reply_qcount;
		} else {
			repq = 0;
		}
	}
	cmd->cmd_rpqidx = repq;
	atomic_inc_32(&mpt->m_rep_post_queues[(int)repq].rpq_ncmds);
	return (TRUE);
}

/*
 * Insert into an active expiration linked list and ensure the list
 * is ordered in decreasing expiration time.
 */
void
mptsas_insert_expiration(mptsas_active_cmdq_t *exq, mptsas_cmd_t *cmd)
{
	mptsas_cmd_t		*c;

	c = TAILQ_FIRST(exq);
	if (c == NULL ||
	    c->cmd_active_expiration < cmd->cmd_active_expiration) {
		/*
		 * Common case is that this is the last pending expiration
		 * (or queue is empty). Insert at head of the queue.
		 */
		TAILQ_INSERT_HEAD(exq, cmd, cmd_active_link);
	} else {
		/*
		 * Queue is not empty and first element expires later than
		 * this command. Search for element expiring sooner.
		 */
		while ((c = TAILQ_NEXT(c, cmd_active_link)) != NULL) {
			if (c->cmd_active_expiration <
			    cmd->cmd_active_expiration) {
				TAILQ_INSERT_BEFORE(c, cmd, cmd_active_link);
				break;
			}
		}
		if (c == NULL) {
			/*
			 * No element found expiring sooner, append to
			 * non-empty queue.
			 */
			TAILQ_INSERT_TAIL(exq, cmd, cmd_active_link);
		}
	}
}

int
mptsas_save_ioccmd(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	struct scsi_pkt		*pkt = CMD2PKT(cmd);

	ASSERT(MUTEX_HELD(&mpt->m_mutex));
	ASSERT((cmd->cmd_flags & (CFLAG_TM_CMD|CFLAG_CMDIOC)) == CFLAG_CMDIOC);

	if (mpt->m_softstate & (MPTSAS_SS_QUIESCED | MPTSAS_SS_DRAINING) ||
	    mpt->m_in_reset == TRUE) {
		return (FALSE);
	}

	if (!mptsas_save_cmd_to_slot(mpt, cmd)) {
		return (FALSE);
	}

	/*
	 * Initialize expiration time for "other" commands,
	 */
	pkt->pkt_start = gethrtime();
	cmd->cmd_active_expiration = pkt->pkt_start +
	    (hrtime_t)pkt->pkt_time * NANOSEC;
	mptsas_insert_expiration(&mpt->m_active_ioccmdq, cmd);
	mpt->m_nioccmds++;
	return (TRUE);
}

/*
 * Scan the slot array for commands and call the given function for any that
 * are found. It's down to the calling function to ensure the command will
 * not disappear from under us.
 * Account for TM requests, which use the last SMID.
 */
static void
mptsas_scan_slots(mptsas_t *mpt, void (*func)(mptsas_t *, mptsas_cmd_t *,
    void *), void *arg)
{
	int		i;
	mptsas_cmd_t	*cmd;

	for (i = 1; i <= mpt->m_active->m_n_normal; i++) {
		if ((cmd = mpt->m_active->m_slot[i]) != NULL) {
			func(mpt, cmd, arg);
		}
	}
}

/*
 * prepare the pkt:
 * the pkt may have been resubmitted or just reused so
 * initialize some fields and do some checks.
 */
static void
mptsas_prepare_pkt(mptsas_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);

	NDBG1(("mptsas_prepare_pkt: cmd=0x%p", (void *)cmd));

	/*
	 * Reinitialize some fields that need it; the packet may
	 * have been resubmitted
	 */
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;
	pkt->pkt_resid = 0;
	cmd->cmd_pkt_flags = pkt->pkt_flags;

	/*
	 * zero status byte.
	 */
	*(pkt->pkt_scbp) = 0;

	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		pkt->pkt_resid = cmd->cmd_dmacount;

		/*
		 * consistent packets need to be sync'ed first
		 * (only for data going out)
		 */
		if ((cmd->cmd_flags & CFLAG_CMDIOPB) &&
		    (cmd->cmd_flags & CFLAG_DMASEND)) {
			(void) ddi_dma_sync(cmd->cmd_dmahandle, 0, 0,
			    DDI_DMA_SYNC_FORDEV);
		}
	}

	cmd->cmd_flags =
	    (cmd->cmd_flags & ~(CFLAG_TRANFLAG)) |
	    CFLAG_PREPARED | CFLAG_IN_TRANSPORT;
}

/*
 * tran_init_pkt(9E) - allocate scsi_pkt(9S) for command
 *
 * One of three possibilities:
 *	- allocate scsi_pkt
 *	- allocate scsi_pkt and DMA resources
 *	- allocate DMA resources to an already-allocated pkt
 */
static struct scsi_pkt *
mptsas_scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
    int (*callback)(), caddr_t arg)
{
	mptsas_cmd_t		*cmd, *new_cmd;
	mptsas_t		*mpt = ADDR2MPT(ap);
	int			failure = 1;
	uint_t			oldcookiec;
	mptsas_target_t		*ptgt = NULL;
	int			rval;
	mptsas_tgt_private_t	*tgt_private;
	int			kf;

	kf = (callback == SLEEP_FUNC)? KM_SLEEP: KM_NOSLEEP;

	tgt_private = (mptsas_tgt_private_t *)ap->a_hba_tran->
	    tran_tgt_private;
	ASSERT(tgt_private != NULL);
	if (tgt_private == NULL) {
		return (NULL);
	}
	ptgt = tgt_private->t_private;
	ASSERT(ptgt != NULL);
	if (ptgt == NULL)
		return (NULL);
	ap->a_target = ptgt->m_devhdl;
	ap->a_lun = tgt_private->t_lun;

	ASSERT(callback == NULL_FUNC || callback == SLEEP_FUNC);
	NDBG3(("%d: scsi_init_pkt:\n"
	    "\ttgt=%d in=0x%p bp=0x%p clen=%d slen=%d tlen=%d flags=%x",
	    mpt->m_instance, ap->a_target, (void *)pkt, (void *)bp,
	    cmdlen, statuslen, tgtlen, flags));

	/*
	 * Allocate the new packet.
	 */
	if (pkt == NULL) {
		ddi_dma_handle_t	save_dma_handle;

		cmd = kmem_cache_alloc(mpt->m_kmem_cache, kf);

		if (cmd) {
			save_dma_handle = cmd->cmd_dmahandle;
			bzero(cmd, sizeof (*cmd) + scsi_pkt_size());
			cmd->cmd_dmahandle = save_dma_handle;

			pkt = (void *)((uchar_t *)cmd +
			    sizeof (struct mptsas_cmd));
			pkt->pkt_ha_private = (opaque_t)cmd;
			pkt->pkt_address = *ap;
			pkt->pkt_private = (opaque_t)cmd->cmd_pkt_private;
			pkt->pkt_scbp = (opaque_t)&cmd->cmd_scb;
			pkt->pkt_cdbp = (opaque_t)&cmd->cmd_cdb;
			cmd->cmd_pkt = (struct scsi_pkt *)pkt;
			cmd->cmd_cdblen = (uchar_t)cmdlen;
			cmd->cmd_scblen = statuslen;
			cmd->cmd_rqslen = SENSE_LENGTH;
			cmd->cmd_tgt_addr = ptgt;
			failure = 0;
		}

		if (failure || (cmdlen > sizeof (cmd->cmd_cdb)) ||
		    (tgtlen > PKT_PRIV_LEN) ||
		    (statuslen > EXTCMDS_STATUS_SIZE)) {
			if (failure == 0) {
				/*
				 * if extern alloc fails, all will be
				 * deallocated, including cmd
				 */
				failure = mptsas_pkt_alloc_extern(mpt, cmd,
				    cmdlen, tgtlen, statuslen, kf);
			}
			if (failure) {
				/*
				 * if extern allocation fails, it will
				 * deallocate the new pkt as well
				 */
				return (NULL);
			}
		}
		new_cmd = cmd;

	} else {
		cmd = PKT2CMD(pkt);
		pkt->pkt_start = 0;
		pkt->pkt_stop = 0;
		new_cmd = NULL;
	}


	/* grab cmd->cmd_cookiec here as oldcookiec */

	oldcookiec = cmd->cmd_cookiec;

	/*
	 * If the dma was broken up into PARTIAL transfers cmd_nwin will be
	 * greater than 0 and we'll need to grab the next dma window
	 */
	/*
	 * SLM-not doing extra command frame right now; may add later
	 */

	if (cmd->cmd_nwin > 0) {

		/*
		 * Make sure we havn't gone past the the total number
		 * of windows
		 */
		if (++cmd->cmd_winindex >= cmd->cmd_nwin) {
			return (NULL);
		}
		if (ddi_dma_getwin(cmd->cmd_dmahandle, cmd->cmd_winindex,
		    &cmd->cmd_dma_offset, &cmd->cmd_dma_len,
		    &cmd->cmd_cookie, &cmd->cmd_cookiec) == DDI_FAILURE) {
			return (NULL);
		}
		goto get_dma_cookies;
	}


	if (flags & PKT_XARQ) {
		cmd->cmd_flags |= CFLAG_XARQ;
	}

	/*
	 * DMA resource allocation.  This version assumes your
	 * HBA has some sort of bus-mastering or onboard DMA capability, with a
	 * scatter-gather list of length MPTSAS_MAX_DMA_SEGS, as given in the
	 * ddi_dma_attr_t structure and passed to scsi_impl_dmaget.
	 */
	if (bp && (bp->b_bcount != 0) &&
	    (cmd->cmd_flags & CFLAG_DMAVALID) == 0) {

		int	cnt, dma_flags;
		mptti_t	*dmap;		/* ptr to the S/G list */

		/*
		 * Set up DMA memory and position to the next DMA segment.
		 */
		ASSERT(cmd->cmd_dmahandle != NULL);

		if (bp->b_flags & B_READ) {
			dma_flags = DDI_DMA_READ;
			cmd->cmd_flags &= ~CFLAG_DMASEND;
		} else {
			dma_flags = DDI_DMA_WRITE;
			cmd->cmd_flags |= CFLAG_DMASEND;
		}
		if (flags & PKT_CONSISTENT) {
			cmd->cmd_flags |= CFLAG_CMDIOPB;
			dma_flags |= DDI_DMA_CONSISTENT;
		}

		if (flags & PKT_DMA_PARTIAL) {
			dma_flags |= DDI_DMA_PARTIAL;
		}

		/*
		 * workaround for byte hole issue on psycho and
		 * schizo pre 2.1
		 */
		if ((bp->b_flags & B_READ) && ((bp->b_flags &
		    (B_PAGEIO|B_REMAPPED)) != B_PAGEIO) &&
		    ((uintptr_t)bp->b_un.b_addr & 0x7)) {
			dma_flags |= DDI_DMA_CONSISTENT;
		}

		rval = ddi_dma_buf_bind_handle(cmd->cmd_dmahandle, bp,
		    dma_flags, callback, arg,
		    &cmd->cmd_cookie, &cmd->cmd_cookiec);
		if (rval == DDI_DMA_PARTIAL_MAP) {
			(void) ddi_dma_numwin(cmd->cmd_dmahandle,
			    &cmd->cmd_nwin);
			cmd->cmd_winindex = 0;
			(void) ddi_dma_getwin(cmd->cmd_dmahandle,
			    cmd->cmd_winindex, &cmd->cmd_dma_offset,
			    &cmd->cmd_dma_len, &cmd->cmd_cookie,
			    &cmd->cmd_cookiec);
		} else if (rval && (rval != DDI_DMA_MAPPED)) {
			switch (rval) {
			case DDI_DMA_NORESOURCES:
				bioerror(bp, 0);
				break;
			case DDI_DMA_BADATTR:
			case DDI_DMA_NOMAPPING:
				bioerror(bp, EFAULT);
				break;
			case DDI_DMA_TOOBIG:
			default:
				bioerror(bp, EINVAL);
				break;
			}
			cmd->cmd_flags &= ~CFLAG_DMAVALID;
			if (new_cmd) {
				mptsas_scsi_destroy_pkt(ap, pkt);
			}
			return ((struct scsi_pkt *)NULL);
		}

get_dma_cookies:
		cmd->cmd_flags |= CFLAG_DMAVALID;
		ASSERT(cmd->cmd_cookiec > 0);

		if (cmd->cmd_cookiec > MPTSAS_MAX_CMD_SEGS) {
			mptsas_log(mpt, CE_NOTE, "large cookiec received %d\n",
			    cmd->cmd_cookiec);
			bioerror(bp, EINVAL);
			if (new_cmd) {
				mptsas_scsi_destroy_pkt(ap, pkt);
			}
			return ((struct scsi_pkt *)NULL);
		}

		/*
		 * Allocate extra SGL buffer if needed.
		 */
		if ((cmd->cmd_cookiec > MPTSAS_MAX_FRAME_SGES64(mpt)) &&
		    (cmd->cmd_extra_frames == NULL)) {
			if (mptsas_alloc_extra_sgl_frame(mpt, cmd) ==
			    DDI_FAILURE) {
				mptsas_log(mpt, CE_WARN, "MPT SGL mem alloc "
				    "failed");
				bioerror(bp, ENOMEM);
				if (new_cmd) {
					mptsas_scsi_destroy_pkt(ap, pkt);
				}
				return ((struct scsi_pkt *)NULL);
			}
		}

		/*
		 * Always use scatter-gather transfer
		 * Use the loop below to store physical addresses of
		 * DMA segments, from the DMA cookies, into your HBA's
		 * scatter-gather list.
		 * We need to ensure we have enough kmem alloc'd
		 * for the sg entries since we are no longer using an
		 * array inside mptsas_cmd_t.
		 *
		 * We check cmd->cmd_cookiec against oldcookiec so
		 * the scatter-gather list is correctly allocated
		 */

		if (oldcookiec != cmd->cmd_cookiec) {
			if (cmd->cmd_sg != (mptti_t *)NULL) {
				kmem_free(cmd->cmd_sg, sizeof (mptti_t) *
				    oldcookiec);
				cmd->cmd_sg = NULL;
			}
		}

		if (cmd->cmd_sg == (mptti_t *)NULL) {
			cmd->cmd_sg = kmem_alloc((size_t)(sizeof (mptti_t)*
			    cmd->cmd_cookiec), kf);

			if (cmd->cmd_sg == (mptti_t *)NULL) {
				mptsas_log(mpt, CE_WARN,
				    "unable to kmem_alloc enough memory "
				    "for scatter/gather list");
		/*
		 * if we have an ENOMEM condition we need to behave
		 * the same way as the rest of this routine
		 */

				bioerror(bp, ENOMEM);
				if (new_cmd) {
					mptsas_scsi_destroy_pkt(ap, pkt);
				}
				return ((struct scsi_pkt *)NULL);
			}
		}

		dmap = cmd->cmd_sg;

		ASSERT(cmd->cmd_cookie.dmac_size != 0);

		/*
		 * store the first segment into the S/G list
		 */
		dmap->count = cmd->cmd_cookie.dmac_size;
		dmap->addr.address64.Low = (uint32_t)
		    (cmd->cmd_cookie.dmac_laddress & 0xffffffffull);
		dmap->addr.address64.High = (uint32_t)
		    (cmd->cmd_cookie.dmac_laddress >> 32);

		/*
		 * dmacount counts the size of the dma for this window
		 * (if partial dma is being used).  totaldmacount
		 * keeps track of the total amount of dma we have
		 * transferred for all the windows (needed to calculate
		 * the resid value below).
		 */
		cmd->cmd_dmacount = cmd->cmd_cookie.dmac_size;
		cmd->cmd_totaldmacount += cmd->cmd_cookie.dmac_size;

		/*
		 * We already stored the first DMA scatter gather segment,
		 * start at 1 if we need to store more.
		 */
		for (cnt = 1; cnt < cmd->cmd_cookiec; cnt++) {
			/*
			 * Get next DMA cookie
			 */
			ddi_dma_nextcookie(cmd->cmd_dmahandle,
			    &cmd->cmd_cookie);
			dmap++;

			cmd->cmd_dmacount += cmd->cmd_cookie.dmac_size;
			cmd->cmd_totaldmacount += cmd->cmd_cookie.dmac_size;

			/*
			 * store the segment parms into the S/G list
			 */
			dmap->count = cmd->cmd_cookie.dmac_size;
			dmap->addr.address64.Low = (uint32_t)
			    (cmd->cmd_cookie.dmac_laddress & 0xffffffffull);
			dmap->addr.address64.High = (uint32_t)
			    (cmd->cmd_cookie.dmac_laddress >> 32);
		}

		/*
		 * If this was partially allocated we set the resid
		 * the amount of data NOT transferred in this window
		 * If there is only one window, the resid will be 0
		 */
		pkt->pkt_resid = (bp->b_bcount - cmd->cmd_totaldmacount);
		NDBG3(("%d: scsi_init_pkt: cmd_dmacount=%d.",
		    mpt->m_instance, cmd->cmd_dmacount));
	}
	return (pkt);
}

/*
 * tran_destroy_pkt(9E) - scsi_pkt(9s) deallocation
 *
 * Notes:
 *	- also frees DMA resources if allocated
 *	- implicit DMA synchonization
 */
static void
mptsas_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	mptsas_cmd_t	*cmd = PKT2CMD(pkt);
	mptsas_t	*mpt = ADDR2MPT(ap);

	NDBG3(("%d: scsi_destroy_pkt: target=%d pkt=0x%p",
	    mpt->m_instance, ap->a_target, (void *)pkt));

	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		(void) ddi_dma_unbind_handle(cmd->cmd_dmahandle);
		cmd->cmd_flags &= ~CFLAG_DMAVALID;
	}

	if (cmd->cmd_sg) {
		kmem_free(cmd->cmd_sg, sizeof (mptti_t) * cmd->cmd_cookiec);
		cmd->cmd_sg = NULL;
	}

	mptsas_free_extra_sgl_frame(mpt, cmd);

	if ((cmd->cmd_flags &
	    (CFLAG_FREE | CFLAG_CDBEXTERN | CFLAG_PRIVEXTERN |
	    CFLAG_SCBEXTERN)) == 0) {
		cmd->cmd_flags = CFLAG_FREE;
		kmem_cache_free(mpt->m_kmem_cache, (void *)cmd);
	} else {
		mptsas_pkt_destroy_extern(mpt, cmd);
	}
}

/*
 * kmem cache constructor and destructor:
 * When constructing, we bzero the cmd and allocate the dma handle
 * When destructing, just free the dma handle
 */
static int
mptsas_kmem_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	mptsas_cmd_t		*cmd = buf;
	mptsas_t		*mpt  = cdrarg;
	int			(*callback)(caddr_t);

	callback = (kmflags == KM_SLEEP)? DDI_DMA_SLEEP: DDI_DMA_DONTWAIT;

	NDBG4(("%d: kmem_cache_constructor for cmd 0x%p", mpt->m_instance,
	    (void *)cmd));

	/*
	 * allocate a dma handle
	 */
	if ((ddi_dma_alloc_handle(mpt->m_dip, &mpt->m_io_dma_attr, callback,
	    NULL, &cmd->cmd_dmahandle)) != DDI_SUCCESS) {
		cmd->cmd_dmahandle = NULL;
		return (-1);
	}
	return (0);
}

static void
mptsas_kmem_cache_destructor(void *buf, void *cdrarg)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(cdrarg))
#endif
	mptsas_cmd_t	*cmd = buf;

	NDBG4(("%d: kmem_cache_destructor for cmd 0x%p",
	    ((mptsas_t *)cdrarg)->m_instance, (void *)cmd));

	if (cmd->cmd_dmahandle) {
		ddi_dma_free_handle(&cmd->cmd_dmahandle);
		cmd->cmd_dmahandle = NULL;
	}
}

static int
mptsas_cache_frames_constructor(void *buf, void *cdrarg, int kmflags)
{
	mptsas_cache_frames_t	*p = buf;
	mptsas_t		*mpt = cdrarg;
	ddi_dma_attr_t		frame_dma_attr;
	size_t			mem_size, alloc_len;
	ddi_dma_cookie_t	cookie;
	uint_t			ncookie;
	int (*callback)(caddr_t) = (kmflags == KM_SLEEP)
	    ? DDI_DMA_SLEEP: DDI_DMA_DONTWAIT;

	frame_dma_attr = mpt->m_msg_dma_attr;
	frame_dma_attr.dma_attr_align = 0x10;
	frame_dma_attr.dma_attr_sgllen = 1;

	if (ddi_dma_alloc_handle(mpt->m_dip, &frame_dma_attr, callback, NULL,
	    &p->m_dma_hdl) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "Unable to allocate dma handle for"
		    " extra SGL.");
		return (DDI_FAILURE);
	}

	mem_size = (mpt->m_max_request_frames - 1) * mpt->m_req_frame_size;

	if (ddi_dma_mem_alloc(p->m_dma_hdl, mem_size, &mpt->m_dev_acc_attr,
	    DDI_DMA_CONSISTENT, callback, NULL, (caddr_t *)&p->m_frames_addr,
	    &alloc_len, &p->m_acc_hdl) != DDI_SUCCESS) {
		ddi_dma_free_handle(&p->m_dma_hdl);
		p->m_dma_hdl = NULL;
		mptsas_log(mpt, CE_WARN, "Unable to allocate dma memory for"
		    " extra SGL.");
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(p->m_dma_hdl, NULL, p->m_frames_addr,
	    alloc_len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, callback, NULL,
	    &cookie, &ncookie) != DDI_DMA_MAPPED) {
		(void) ddi_dma_mem_free(&p->m_acc_hdl);
		ddi_dma_free_handle(&p->m_dma_hdl);
		p->m_dma_hdl = NULL;
		mptsas_log(mpt, CE_WARN, "Unable to bind DMA resources for"
		    " extra SGL");
		return (DDI_FAILURE);
	}

	/*
	 * Store the SGL memory address.  This chip uses this
	 * address to dma to and from the driver.  The second
	 * address is the address mpt uses to fill in the SGL.
	 */
	p->m_phys_addr = cookie.dmac_laddress;

	return (DDI_SUCCESS);
}

static void
mptsas_cache_frames_destructor(void *buf, void *cdrarg)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(cdrarg))
#endif
	mptsas_cache_frames_t	*p = buf;
	if (p->m_dma_hdl != NULL) {
		(void) ddi_dma_unbind_handle(p->m_dma_hdl);
		(void) ddi_dma_mem_free(&p->m_acc_hdl);
		ddi_dma_free_handle(&p->m_dma_hdl);
		p->m_phys_addr = 0;
		p->m_frames_addr = NULL;
		p->m_dma_hdl = NULL;
		p->m_acc_hdl = NULL;
	}

}

/*
 * Figure out if we need to use a different method for the request
 * sense buffer and allocate from the map if necessary.
 */
static void
mptsas_cmdarqsize(mptsas_t *mpt, mptsas_cmd_t *cmd, size_t senselength)
{
	if (senselength > mpt->m_req_sense_size) {
		unsigned long i;

		/* Sense length is limited to an 8 bit value in MPI Spec. */
		if (senselength > 255)
			senselength = 255;
		cmd->cmd_extrqslen = (uint16_t)senselength;
		cmd->cmd_extrqschunks = (senselength +
		    (mpt->m_req_sense_size - 1))/mpt->m_req_sense_size;
		i = rmalloc_wait(mpt->m_erqsense_map,
		    cmd->cmd_extrqschunks);
		ASSERT(i != 0);
		cmd->cmd_extrqsidx = i - 1;
	} else {
		cmd->cmd_rqslen = (uchar_t)senselength;
	}
}

/*
 * allocate and deallocate external pkt space (ie. not part of mptsas_cmd)
 * for non-standard length cdb, pkt_private, status areas
 * if allocation fails, then deallocate all external space and the pkt
 */
/* ARGSUSED */
static int
mptsas_pkt_alloc_extern(mptsas_t *mpt, mptsas_cmd_t *cmd,
    int cmdlen, int tgtlen, int statuslen, int kf)
{
	caddr_t			cdbp, scbp, tgt;

	NDBG3(("%d: pkt_alloc_extern: "
	    "cmd=0x%p cmdlen=%d tgtlen=%d statuslen=%d kf=%x", mpt->m_instance,
	    (void *)cmd, cmdlen, tgtlen, statuslen, kf));

	tgt = cdbp = scbp = NULL;
	cmd->cmd_scblen		= statuslen;
	cmd->cmd_privlen	= (uchar_t)tgtlen;

	if (cmdlen > sizeof (cmd->cmd_cdb)) {
		if ((cdbp = kmem_zalloc((size_t)cmdlen, kf)) == NULL) {
			goto fail;
		}
		cmd->cmd_pkt->pkt_cdbp = (opaque_t)cdbp;
		cmd->cmd_flags |= CFLAG_CDBEXTERN;
	}
	if (tgtlen > PKT_PRIV_LEN) {
		if ((tgt = kmem_zalloc((size_t)tgtlen, kf)) == NULL) {
			goto fail;
		}
		cmd->cmd_flags |= CFLAG_PRIVEXTERN;
		cmd->cmd_pkt->pkt_private = tgt;
	}
	if (statuslen > EXTCMDS_STATUS_SIZE) {
		if ((scbp = kmem_zalloc((size_t)statuslen, kf)) == NULL) {
			goto fail;
		}
		cmd->cmd_flags |= CFLAG_SCBEXTERN;
		cmd->cmd_pkt->pkt_scbp = (opaque_t)scbp;

		/* allocate sense data buf for DMA */
		mptsas_cmdarqsize(mpt, cmd, statuslen - MPTSAS_GET_ITEM_OFF(
		    struct scsi_arq_status, sts_sensedata));
	}
	return (0);
fail:
	mptsas_pkt_destroy_extern(mpt, cmd);
	return (1);
}

/*
 * deallocate external pkt space and deallocate the pkt
 */
static void
mptsas_pkt_destroy_extern(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	NDBG3(("%d: pkt_destroy_extern: cmd=0x%p", mpt->m_instance,
	    (void *)cmd));

	if (cmd->cmd_flags & CFLAG_FREE) {
		mptsas_log(mpt, CE_PANIC,
		    "mptsas_pkt_destroy_extern: freeing free packet");
		_NOTE(NOT_REACHED)
		/* NOTREACHED */
	}
	if (cmd->cmd_extrqslen != 0) {
		rmfree(mpt->m_erqsense_map, cmd->cmd_extrqschunks,
		    cmd->cmd_extrqsidx + 1);
	}
	if (cmd->cmd_flags & CFLAG_CDBEXTERN) {
		kmem_free(cmd->cmd_pkt->pkt_cdbp, (size_t)cmd->cmd_cdblen);
	}
	if (cmd->cmd_flags & CFLAG_SCBEXTERN) {
		kmem_free(cmd->cmd_pkt->pkt_scbp, (size_t)cmd->cmd_scblen);
	}
	if (cmd->cmd_flags & CFLAG_PRIVEXTERN) {
		kmem_free(cmd->cmd_pkt->pkt_private, (size_t)cmd->cmd_privlen);
	}
	cmd->cmd_flags = CFLAG_FREE;
	kmem_cache_free(mpt->m_kmem_cache, (void *)cmd);
}

/*
 * tran_sync_pkt(9E) - explicit DMA synchronization
 */
/*ARGSUSED*/
static void
mptsas_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	mptsas_cmd_t	*cmd = PKT2CMD(pkt);

	NDBG3(("%d: scsi_sync_pkt: target=%d, pkt=0x%p",
	    ADDR2MPT(ap)->m_instance, ap->a_target, (void *)pkt));

	if (cmd->cmd_dmahandle) {
		(void) ddi_dma_sync(cmd->cmd_dmahandle, 0, 0,
		    (cmd->cmd_flags & CFLAG_DMASEND) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
	}
}

/*
 * tran_dmafree(9E) - deallocate DMA resources allocated for command
 */
/*ARGSUSED*/
static void
mptsas_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	mptsas_cmd_t	*cmd = PKT2CMD(pkt);
	mptsas_t	*mpt = ADDR2MPT(ap);

	NDBG3(("%d: scsi_dmafree: target=%d pkt=0x%p", mpt->m_instance,
	    ap->a_target, (void *)pkt));

	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		(void) ddi_dma_unbind_handle(cmd->cmd_dmahandle);
		cmd->cmd_flags &= ~CFLAG_DMAVALID;
	}

	mptsas_free_extra_sgl_frame(mpt, cmd);
}

static void
mptsas_pkt_comp(mptsas_cmd_t *cmd)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);

	cmd->cmd_flags |= CFLAG_COMPLETED;
	if ((cmd->cmd_flags & CFLAG_CMDIOPB) &&
	    (!(cmd->cmd_flags & CFLAG_DMASEND))) {
		(void) ddi_dma_sync(cmd->cmd_dmahandle, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
	}
	if (pkt != NULL && pkt->pkt_comp != NULL) {
		(*pkt->pkt_comp)(pkt);
	}
}

static void
mptsas_sge_mainframe(mptsas_cmd_t *cmd, pMpi2SCSIIORequest_t frame,
		ddi_acc_handle_t acc_hdl, uint_t cookiec,
		uint32_t end_flags)
{
	pMpi2SGESimple64_t	sge;
	mptti_t			*dmap;
	uint32_t		flags;

	dmap = cmd->cmd_sg;

	sge = (pMpi2SGESimple64_t)(&frame->SGL);
	while (cookiec--) {
		ddi_put32(acc_hdl, &sge->Address.Low,
		    dmap->addr.address64.Low);
		ddi_put32(acc_hdl, &sge->Address.High,
		    dmap->addr.address64.High);
		ddi_put32(acc_hdl, &sge->FlagsLength, dmap->count);
		flags = ddi_get32(acc_hdl, &sge->FlagsLength);
		flags |= ((uint32_t)
		    (MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
		    MPI2_SGE_FLAGS_SYSTEM_ADDRESS |
		    MPI2_SGE_FLAGS_64_BIT_ADDRESSING) <<
		    MPI2_SGE_FLAGS_SHIFT);

		/*
		 * If this is the last cookie, we set the flags
		 * to indicate so
		 */
		if (cookiec == 0) {
			flags |= end_flags;
		}
		if (cmd->cmd_flags & CFLAG_DMASEND) {
			flags |= (MPI2_SGE_FLAGS_HOST_TO_IOC <<
			    MPI2_SGE_FLAGS_SHIFT);
		} else {
			flags |= (MPI2_SGE_FLAGS_IOC_TO_HOST <<
			    MPI2_SGE_FLAGS_SHIFT);
		}
		ddi_put32(acc_hdl, &sge->FlagsLength, flags);
		dmap++;
		sge++;
	}
}

static void
mptsas_sge_chain(mptsas_t *mpt, mptsas_cmd_t *cmd,
    pMpi2SCSIIORequest_t frame, ddi_acc_handle_t acc_hdl)
{
	pMpi2SGESimple64_t	sge;
	pMpi2SGEChain64_t	sgechain;
	uint64_t		nframe_phys_addr;
	uint_t			cookiec;
	mptti_t			*dmap;
	uint32_t		flags;
	int			i, j, k, l, frames, sgemax;
	int			temp, maxframe_sges;
	uint8_t			chainflags;
	uint16_t		chainlength;
	mptsas_cache_frames_t	*p;

	cookiec = cmd->cmd_cookiec;

	/*
	 * Hereby we start to deal with multiple frames.
	 * The process is as follows:
	 * 1. Determine how many frames are needed for SGL element
	 *    storage; Note that all frames are stored in contiguous
	 *    memory space and in 64-bit DMA mode each element is
	 *    3 double-words (12 bytes) long.
	 * 2. Fill up the main frame. We need to do this separately
	 *    since it contains the SCSI IO request header and needs
	 *    dedicated processing. Note that the last 4 double-words
	 *    of the SCSI IO header is for SGL element storage
	 *    (MPI2_SGE_IO_UNION).
	 * 3. Fill the chain element in the main frame, so the DMA
	 *    engine can use the following frames.
	 * 4. Enter a loop to fill the remaining frames. Note that the
	 *    last frame contains no chain element.  The remaining
	 *    frames go into the mpt SGL buffer allocated on the fly,
	 *    not immediately following the main message frame, as in
	 *    Gen1.
	 * Some restrictions:
	 * 1. For 64-bit DMA, the simple element and chain element
	 *    are both of 3 double-words (12 bytes) in size, even
	 *    though all frames are stored in the first 4G of mem
	 *    range and the higher 32-bits of the address are always 0.
	 * 2. On some controllers (like the 1064/1068), a frame can
	 *    hold SGL elements with the last 1 or 2 double-words
	 *    (4 or 8 bytes) un-used. On these controllers, we should
	 *    recognize that there's not enough room for another SGL
	 *    element and move the sge pointer to the next frame.
	 */

	/*
	 * Sgemax is the number of SGE's that will fit
	 * each extra frame and frames is total
	 * number of frames we'll need.  1 sge entry per
	 * frame is reseverd for the chain element thus the -1 below.
	 */
	sgemax = ((mpt->m_req_frame_size / sizeof (MPI2_SGE_SIMPLE64)) - 1);
	maxframe_sges = MPTSAS_MAX_FRAME_SGES64(mpt);
	temp = (cookiec - (maxframe_sges - 1)) / sgemax;

	/*
	 * A little check to see if we need to round up the number
	 * of frames we need
	 */
	if ((cookiec - (maxframe_sges - 1)) - (temp * sgemax) > 1) {
		frames = (temp + 1);
	} else {
		frames = temp;
	}
	dmap = cmd->cmd_sg;
	sge = (pMpi2SGESimple64_t)(&frame->SGL);

	/*
	 * First fill in the main frame
	 */
	j = maxframe_sges - 1;
	mptsas_sge_mainframe(cmd, frame, acc_hdl, j,
	    ((uint32_t)(MPI2_SGE_FLAGS_LAST_ELEMENT) <<
	    MPI2_SGE_FLAGS_SHIFT));
	dmap += j;
	sge += j;
	j++;

	/*
	 * Fill in the chain element in the main frame.
	 * About calculation on ChainOffset:
	 * 1. Struct msg_scsi_io_request has 4 double-words (16 bytes)
	 *    in the end reserved for SGL element storage
	 *    (MPI2_SGE_IO_UNION); we should count it in our
	 *    calculation.  See its definition in the header file.
	 * 2. Constant j is the counter of the current SGL element
	 *    that will be processed, and (j - 1) is the number of
	 *    SGL elements that have been processed (stored in the
	 *    main frame).
	 * 3. ChainOffset value should be in units of double-words (4
	 *    bytes) so the last value should be divided by 4.
	 */
	ddi_put8(acc_hdl, &frame->ChainOffset,
	    (sizeof (MPI2_SCSI_IO_REQUEST) -
	    sizeof (MPI2_SGE_IO_UNION) +
	    (j - 1) * sizeof (MPI2_SGE_SIMPLE64)) >> 2);
	sgechain = (pMpi2SGEChain64_t)sge;
	chainflags = (MPI2_SGE_FLAGS_CHAIN_ELEMENT |
	    MPI2_SGE_FLAGS_SYSTEM_ADDRESS |
	    MPI2_SGE_FLAGS_64_BIT_ADDRESSING);
	ddi_put8(acc_hdl, &sgechain->Flags, chainflags);

	/*
	 * The size of the next frame is the accurate size of space
	 * (in bytes) used to store the SGL elements. j is the counter
	 * of SGL elements. (j - 1) is the number of SGL elements that
	 * have been processed (stored in frames).
	 */
	if (frames >= 2) {
		chainlength = mpt->m_req_frame_size /
		    sizeof (MPI2_SGE_SIMPLE64) *
		    sizeof (MPI2_SGE_SIMPLE64);
	} else {
		chainlength = ((cookiec - (j - 1)) *
		    sizeof (MPI2_SGE_SIMPLE64));
	}

	p = cmd->cmd_extra_frames;

	ddi_put16(acc_hdl, &sgechain->Length, chainlength);
	ddi_put32(acc_hdl, &sgechain->Address.Low,
	    (p->m_phys_addr&0xffffffffull));
	ddi_put32(acc_hdl, &sgechain->Address.High, p->m_phys_addr>>32);

	/*
	 * If there are more than 2 frames left we have to
	 * fill in the next chain offset to the location of
	 * the chain element in the next frame.
	 * sgemax is the number of simple elements in an extra
	 * frame. Note that the value NextChainOffset should be
	 * in double-words (4 bytes).
	 */
	if (frames >= 2) {
		ddi_put8(acc_hdl, &sgechain->NextChainOffset,
		    (sgemax * sizeof (MPI2_SGE_SIMPLE64)) >> 2);
	} else {
		ddi_put8(acc_hdl, &sgechain->NextChainOffset, 0);
	}

	/*
	 * Jump to next frame;
	 * Starting here, chain buffers go into the per command SGL.
	 * This buffer is allocated when chain buffers are needed.
	 */
	sge = (pMpi2SGESimple64_t)p->m_frames_addr;
	i = cookiec;

	/*
	 * Start filling in frames with SGE's.  If we
	 * reach the end of frame and still have SGE's
	 * to fill we need to add a chain element and
	 * use another frame.  j will be our counter
	 * for what cookie we are at and i will be
	 * the total cookiec. k is the current frame
	 */
	for (k = 1; k <= frames; k++) {
		for (l = 1; (l <= (sgemax + 1)) && (j <= i); j++, l++) {

			/*
			 * If we have reached the end of frame
			 * and we have more SGE's to fill in
			 * we have to fill the final entry
			 * with a chain element and then
			 * continue to the next frame
			 */
			if ((l == (sgemax + 1)) && (k != frames)) {
				sgechain = (pMpi2SGEChain64_t)sge;
				j--;
				chainflags = (
				    MPI2_SGE_FLAGS_CHAIN_ELEMENT |
				    MPI2_SGE_FLAGS_SYSTEM_ADDRESS |
				    MPI2_SGE_FLAGS_64_BIT_ADDRESSING);
				ddi_put8(p->m_acc_hdl,
				    &sgechain->Flags, chainflags);
				/*
				 * k is the frame counter and (k + 1)
				 * is the number of the next frame.
				 * Note that frames are in contiguous
				 * memory space.
				 */
				nframe_phys_addr = p->m_phys_addr +
				    (mpt->m_req_frame_size * k);
				ddi_put32(p->m_acc_hdl,
				    &sgechain->Address.Low,
				    nframe_phys_addr&0xffffffffull);
				ddi_put32(p->m_acc_hdl,
				    &sgechain->Address.High,
				    nframe_phys_addr>>32);

				/*
				 * If there are more than 2 frames left
				 * we have to next chain offset to
				 * the location of the chain element
				 * in the next frame and fill in the
				 * length of the next chain
				 */
				if ((frames - k) >= 2) {
					ddi_put8(p->m_acc_hdl,
					    &sgechain->NextChainOffset,
					    (sgemax *
					    sizeof (MPI2_SGE_SIMPLE64))
					    >> 2);
					ddi_put16(p->m_acc_hdl,
					    &sgechain->Length,
					    mpt->m_req_frame_size /
					    sizeof (MPI2_SGE_SIMPLE64) *
					    sizeof (MPI2_SGE_SIMPLE64));
				} else {
					/*
					 * This is the last frame. Set
					 * the NextChainOffset to 0 and
					 * Length is the total size of
					 * all remaining simple elements
					 */
					ddi_put8(p->m_acc_hdl,
					    &sgechain->NextChainOffset,
					    0);
					ddi_put16(p->m_acc_hdl,
					    &sgechain->Length,
					    (cookiec - j) *
					    sizeof (MPI2_SGE_SIMPLE64));
				}

				/* Jump to the next frame */
				sge = (pMpi2SGESimple64_t)
				    ((char *)p->m_frames_addr +
				    (int)mpt->m_req_frame_size * k);

				continue;
			}

			ddi_put32(p->m_acc_hdl,
			    &sge->Address.Low,
			    dmap->addr.address64.Low);
			ddi_put32(p->m_acc_hdl,
			    &sge->Address.High,
			    dmap->addr.address64.High);
			ddi_put32(p->m_acc_hdl,
			    &sge->FlagsLength, dmap->count);
			flags = ddi_get32(p->m_acc_hdl,
			    &sge->FlagsLength);
			flags |= ((uint32_t)(
			    MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
			    MPI2_SGE_FLAGS_SYSTEM_ADDRESS |
			    MPI2_SGE_FLAGS_64_BIT_ADDRESSING) <<
			    MPI2_SGE_FLAGS_SHIFT);

			/*
			 * If we are at the end of the frame and
			 * there is another frame to fill in
			 * we set the last simple element as last
			 * element
			 */
			if ((l == sgemax) && (k != frames)) {
				flags |= ((uint32_t)
				    (MPI2_SGE_FLAGS_LAST_ELEMENT) <<
				    MPI2_SGE_FLAGS_SHIFT);
			}

			/*
			 * If this is the final cookie we
			 * indicate it by setting the flags
			 */
			if (j == i) {
				flags |= ((uint32_t)
				    (MPI2_SGE_FLAGS_LAST_ELEMENT |
				    MPI2_SGE_FLAGS_END_OF_BUFFER |
				    MPI2_SGE_FLAGS_END_OF_LIST) <<
				    MPI2_SGE_FLAGS_SHIFT);
			}
			if (cmd->cmd_flags & CFLAG_DMASEND) {
				flags |=
				    (MPI2_SGE_FLAGS_HOST_TO_IOC <<
				    MPI2_SGE_FLAGS_SHIFT);
			} else {
				flags |=
				    (MPI2_SGE_FLAGS_IOC_TO_HOST <<
				    MPI2_SGE_FLAGS_SHIFT);
			}
			ddi_put32(p->m_acc_hdl,
			    &sge->FlagsLength, flags);
			dmap++;
			sge++;
		}
	}

	/*
	 * Sync DMA with the chain buffers that were just created
	 */
	(void) ddi_dma_sync(p->m_dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);
}

static void
mptsas_ieee_sge_mainframe(mptsas_cmd_t *cmd, pMpi2SCSIIORequest_t frame,
    ddi_acc_handle_t acc_hdl, uint_t cookiec,
    uint8_t end_flag)
{
	pMpi2IeeeSgeSimple64_t	ieeesge;
	mptti_t			*dmap;
	uint8_t			flags;

	dmap = cmd->cmd_sg;

	NDBG1(("mptsas_ieee_sge_mainframe: cookiec=%d, %s", cookiec,
	    cmd->cmd_flags & CFLAG_DMASEND?"Out":"In"));

	ieeesge = (pMpi2IeeeSgeSimple64_t)(&frame->SGL);
	while (cookiec--) {
		ddi_put32(acc_hdl, &ieeesge->Address.Low,
		    dmap->addr.address64.Low);
		ddi_put32(acc_hdl, &ieeesge->Address.High,
		    dmap->addr.address64.High);
		ddi_put32(acc_hdl, &ieeesge->Length, dmap->count);
		NDBG1(("mptsas_ieee_sge_mainframe: len=%d, high=0x%x",
		    dmap->count, dmap->addr.address64.High));
		flags = (MPI2_IEEE_SGE_FLAGS_SIMPLE_ELEMENT |
		    MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR);

		/*
		 * If this is the last cookie, we set the flags
		 * to indicate so
		 */
		if (cookiec == 0) {
			flags |= end_flag;
		}

		/*
		 * There are no flags in the IEEE SGE to indicate
		 * direction.
		 */
		ddi_put8(acc_hdl, &ieeesge->Flags, flags);
		dmap++;
		ieeesge++;
	}
}

static void
mptsas_ieee_sge_chain(mptsas_t *mpt, mptsas_cmd_t *cmd,
    pMpi2SCSIIORequest_t frame, ddi_acc_handle_t acc_hdl)
{
	pMpi2IeeeSgeSimple64_t	ieeesge;
	pMpi25IeeeSgeChain64_t	ieeesgechain;
	uint64_t		nframe_phys_addr;
	uint_t			cookiec;
	mptti_t			*dmap;
	uint8_t			flags;
	int			i, j, k, l, frames, sgemax;
	int			temp, maxframe_sges;
	uint8_t			chainflags;
	uint32_t		chainlength;
	mptsas_cache_frames_t	*p;

	cookiec = cmd->cmd_cookiec;

	NDBG1(("mptsas_ieee_sge_chain: cookiec=%d", cookiec));

	/*
	 * Hereby we start to deal with multiple frames.
	 * The process is as follows:
	 * 1. Determine how many frames are needed for SGL element
	 *    storage; Note that all frames are stored in contiguous
	 *    memory space and in 64-bit DMA mode each element is
	 *    4 double-words (16 bytes) long.
	 * 2. Fill up the main frame. We need to do this separately
	 *    since it contains the SCSI IO request header and needs
	 *    dedicated processing. Note that the last 4 double-words
	 *    of the SCSI IO header is for SGL element storage
	 *    (MPI2_SGE_IO_UNION).
	 * 3. Fill the chain element in the main frame, so the DMA
	 *    engine can use the following frames.
	 * 4. Enter a loop to fill the remaining frames. Note that the
	 *    last frame contains no chain element.  The remaining
	 *    frames go into the mpt SGL buffer allocated on the fly,
	 *    not immediately following the main message frame, as in
	 *    Gen1.
	 * Some restrictions:
	 * 1. For 64-bit DMA, the simple element and chain element
	 *    are both of 4 double-words (16 bytes) in size, even
	 *    though all frames are stored in the first 4G of mem
	 *    range and the higher 32-bits of the address are always 0.
	 * 2. On some controllers (like the 1064/1068), a frame can
	 *    hold SGL elements with the last 1 or 2 double-words
	 *    (4 or 8 bytes) un-used. On these controllers, we should
	 *    recognize that there's not enough room for another SGL
	 *    element and move the sge pointer to the next frame.
	 */

	/*
	 * Sgemax is the number of SGE's that will fit
	 * each extra frame and frames is total
	 * number of frames we'll need.  1 sge entry per
	 * frame is reseverd for the chain element thus the -1 below.
	 */
	sgemax = ((mpt->m_req_frame_size / sizeof (MPI2_IEEE_SGE_SIMPLE64))
	    - 1);
	maxframe_sges = MPTSAS_MAX_FRAME_SGES64(mpt);
	temp = (cookiec - (maxframe_sges - 1)) / sgemax;

	/*
	 * A little check to see if we need to round up the number
	 * of frames we need
	 */
	if ((cookiec - (maxframe_sges - 1)) - (temp * sgemax) > 1) {
		frames = (temp + 1);
	} else {
		frames = temp;
	}
	NDBG1(("mptsas_ieee_sge_chain: temp=%d, frames=%d", temp, frames));
	dmap = cmd->cmd_sg;
	ieeesge = (pMpi2IeeeSgeSimple64_t)(&frame->SGL);

	/*
	 * First fill in the main frame
	 */
	j = maxframe_sges - 1;
	mptsas_ieee_sge_mainframe(cmd, frame, acc_hdl, j, 0);
	dmap += j;
	ieeesge += j;
	j++;

	/*
	 * Fill in the chain element in the main frame.
	 * About calculation on ChainOffset:
	 * 1. Struct msg_scsi_io_request has 4 double-words (16 bytes)
	 *    in the end reserved for SGL element storage
	 *    (MPI2_SGE_IO_UNION); we should count it in our
	 *    calculation.  See its definition in the header file.
	 * 2. Constant j is the counter of the current SGL element
	 *    that will be processed, and (j - 1) is the number of
	 *    SGL elements that have been processed (stored in the
	 *    main frame).
	 * 3. ChainOffset value should be in units of quad-words (16
	 *    bytes) so the last value should be divided by 16.
	 */
	ddi_put8(acc_hdl, &frame->ChainOffset,
	    (sizeof (MPI2_SCSI_IO_REQUEST) -
	    sizeof (MPI2_SGE_IO_UNION) +
	    (j - 1) * sizeof (MPI2_IEEE_SGE_SIMPLE64)) >> 4);
	ieeesgechain = (pMpi25IeeeSgeChain64_t)ieeesge;
	chainflags = (MPI2_IEEE_SGE_FLAGS_CHAIN_ELEMENT |
	    MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR);
	ddi_put8(acc_hdl, &ieeesgechain->Flags, chainflags);

	/*
	 * The size of the next frame is the accurate size of space
	 * (in bytes) used to store the SGL elements. j is the counter
	 * of SGL elements. (j - 1) is the number of SGL elements that
	 * have been processed (stored in frames).
	 */
	if (frames >= 2) {
		chainlength = mpt->m_req_frame_size /
		    sizeof (MPI2_IEEE_SGE_SIMPLE64) *
		    sizeof (MPI2_IEEE_SGE_SIMPLE64);
	} else {
		chainlength = ((cookiec - (j - 1)) *
		    sizeof (MPI2_IEEE_SGE_SIMPLE64));
	}

	p = cmd->cmd_extra_frames;

	ddi_put32(acc_hdl, &ieeesgechain->Length, chainlength);
	ddi_put32(acc_hdl, &ieeesgechain->Address.Low,
	    p->m_phys_addr&0xffffffffull);
	ddi_put32(acc_hdl, &ieeesgechain->Address.High, p->m_phys_addr>>32);

	/*
	 * If there are more than 2 frames left we have to
	 * fill in the next chain offset to the location of
	 * the chain element in the next frame.
	 * sgemax is the number of simple elements in an extra
	 * frame. Note that the value NextChainOffset should be
	 * in double-words (4 bytes).
	 */
	if (frames >= 2) {
		ddi_put8(acc_hdl, &ieeesgechain->NextChainOffset,
		    (sgemax * sizeof (MPI2_IEEE_SGE_SIMPLE64)) >> 4);
	} else {
		ddi_put8(acc_hdl, &ieeesgechain->NextChainOffset, 0);
	}

	/*
	 * Jump to next frame;
	 * Starting here, chain buffers go into the per command SGL.
	 * This buffer is allocated when chain buffers are needed.
	 */
	ieeesge = (pMpi2IeeeSgeSimple64_t)p->m_frames_addr;
	i = cookiec;

	/*
	 * Start filling in frames with SGE's.  If we
	 * reach the end of frame and still have SGE's
	 * to fill we need to add a chain element and
	 * use another frame.  j will be our counter
	 * for what cookie we are at and i will be
	 * the total cookiec. k is the current frame
	 */
	for (k = 1; k <= frames; k++) {
		for (l = 1; (l <= (sgemax + 1)) && (j <= i); j++, l++) {

			/*
			 * If we have reached the end of frame
			 * and we have more SGE's to fill in
			 * we have to fill the final entry
			 * with a chain element and then
			 * continue to the next frame
			 */
			if ((l == (sgemax + 1)) && (k != frames)) {
				ieeesgechain = (pMpi25IeeeSgeChain64_t)ieeesge;
				j--;
				chainflags =
				    MPI2_IEEE_SGE_FLAGS_CHAIN_ELEMENT |
				    MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR;
				ddi_put8(p->m_acc_hdl,
				    &ieeesgechain->Flags, chainflags);
				/*
				 * k is the frame counter and (k + 1)
				 * is the number of the next frame.
				 * Note that frames are in contiguous
				 * memory space.
				 */
				nframe_phys_addr = p->m_phys_addr +
				    (mpt->m_req_frame_size * k);
				ddi_put32(p->m_acc_hdl,
				    &ieeesgechain->Address.Low,
				    nframe_phys_addr&0xffffffffull);
				ddi_put32(p->m_acc_hdl,
				    &ieeesgechain->Address.High,
				    nframe_phys_addr>>32);

				/*
				 * If there are more than 2 frames left
				 * we have to next chain offset to
				 * the location of the chain element
				 * in the next frame and fill in the
				 * length of the next chain
				 */
				if ((frames - k) >= 2) {
					ddi_put8(p->m_acc_hdl,
					    &ieeesgechain->NextChainOffset,
					    (sgemax *
					    sizeof (MPI2_IEEE_SGE_SIMPLE64))
					    >> 4);
					ddi_put32(p->m_acc_hdl,
					    &ieeesgechain->Length,
					    mpt->m_req_frame_size /
					    sizeof (MPI2_IEEE_SGE_SIMPLE64) *
					    sizeof (MPI2_IEEE_SGE_SIMPLE64));
				} else {
					/*
					 * This is the last frame. Set
					 * the NextChainOffset to 0 and
					 * Length is the total size of
					 * all remaining simple elements
					 */
					ddi_put8(p->m_acc_hdl,
					    &ieeesgechain->NextChainOffset,
					    0);
					ddi_put32(p->m_acc_hdl,
					    &ieeesgechain->Length,
					    (cookiec - j) *
					    sizeof (MPI2_IEEE_SGE_SIMPLE64));
				}

				/* Jump to the next frame */
				ieeesge = (pMpi2IeeeSgeSimple64_t)
				    ((char *)p->m_frames_addr +
				    (int)mpt->m_req_frame_size * k);

				continue;
			}

			ddi_put32(p->m_acc_hdl,
			    &ieeesge->Address.Low,
			    dmap->addr.address64.Low);
			ddi_put32(p->m_acc_hdl,
			    &ieeesge->Address.High,
			    dmap->addr.address64.High);
			ddi_put32(p->m_acc_hdl,
			    &ieeesge->Length, dmap->count);
			flags = (MPI2_IEEE_SGE_FLAGS_SIMPLE_ELEMENT |
			    MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR);

			/*
			 * If we are at the end of the frame and
			 * there is another frame to fill in
			 * do we need to do anything?
			 * if ((l == sgemax) && (k != frames)) {
			 * }
			 */

			/*
			 * If this is the final cookie set end of list.
			 */
			if (j == i) {
				flags |= MPI25_IEEE_SGE_FLAGS_END_OF_LIST;
			}

			ddi_put8(p->m_acc_hdl, &ieeesge->Flags, flags);
			dmap++;
			ieeesge++;
		}
	}

	/*
	 * Sync DMA with the chain buffers that were just created
	 */
	(void) ddi_dma_sync(p->m_dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);
}

static void
mptsas_sge_setup(mptsas_t *mpt, mptsas_cmd_t *cmd, uint32_t *control,
    pMpi2SCSIIORequest_t frame, ddi_acc_handle_t acc_hdl)
{
	ASSERT(cmd->cmd_flags & CFLAG_DMAVALID);

	NDBG1(("%d: sge_setup: cookiec=%d", mpt->m_instance,
	    cmd->cmd_cookiec));

	/*
	 * Set read/write bit in control.
	 */
	if (cmd->cmd_flags & CFLAG_DMASEND) {
		*control |= MPI2_SCSIIO_CONTROL_WRITE;
	} else {
		*control |= MPI2_SCSIIO_CONTROL_READ;
	}

	ddi_put32(acc_hdl, &frame->DataLength, cmd->cmd_dmacount);

	/*
	 * We have 4 cases here.  First where we can fit all the
	 * SG elements into the main frame, and the case
	 * where we can't. The SG element is also different when using
	 * MPI2.5 interface.
	 * If we have more cookies than we can attach to a frame
	 * we will need to use a chain element to point
	 * a location of memory where the rest of the S/G
	 * elements reside.
	 */
	if (cmd->cmd_cookiec <= MPTSAS_MAX_FRAME_SGES64(mpt)) {
		if (mpt->m_MPI25) {
			mptsas_ieee_sge_mainframe(cmd, frame, acc_hdl,
			    cmd->cmd_cookiec,
			    MPI25_IEEE_SGE_FLAGS_END_OF_LIST);
		} else {
			mptsas_sge_mainframe(cmd, frame, acc_hdl,
			    cmd->cmd_cookiec,
			    ((uint32_t)(MPI2_SGE_FLAGS_LAST_ELEMENT
			    | MPI2_SGE_FLAGS_END_OF_BUFFER
			    | MPI2_SGE_FLAGS_END_OF_LIST) <<
			    MPI2_SGE_FLAGS_SHIFT));
		}
	} else {
		if (mpt->m_MPI25) {
			mptsas_ieee_sge_chain(mpt, cmd, frame, acc_hdl);
		} else {
			mptsas_sge_chain(mpt, cmd, frame, acc_hdl);
		}
	}
}

/*
 * Interrupt handling
 * Utility routine.  Poll for status of a command sent to HBA
 * without interrupts (a FLAG_NOINTR command).
 */
int
mptsas_poll(mptsas_t *mpt, mptsas_cmd_t *poll_cmd, int polltime)
{
	int		rval = TRUE;
	uint32_t	int_mask;

	NDBG5(("%d: poll: cmd=0x%p, flags 0x%x", mpt->m_instance,
	    (void *)poll_cmd, poll_cmd->cmd_flags));

	/*
	 * Get the current interrupt mask and disable interrupts.  When
	 * re-enabling ints, set mask to saved value.
	 */
	int_mask = ddi_get32(mpt->m_datap, &mpt->m_reg->HostInterruptMask);
	MPTSAS_DISABLE_INTR(mpt);

	mpt->m_polled_intr = 1;

	if ((poll_cmd->cmd_flags & CFLAG_TM_CMD) == 0) {
		mptsas_restart_hba(mpt);
	}

	/*
	 * Wait, using drv_usecwait(), long enough for the command to
	 * reasonably return from the target if the target isn't
	 * "dead".  A polled command may well be sent from scsi_poll, and
	 * there are retries built in to scsi_poll if the transport
	 * accepted the packet (TRAN_ACCEPT).  scsi_poll waits 1 second
	 * and retries the transport up to scsi_poll_busycnt times
	 * (currently 60) if
	 * 1. pkt_reason is CMD_INCOMPLETE and pkt_state is 0, or
	 * 2. pkt_reason is CMD_CMPLT and *pkt_scbp has STATUS_BUSY
	 *
	 * limit the waiting to avoid a hang in the event that the
	 * cmd never gets started but we are still receiving interrupts
	 */
	while (!(poll_cmd->cmd_flags & CFLAG_FINISHED)) {
		if (mptsas_wait_intr(mpt, polltime) == FALSE) {
			NDBG5(("%d: poll: command incomplete",
			    mpt->m_instance));
			rval = FALSE;
			break;
		}
	}

	if (rval == FALSE) {

		/*
		 * this isn't supposed to happen, the hba must be wedged
		 * Mark this cmd as a timeout.
		 */
		mptsas_set_pkt_reason(mpt, poll_cmd, CMD_TIMEOUT,
		    (STAT_TIMEOUT|STAT_ABORTED));

		if (poll_cmd->cmd_queued == CQ_NOTQUEUED) {

			NDBG5(("%d: poll: not on waitq",
			    mpt->m_instance));

			poll_cmd->cmd_pkt->pkt_state |=
			    (STATE_GOT_BUS|STATE_GOT_TARGET|STATE_SENT_CMD);
		} else if (poll_cmd->cmd_queued == CQ_MAIN) {

			/* find and remove it from the waitq */
			NDBG5(("%d: poll: delete from waitq",
			    mpt->m_instance));
			mptsas_waitq_delete(mpt, poll_cmd);
		} else {
			ASSERT(poll_cmd->cmd_queued == CQ_TARGET);
			NDBG5(("%d: poll: delete from target %d waitq",
			    mpt->m_instance, poll_cmd->cmd_tgt_addr->m_devhdl));
			mutex_enter(&poll_cmd->cmd_tgt_addr->m_t_mutex);
			mptsas_targwaitq_delete(mpt, poll_cmd->cmd_tgt_addr,
			    poll_cmd);
			mutex_exit(&poll_cmd->cmd_tgt_addr->m_t_mutex);
		}
	}

	mptsas_fma_check(mpt, poll_cmd);

	/*
	 * Clear polling flag, re-enable interrupts.
	 */
	mpt->m_polled_intr = 0;
	ddi_put32(mpt->m_datap, &mpt->m_reg->HostInterruptMask, int_mask);

	/*
	 * If there are queued cmd, start them now.
	 */
	if (mpt->m_wait.cl_len != 0 || mpt->m_ntwait != 0) {
		mptsas_restart_waitq(mpt);
	}

	NDBG5(("%d: poll: done", mpt->m_instance));
	return (rval);
}

/*
 * Used for polling cmds and TM function
 */
static int
mptsas_wait_intr(mptsas_t *mpt, int polltime)
{
	int				cnt, rval = FALSE;
	pMpi2ReplyDescriptorsUnion_t	reply_desc_union;
	mptsas_reply_pqueue_t		*rpqp;

	NDBG5(("%d: wait_intr", mpt->m_instance));
	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Keep polling for at least (polltime * 1000) seconds
	 */
	rpqp = mpt->m_rep_post_queues;

	/*
	 * Drop the main mutex and grab the mutex for reply queue 0
	 */
	mutex_exit(&mpt->m_mutex);
	mutex_enter(&rpqp->rpq_mutex);
	for (cnt = 0; cnt < polltime; cnt++) {
		(void) ddi_dma_sync(mpt->m_dma_post_queue_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);

		/*
		 * Polled requests should only come back through
		 * the first interrupt.
		 */
		reply_desc_union = (pMpi2ReplyDescriptorsUnion_t)
		    MPTSAS_GET_NEXT_REPLY(rpqp, rpqp->rpq_index);

		if (ddi_get32(mpt->m_acc_post_queue_hdl,
		    &reply_desc_union->Words.Low) == 0xFFFFFFFF ||
		    ddi_get32(mpt->m_acc_post_queue_hdl,
		    &reply_desc_union->Words.High) == 0xFFFFFFFF) {
			drv_usecwait(1000);
			continue;
		}

		/*
		 * The reply is valid, process it according to its
		 * type.
		 */
		mptsas_process_intr(mpt, rpqp, reply_desc_union);

		/*
		 * Clear the reply descriptor for re-use.
		 */
		ddi_put64(mpt->m_acc_post_queue_hdl,
		    &((uint64_t *)(void *)rpqp->rpq_queue)[rpqp->rpq_index],
		    0xFFFFFFFFFFFFFFFF);
		(void) ddi_dma_sync(mpt->m_dma_post_queue_hdl, 0, 0,
		    DDI_DMA_SYNC_FORDEV);

		if (++rpqp->rpq_index == mpt->m_post_queue_depth) {
			rpqp->rpq_index = 0;
		}

		/*
		 * Update the reply index
		 */
		ddi_put32(mpt->m_datap,
		    &mpt->m_reg->ReplyPostHostIndex, rpqp->rpq_index);
		rval = TRUE;
		break;
	}

	mutex_exit(&rpqp->rpq_mutex);
	mutex_enter(&mpt->m_mutex);

	return (rval);
}

static void
mptsas_handle_scsi_io_success(mptsas_t *mpt,
    mptsas_reply_pqueue_t *rpqp,
    pMpi2ReplyDescriptorsUnion_t reply_desc)
{
	pMpi2SCSIIOSuccessReplyDescriptor_t	scsi_io_success;
	uint16_t				SMID;
	mptsas_slots_t				*slots = mpt->m_active;
	mptsas_cmd_t				*cmd = NULL;
	struct scsi_pkt				*pkt;
#ifdef MPTSAS_TEST
	boolean_t				testing_timeout = B_FALSE;
#endif

	scsi_io_success = (pMpi2SCSIIOSuccessReplyDescriptor_t)reply_desc;
	SMID = ddi_get16(mpt->m_acc_post_queue_hdl, &scsi_io_success->SMID);

	/*
	 * This is a success reply so just complete the IO.  First, do a sanity
	 * check on the SMID.  The final slot is used for TM requests, which
	 * would not come into this reply handler.
	 */
	if ((SMID == 0) || (SMID > slots->m_n_normal)) {
		mptsas_log(mpt, CE_WARN, "?Received invalid SMID of %d\n",
		    SMID);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		return;
	}

#ifdef MPTSAS_TEST
	if (mptsas_test_timeout & (1<<mpt->m_instance)) {
		uint16_t	targ;

		targ = (uint16_t)(mptsas_test_timeout>>16);

		/*
		 * If we are testing we don't want to clear the slot otherwise
		 * the flush code will not find the command in the slot array.
		 */
		cmd = slots->m_slot[SMID];
		/* targ == 0 means any target */
		if (targ == 0 || (cmd != NULL && cmd->cmd_tgt_addr != NULL &&
		    cmd->cmd_tgt_addr->m_devhdl == targ)) {
			mptsas_test_timeout = 0;
			testing_timeout = B_TRUE;
		} else {
			cmd = mptsas_secure_cmd_from_slots(slots, SMID);
		}
	} else {
		cmd = mptsas_secure_cmd_from_slots(slots, SMID);
	}
#else
	cmd = mptsas_secure_cmd_from_slots(slots, SMID);
#endif

	/*
	 * If we flushed the target but things were still happening on
	 * the HBA it's quite possible to get an interrupt for a slot
	 * that's no longer associated with a command (NULL).
	 * In that case no need to do anything.
	 */
	if (cmd == NULL) {
		NDBG18(("%d: NULL command for successful SCSI IO in slot %d",
		    mpt->m_instance, SMID));
		atomic_inc_32(&mpt->m_failed_cmd_slot_secures);
		return;
	}
	ASSERT(cmd->cmd_rpqidx == rpqp->rpq_num);
	ASSERT((cmd->cmd_flags & CFLAG_TM_CMD) == 0);

	pkt = CMD2PKT(cmd);
	ASSERT(pkt->pkt_start != 0);
	pkt->pkt_stop = gethrtime();
	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_GOT_STATUS);
	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		pkt->pkt_state |= STATE_XFERRED_DATA;
	}
	pkt->pkt_resid = 0;

	if (cmd->cmd_flags & CFLAG_CMDIOC) {
		mutex_enter(&mpt->m_mutex);
		if (cmd->cmd_flags & CFLAG_PASSTHRU) {
			cmd->cmd_flags |= CFLAG_FINISHED;
			cv_broadcast(&mpt->m_passthru_cv);
			mutex_exit(&mpt->m_mutex);
			return;
		}
		mptsas_deref_ioccmd(mpt, cmd);
		mutex_exit(&mpt->m_mutex);
	} else {
#ifdef MPTSAS_TEST
		/*
		 * In order to test timeout for a command set
		 * mptsas_test_timeout via mdb to avoid completion
		 * processing here.
		 */
		if (testing_timeout) {
			return;
		}

		/*
		 * To test retries set mptsas_test_retries via mdb
		 * This should just re-execute the command.
		 */
		if ((mptsas_test_retry & (1<<mpt->m_instance)) && (
		    (mptsas_test_retry & 0xffff0000) == 0 ||
		    cmd->cmd_tgt_addr->m_devhdl ==
		    (uint16_t)(mptsas_test_retry>>16))) {
			mptsas_test_retry = 0;
			/*
			 * Other code paths that call retry_pkt()
			 * already have the m_mutex, so we need to
			 * grab it here too.
			 */
			mutex_enter(&mpt->m_mutex);
			mptsas_retry_pkt(mpt, cmd);
			mutex_exit(&mpt->m_mutex);
		} else {
			mutex_enter(&cmd->cmd_tgt_addr->m_t_mutex);
			mptsas_deref_tgtcmd(mpt, cmd);
			mutex_exit(&cmd->cmd_tgt_addr->m_t_mutex);
		}
#else
		/*
		 * This is the normal path, avoid grabbing
		 * the m_mutex, but we need the per target one.
		 */
		mutex_enter(&cmd->cmd_tgt_addr->m_t_mutex);
		mptsas_deref_tgtcmd(mpt, cmd);
		mutex_exit(&cmd->cmd_tgt_addr->m_t_mutex);
#endif
	}

	if (cmd->cmd_flags & CFLAG_RETRY) {
		/*
		 * The target returned QFULL or busy, do not add this
		 * pkt to the doneq since the hba will retry
		 * this cmd.
		 *
		 * The pkt has already been resubmitted in
		 * mptsas_handle_qfull() or in mptsas_check_scsi_io_error().
		 * Remove this cmd_flag here.
		 */
		cmd->cmd_flags &= ~CFLAG_RETRY;
	} else {
		mptsas_rpdoneq_add(mpt, rpqp, cmd);
	}
}

void
mptsas_return_replyframe(mptsas_t *mpt, uint32_t reply_addr)
{
	/*
	 * Return the reply frame to the free queue.
	 */
	ddi_put32(mpt->m_acc_free_queue_hdl,
	    &((uint32_t *)(void *)mpt->m_free_queue)[mpt->m_free_index],
	    reply_addr);
	(void) ddi_dma_sync(mpt->m_dma_free_queue_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);
	if (++mpt->m_free_index == mpt->m_free_queue_depth) {
		mpt->m_free_index = 0;
	}
	ddi_put32(mpt->m_datap, &mpt->m_reg->ReplyFreeHostIndex,
	    mpt->m_free_index);
}

static void
mptsas_handle_address_reply(mptsas_t *mpt,
    pMpi2ReplyDescriptorsUnion_t reply_desc)
{
	pMpi2AddressReplyDescriptor_t	address_reply;
	pMPI2DefaultReply_t		reply;
	mptsas_fw_diagnostic_buffer_t	*pBuffer;
	uint32_t			reply_addr, reply_frame_dma_baseaddr;
	uint16_t			SMID, iocstatus;
	mptsas_slots_t			*slots = mpt->m_active;
	mptsas_cmd_t			*cmd = NULL;
	uint8_t				function, buffer_type;
	m_replyh_arg_t			*args;
	int				reply_frame_no;

	ASSERT(mutex_owned(&mpt->m_mutex));

	address_reply = (pMpi2AddressReplyDescriptor_t)reply_desc;
	reply_addr = ddi_get32(mpt->m_acc_post_queue_hdl,
	    &address_reply->ReplyFrameAddress);
	SMID = ddi_get16(mpt->m_acc_post_queue_hdl, &address_reply->SMID);

	/*
	 * If reply frame is not in the proper range we should ignore this
	 * message and exit the interrupt handler.
	 */
	reply_frame_dma_baseaddr = mpt->m_reply_frame_dma_addr & 0xfffffffful;
	if ((reply_addr < reply_frame_dma_baseaddr) ||
	    (reply_addr >= (reply_frame_dma_baseaddr +
	    (mpt->m_reply_frame_size * mpt->m_max_replies))) ||
	    ((reply_addr - reply_frame_dma_baseaddr) %
	    mpt->m_reply_frame_size != 0)) {
		mptsas_log(mpt, CE_WARN, "?Received invalid reply frame "
		    "address 0x%x\n", reply_addr);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		return;
	}

	(void) ddi_dma_sync(mpt->m_dma_reply_frame_hdl, 0, 0,
	    DDI_DMA_SYNC_FORCPU);
	reply = (pMPI2DefaultReply_t)(mpt->m_reply_frame + (reply_addr -
	    reply_frame_dma_baseaddr));
	function = ddi_get8(mpt->m_acc_reply_frame_hdl, &reply->Function);

	NDBG31(("%d: handle_address_reply: function 0x%x, "
	    "reply_addr=0x%x", mpt->m_instance, function, reply_addr));

	/*
	 * don't get slot information and command for events since these values
	 * don't exist
	 */
	if ((function != MPI2_FUNCTION_EVENT_NOTIFICATION) &&
	    (function != MPI2_FUNCTION_DIAG_BUFFER_POST)) {
		/*
		 * This could be a TM reply, which use the last allocated SMID,
		 * so allow for that.
		 */
		if ((SMID == 0) || (SMID > (slots->m_n_normal + 1))) {
			mptsas_log(mpt, CE_WARN, "?Received invalid SMID of "
			    "%d\n", SMID);
			ddi_fm_service_impact(mpt->m_dip,
			    DDI_SERVICE_UNAFFECTED);
			return;
		}

		cmd = mptsas_secure_cmd_from_slots(slots, SMID);

		/*
		 * Print warning and return if the slot is empty.
		 * But will still need to return the frame!
		 */
		if (cmd == NULL) {
			NDBG31(("%d: NULL command for address reply in slot %d",
			    mpt->m_instance, SMID));
			atomic_inc_32(&mpt->m_failed_cmd_slot_secures);
			mptsas_return_replyframe(mpt, reply_addr);
			return;
		}
		cmd->cmd_arfunc = function;
		if ((cmd->cmd_flags &
		    (CFLAG_PASSTHRU | CFLAG_CONFIG | CFLAG_FW_DIAG))) {
			cmd->cmd_rfm = reply_addr;
			cmd->cmd_flags |= CFLAG_FINISHED;
			if (cmd->cmd_flags & CFLAG_PASSTHRU)
				cv_broadcast(&mpt->m_passthru_cv);
			if (cmd->cmd_flags & CFLAG_CONFIG)
				cv_broadcast(&mpt->m_config_cv);
			if (cmd->cmd_flags & CFLAG_FW_DIAG)
				cv_broadcast(&mpt->m_fw_diag_cv);
			return;
		} else {
			mptsas_deref_cmd(mpt, cmd);
		}
		NDBG31(("%d: handle_address_reply: slot=%d",
		    mpt->m_instance, SMID));
	}

	/*
	 * Depending on the function, we need to handle
	 * the reply frame (and cmd) differently.
	 */
	switch (function) {
	case MPI2_FUNCTION_SCSI_IO_REQUEST:
		mptsas_check_scsi_io_error(mpt, (pMpi2SCSIIOReply_t)reply, cmd);
		break;
	case MPI2_FUNCTION_SCSI_TASK_MGMT:
		cmd->cmd_rfm = reply_addr;
		mptsas_check_task_mgt(mpt, (pMpi2SCSIManagementReply_t)reply,
		    cmd);
		cmd->cmd_flags |= CFLAG_FINISHED;
		mptsas_cmplt_task_management(mpt);
		return;
	case MPI2_FUNCTION_FW_DOWNLOAD:
		cmd->cmd_flags |= CFLAG_FINISHED;
		cv_broadcast(&mpt->m_fw_cv);
		break;
	case MPI2_FUNCTION_EVENT_NOTIFICATION:
		reply_frame_no = (reply_addr - reply_frame_dma_baseaddr) /
		    mpt->m_reply_frame_size;
		args = &mpt->m_replyh_args[reply_frame_no];
		ASSERT(args->mpt == NULL);
		args->mpt = (void *)mpt;
		args->rfm = reply_addr;

		/*
		 * Record the event if its type is enabled in
		 * this mpt instance by ioctl.
		 */
		mptsas_record_event(args);

		/*
		 * Handle time critical events
		 * NOT_RESPONDING/ADDED only now
		 */
		if (mptsas_handle_event_sync(args) == DDI_SUCCESS) {
			/*
			 * Would not return main process,
			 * just let taskq resolve ack action
			 * and ack would be sent in taskq thread
			 */
			NDBG20(("%d: send mptsas_handle_event_sync success",
			    mpt->m_instance));
		}

		if (mpt->m_in_reset == TRUE) {
			NDBG20(("%d: dropping event received during reset",
			    mpt->m_instance));
			return;
		}

		if ((ddi_taskq_dispatch(mpt->m_event_taskq, mptsas_handle_event,
		    (void *)args, DDI_NOSLEEP)) != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "No memory available"
			"for dispatch taskq");
			/*
			 * Return the reply frame to the free queue.
			 */
			mptsas_return_replyframe(mpt, reply_addr);
		}
		return;
	case MPI2_FUNCTION_DIAG_BUFFER_POST:
		/*
		 * If SMID is 0, this implies that the reply is due to a
		 * release function with a status that the buffer has been
		 * released.  Set the buffer flags accordingly.
		 */
		if (SMID == 0) {
			iocstatus = ddi_get16(mpt->m_acc_reply_frame_hdl,
			    &reply->IOCStatus);
			buffer_type = ddi_get8(mpt->m_acc_reply_frame_hdl,
			    &(((pMpi2DiagBufferPostReply_t)reply)->BufferType));
			if (iocstatus == MPI2_IOCSTATUS_DIAGNOSTIC_RELEASED) {
				pBuffer =
				    &mpt->m_fw_diag_buffer_list[buffer_type];
				pBuffer->valid_data = TRUE;
				pBuffer->owned_by_firmware = FALSE;
				pBuffer->immediate = FALSE;
			}
		} else {
			/*
			 * Normal handling of diag post reply with SMID.
			 */
			cmd = mptsas_secure_cmd_from_slots(slots, SMID);

			/*
			 * print warning and return if the slot is empty
			 */
			if (cmd == NULL) {
				mptsas_log(mpt, CE_NOTE, "NULL command for "
				    "address reply in slot %d", SMID);
				atomic_inc_32(&mpt->m_failed_cmd_slot_secures);
				mptsas_return_replyframe(mpt, reply_addr);
				return;
			}
			cmd->cmd_rfm = reply_addr;
			cmd->cmd_flags |= CFLAG_FINISHED;
			cv_broadcast(&mpt->m_fw_diag_cv);
		}
		return;
	default:
		mptsas_log(mpt, CE_WARN, "Unknown function 0x%x ", function);
		break;
	}

	mptsas_return_replyframe(mpt, reply_addr);

	if (cmd->cmd_flags & CFLAG_FW_CMD)
		return;

	if (cmd->cmd_flags & CFLAG_RETRY) {
		/*
		 * The target returned QFULL or busy, do not add this
		 * pkt to the doneq since the hba will retry
		 * this cmd.
		 *
		 * The pkt has already been resubmitted in
		 * mptsas_handle_qfull() or in mptsas_check_scsi_io_error().
		 * Remove this cmd_flag here.
		 */
		cmd->cmd_flags &= ~CFLAG_RETRY;
	} else {
		mptsas_doneq_add(mpt, cmd);
	}
}

#ifdef MPTSAS_DEBUG
static uint8_t mptsas_last_sense[256];
#endif

static void
mptsas_check_scsi_io_error(mptsas_t *mpt, pMpi2SCSIIOReply_t reply,
    mptsas_cmd_t *cmd)
{
	uint8_t			scsi_status, scsi_state;
	uint16_t		ioc_status, cmd_rqs_len;
	uint32_t		xferred, sensecount, responsedata, loginfo = 0;
	struct scsi_pkt		*pkt;
	struct scsi_arq_status	*arqstat;
	mptsas_target_t		*ptgt = cmd->cmd_tgt_addr;
	uint8_t			*sensedata = NULL;
	uint64_t		sas_wwn;
	uint8_t			phy;
	char			wwn_str[MPTSAS_WWN_STRLEN];

	scsi_status = ddi_get8(mpt->m_acc_reply_frame_hdl, &reply->SCSIStatus);
	ioc_status = ddi_get16(mpt->m_acc_reply_frame_hdl, &reply->IOCStatus);
	scsi_state = ddi_get8(mpt->m_acc_reply_frame_hdl, &reply->SCSIState);
	xferred = ddi_get32(mpt->m_acc_reply_frame_hdl, &reply->TransferCount);
	sensecount = ddi_get32(mpt->m_acc_reply_frame_hdl, &reply->SenseCount);
	responsedata = ddi_get32(mpt->m_acc_reply_frame_hdl,
	    &reply->ResponseInfo);

	if (ioc_status & MPI2_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE) {
		sas_wwn = ptgt->m_addr.mta_wwn;
		phy = ptgt->m_phynum;
		if (sas_wwn == 0) {
			(void) sprintf(wwn_str, "p%x", phy);
		} else {
			(void) sprintf(wwn_str, "w%016"PRIx64, sas_wwn);
		}
		loginfo = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCLogInfo);
		mptsas_log(mpt, CE_NOTE,
		    "?Log info 0x%x received for target %d %s.\n"
		    "\tscsi_status=0x%x, ioc_status=0x%x, scsi_state=0x%x",
		    loginfo, Tgt(cmd), wwn_str, scsi_status, ioc_status,
		    scsi_state);
	}

	NDBG31(("\t\tsas-wwn=0x%016"PRIx64", bay-no=%d, phy-num=0x%x",
	    ptgt->m_addr.mta_wwn, ptgt->m_slot_num, ptgt->m_phynum));
	NDBG31(("\t\tscsi_status=0x%x, ioc_status=0x%x, scsi_state=0x%x",
	    scsi_status, ioc_status, scsi_state));

	pkt = CMD2PKT(cmd);
	ASSERT(pkt->pkt_start != 0);
	pkt->pkt_stop = gethrtime();
	*(pkt->pkt_scbp) = scsi_status;

	if (loginfo == 0x31170000) {
		/*
		 * if loginfo PL_LOGINFO_CODE_IO_DEVICE_MISSING_DELAY_RETRY
		 * 0x31170000 comes, that means the device missing delay
		 * is in progressing, the command need retry later.
		 */
		*(pkt->pkt_scbp) = STATUS_BUSY;
		return;
	}

	if ((scsi_state & MPI2_SCSI_STATE_NO_SCSI_STATUS) &&
	    ((ioc_status & MPI2_IOCSTATUS_MASK) ==
	    MPI2_IOCSTATUS_SCSI_DEVICE_NOT_THERE)) {
		mptsas_set_pkt_reason(mpt, cmd, CMD_INCOMPLETE, STAT_ABORTED);
		pkt->pkt_state |= STATE_GOT_BUS;
		mutex_enter(&ptgt->m_t_mutex);
		if (ptgt->m_reset_delay == 0) {
			mptsas_set_throttle(mpt, ptgt, DRAIN_THROTTLE);
		}
		mutex_exit(&ptgt->m_t_mutex);
		return;
	}

	if (scsi_state & MPI2_SCSI_STATE_RESPONSE_INFO_VALID) {
		responsedata &= 0x000000FF;
		if (responsedata & MPTSAS_SCSI_RESPONSE_CODE_TLR_OFF) {
			mptsas_log(mpt, CE_NOTE, "Do not support the TLR\n");
			mptsas_set_pkt_reason(mpt, cmd, CMD_TLR_OFF,
			    STAT_ABORTED);
			return;
		}
	}


	switch (scsi_status) {
	case MPI2_SCSI_STATUS_CHECK_CONDITION:
		(void) ddi_dma_sync(mpt->m_dma_req_sense_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		pkt->pkt_resid = (cmd->cmd_dmacount - xferred);
		arqstat = (void*)(pkt->pkt_scbp);
		arqstat->sts_rqpkt_status = *((struct scsi_status *)
		    (pkt->pkt_scbp));
		pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS | STATE_ARQ_DONE);
		if (cmd->cmd_flags & CFLAG_XARQ) {
			pkt->pkt_state |= STATE_XARQ_DONE;
		}
		if (pkt->pkt_resid != cmd->cmd_dmacount) {
			pkt->pkt_state |= STATE_XFERRED_DATA;
		}
		arqstat->sts_rqpkt_reason = pkt->pkt_reason;
		arqstat->sts_rqpkt_state  = pkt->pkt_state;
		arqstat->sts_rqpkt_state |= STATE_XFERRED_DATA;
		arqstat->sts_rqpkt_statistics = pkt->pkt_statistics;
		sensedata = (uint8_t *)&arqstat->sts_sensedata;
		if (cmd->cmd_extrqslen != 0) {
			cmd_rqs_len = cmd->cmd_extrqslen;
		} else {
			cmd_rqs_len = cmd->cmd_rqslen;
		}
		(void) ddi_dma_sync(mpt->m_dma_req_sense_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
#ifdef MPTSAS_DEBUG
		bcopy((uchar_t *)cmd->cmd_arq_buf, mptsas_last_sense,
		    ((cmd_rqs_len >= sizeof (mptsas_last_sense)) ?
		    sizeof (mptsas_last_sense):cmd_rqs_len));
#endif
		bcopy((uchar_t *)cmd->cmd_arq_buf, sensedata,
		    ((cmd_rqs_len >= sensecount) ? sensecount :
		    cmd_rqs_len));
		arqstat->sts_rqpkt_resid = (cmd_rqs_len - sensecount);
		cmd->cmd_flags |= CFLAG_CMDARQ;
		/*
		 * Set proper status for pkt if autosense was valid
		 */
		if (scsi_state & MPI2_SCSI_STATE_AUTOSENSE_VALID) {
			struct scsi_status zero_status = { 0 };
			arqstat->sts_rqpkt_status = zero_status;
		}

		/*
		 * ASC=0x47 is parity error
		 * ASC=0x48 is initiator detected error received
		 */
		if ((scsi_sense_key(sensedata) == KEY_ABORTED_COMMAND) &&
		    ((scsi_sense_asc(sensedata) == 0x47) ||
		    (scsi_sense_asc(sensedata) == 0x48))) {
			mptsas_log(mpt, CE_NOTE, "Aborted_command!");
		}

		/*
		 * ASC/ASCQ=0x3F/0x0E means report_luns data changed
		 * ASC/ASCQ=0x25/0x00 means invalid lun
		 */
		if (((scsi_sense_key(sensedata) == KEY_UNIT_ATTENTION) &&
		    (scsi_sense_asc(sensedata) == 0x3F) &&
		    (scsi_sense_ascq(sensedata) == 0x0E)) ||
		    ((scsi_sense_key(sensedata) == KEY_ILLEGAL_REQUEST) &&
		    (scsi_sense_asc(sensedata) == 0x25) &&
		    (scsi_sense_ascq(sensedata) == 0x00))) {
			mptsas_dispatch_reconf_tgt(mpt, ptgt, ptgt->m_devhdl,
			    DDI_NOSLEEP, MPTSAS_TOPO_FLAG_LUN_ASSOCIATED);
		}
		break;
	case MPI2_SCSI_STATUS_GOOD:
		switch (ioc_status & MPI2_IOCSTATUS_MASK) {
		case MPI2_IOCSTATUS_SCSI_DEVICE_NOT_THERE:
			mptsas_set_pkt_reason(mpt, cmd, CMD_DEV_GONE,
			    STAT_ABORTED);
			pkt->pkt_state |= STATE_GOT_BUS;
			mutex_enter(&ptgt->m_t_mutex);
			if (ptgt->m_reset_delay == 0) {
				mptsas_set_throttle(mpt, ptgt, DRAIN_THROTTLE);
			}
			mutex_exit(&ptgt->m_t_mutex);
			NDBG31(("%d: lost disk for target%d, command:%x",
			    mpt->m_instance, Tgt(cmd), pkt->pkt_cdbp[0]));
			break;
		case MPI2_IOCSTATUS_SCSI_DATA_OVERRUN:
			NDBG31(("%d: data overrun: xferred=% ddmacount=%d ",
			    mpt->m_instance, xferred, cmd->cmd_dmacount));
			mptsas_set_pkt_reason(mpt, cmd, CMD_DATA_OVR, 0);
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET
			    | STATE_SENT_CMD | STATE_GOT_STATUS
			    | STATE_XFERRED_DATA);
			pkt->pkt_resid = 0;
			break;
		case MPI2_IOCSTATUS_SCSI_RESIDUAL_MISMATCH:
		case MPI2_IOCSTATUS_SCSI_DATA_UNDERRUN:
			NDBG31(("%d: data underrun: xferred=%d dmacount=%d",
			    mpt->m_instance, xferred, cmd->cmd_dmacount));
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET
			    | STATE_SENT_CMD | STATE_GOT_STATUS);
			pkt->pkt_resid = (cmd->cmd_dmacount - xferred);
			if (pkt->pkt_resid != cmd->cmd_dmacount) {
				pkt->pkt_state |= STATE_XFERRED_DATA;
			}
			break;
		case MPI2_IOCSTATUS_SCSI_TASK_TERMINATED:
			if (pkt->pkt_stop - pkt->pkt_start >
			    ((hrtime_t)pkt->pkt_time * (hrtime_t)NANOSEC)) {
				/*
				 * When timeout requested, propagate
				 * proper reason and statistics to
				 * target drivers.
				 */
				mptsas_set_pkt_reason(mpt, cmd, CMD_TIMEOUT,
				    STAT_BUS_RESET | STAT_TIMEOUT);
			} else {
				mptsas_set_pkt_reason(mpt, cmd, CMD_RESET,
				    STAT_BUS_RESET);
			}
			break;
		case MPI2_IOCSTATUS_SCSI_IOC_TERMINATED:
		case MPI2_IOCSTATUS_SCSI_EXT_TERMINATED:
			mptsas_set_pkt_reason(mpt,
			    cmd, CMD_RESET, STAT_DEV_RESET);
			break;
		case MPI2_IOCSTATUS_SCSI_IO_DATA_ERROR:
		case MPI2_IOCSTATUS_SCSI_PROTOCOL_ERROR:
			pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET);
			mptsas_set_pkt_reason(mpt,
			    cmd, CMD_TERMINATED, STAT_TERMINATED);
			break;
		case MPI2_IOCSTATUS_INSUFFICIENT_RESOURCES:
		case MPI2_IOCSTATUS_BUSY:
			/*
			 * set throttles to drain
			 */
			for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
			    ptgt = refhash_next(mpt->m_targets, ptgt)) {
				mptsas_set_throttle_mtx(mpt, ptgt,
				    DRAIN_THROTTLE);
			}

			/*
			 * retry command
			 */
			mptsas_retry_pkt(mpt, cmd);
			break;
		default:
			mptsas_log(mpt, CE_WARN,
			    "unknown ioc_status = %x\n", ioc_status);
			mptsas_log(mpt, CE_CONT, "scsi_state = %x, transfer "
			    "count = %x, scsi_status = %x", scsi_state,
			    xferred, scsi_status);
			break;
		}
		break;
	case MPI2_SCSI_STATUS_TASK_SET_FULL:
		mptsas_handle_qfull(mpt, cmd);
		break;
	case MPI2_SCSI_STATUS_BUSY:
		NDBG31(("scsi_status busy received"));
		break;
	case MPI2_SCSI_STATUS_RESERVATION_CONFLICT:
		NDBG31(("scsi_status reservation conflict received"));
		break;
	default:
		mptsas_log(mpt, CE_WARN, "scsi_status=%x, ioc_status=%x\n",
		    scsi_status, ioc_status);
		mptsas_log(mpt, CE_WARN,
		    "mptsas_process_intr: invalid scsi status\n");
		break;
	}
}

static void
mptsas_check_task_mgt(mptsas_t *mpt, pMpi2SCSIManagementReply_t reply,
	mptsas_cmd_t *cmd)
{
	uint8_t		task_type;
	uint16_t	ioc_status;
	uint32_t	log_info;
	uint16_t	dev_handle;

	task_type = ddi_get8(mpt->m_acc_reply_frame_hdl, &reply->TaskType);
	ioc_status = ddi_get16(mpt->m_acc_reply_frame_hdl, &reply->IOCStatus);
	log_info = ddi_get32(mpt->m_acc_reply_frame_hdl, &reply->IOCLogInfo);
	dev_handle = ddi_get16(mpt->m_acc_reply_frame_hdl, &reply->DevHandle);

	if (ioc_status != MPI2_IOCSTATUS_SUCCESS) {
		uint8_t	dr_flag = cmd->cmd_tgt_addr ?
		    cmd->cmd_tgt_addr->m_dr_flag : 0;

		mptsas_log(mpt, CE_WARN, "mptsas_check_task_mgt: Task 0x%x "
		    "failed. IOCStatus=0x%x RespCode=0x%x IOCLogInfo=0x%x "
		    "TermCt=0x%x target=%d, dr=%d\n",
		    task_type, ioc_status,
		    ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &reply->ResponseCode), log_info,
		    ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &reply->TerminationCount),
		    dev_handle, dr_flag);

		/*
		 * If we tried to reset a target that is in dr transition
		 * failure is a reasonable reply and should not be considered
		 * a problem.
		 * If we fail this management command it will result in
		 * the entire controller being reset, avoid that if
		 * possible.
		 */
		if (task_type != MPI2_SCSITASKMGMT_TASKTYPE_TARGET_RESET ||
		    dr_flag != MPTSAS_DR_INTRANSITION) {
			mptsas_set_pkt_reason(mpt, cmd, CMD_INCOMPLETE,
			    STAT_ABORTED);
			return;
		}
	}

	NDBG31(("%d: check_task_mgt: Task 0x%x "
	    "IOCStatus=0x%x IOCLogInfo=0x%x target=%d\n", mpt->m_instance,
	    task_type, ioc_status, log_info, dev_handle));

	switch (task_type) {
	case MPI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK:
	case MPI2_SCSITASKMGMT_TASKTYPE_CLEAR_TASK_SET:
	case MPI2_SCSITASKMGMT_TASKTYPE_QUERY_TASK:
	case MPI2_SCSITASKMGMT_TASKTYPE_CLR_ACA:
	case MPI2_SCSITASKMGMT_TASKTYPE_QRY_TASK_SET:
	case MPI2_SCSITASKMGMT_TASKTYPE_QRY_UNIT_ATTENTION:
	break;
	case MPI2_SCSITASKMGMT_TASKTYPE_ABRT_TASK_SET:
	case MPI2_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET:
	case MPI2_SCSITASKMGMT_TASKTYPE_TARGET_RESET:
		/*
		 * Check for invalid DevHandle of 0 in case application
		 * sends bad command.  DevHandle of 0 could cause problems.
		 */
		if (dev_handle == 0) {
			mptsas_log(mpt, CE_WARN, "!Can't flush target with"
			    " DevHandle of 0.");
		} else {
			/*
			 * Flush the target here.
			 * This may well leave commands on the HBA and
			 * we are likely to get responses for slots with
			 * NULL pointers.
			 */
			mptsas_flush_target_hba(mpt, dev_handle, Lun(cmd),
			    task_type);
		}
	break;
	default:
		mptsas_log(mpt, CE_WARN, "Unknown task management type %d.",
		    task_type);
		mptsas_log(mpt, CE_WARN, "ioc status = %x", ioc_status);
	break;
	}
}

static void
mptsas_doneq_thread(mptsas_thread_arg_t *arg)
{
	mptsas_t			*mpt = arg->mpt;
	uint32_t			t = arg->t;
	mptsas_cmd_t			*cmd, *next;
	mptsas_doneq_thread_list_t	*item = &mpt->m_doneq_thread_id[t];

	mutex_enter(&item->mutex);
	while (item->flag & MPTSAS_DONEQ_THREAD_ACTIVE) {
		while (STAILQ_EMPTY(&item->done.cl_q)) {
			cv_wait(&item->cv, &item->mutex);
		}
		cmd = STAILQ_FIRST(&item->done.cl_q);
		ASSERT(cmd != NULL);
		NDBG1(("%d: mptsas_doneq_thread: rm %d cmds (head 0x%p)",
		    mpt->m_instance, item->done.cl_len, (void *)cmd));
		STAILQ_INIT(&item->done.cl_q);
		item->done.cl_len = 0;

		mutex_exit(&item->mutex);
		while (cmd != NULL) {
			next = STAILQ_NEXT(cmd, cmd_link);
			STAILQ_NEXT(cmd, cmd_link) = NULL;
			mptsas_pkt_comp(cmd);
			cmd = next;
		}
		mutex_enter(&item->mutex);
	}
	mutex_exit(&item->mutex);
	mutex_enter(&mpt->m_qthread_mutex);
	mpt->m_doneq_thread_n--;
	cv_broadcast(&mpt->m_qthread_cv);
	mutex_exit(&mpt->m_qthread_mutex);
}


/*
 * mpt interrupt handler.
 */
static uint_t
mptsas_intr(caddr_t arg1, caddr_t arg2)
{
	mptsas_t			*mpt = (void *)arg1;
	mptsas_reply_pqueue_t		*rpqp;
	int				reply_q = (int)(uintptr_t)arg2;
	pMpi2ReplyDescriptorsUnion_t	reply_desc_union;
	int				found = 0, i, rpqidx;
	size_t				dma_sync_len;
	off_t				dma_sync_offset;
	uint32_t			istat;
	int8_t				cpumap;

	NDBG18(("%d: intr: reply_q 0x%d", mpt->m_instance, reply_q));

	rpqp = &mpt->m_rep_post_queues[reply_q];

	/*
	 * If interrupts are shared by two channels then check whether this
	 * interrupt is genuinely for this channel by making sure first the
	 * chip is in high power state.
	 */
	if ((mpt->m_options & MPTSAS_OPT_PM) &&
	    (mpt->m_power_level != PM_LEVEL_D0)) {
		mpt->m_unclaimed_pm_interrupt_count++;
		return (DDI_INTR_UNCLAIMED);
	}

	istat = MPTSAS_GET_ISTAT(mpt);
	if (!(istat & MPI2_HIS_REPLY_DESCRIPTOR_INTERRUPT)) {
		NDBG18(("%d: Interrupt bit not set, istat 0x%x",
		    mpt->m_instance, istat));
		mpt->m_unclaimed_no_interrupt_count++;
		/*
		 * Really need a good definition of when this is valid.
		 * It appears not to be if you have multiple reply post
		 * queues, there may be a better way - need LSI info.
		 * For now just count them.
		 */
#if 0
		return (DDI_INTR_UNCLAIMED);
#endif
	}

	mpt->m_lastintr_tstamp = gethrtime();
	cpumap = mpt->m_cpu_to_repq[CPU_SEQID];
	if (cpumap == -1)
		mpt->m_cpu_to_repq[CPU_SEQID] = (int8_t)reply_q;

	/* Just exit if we find in_reset flag */
	if (mpt->m_in_reset == TRUE) {
		mpt->m_unclaimed_inreset_interrupt_count++;
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Grab mutex for the repqueue.
	 */
	mutex_enter(&rpqp->rpq_mutex);

	/*
	 * If polling, interrupt was triggered by some shared interrupt because
	 * IOC interrupts are disabled during polling, so polling routine will
	 * handle any replies.  Considering this, if polling is happening,
	 * return with interrupt unclaimed.
	 */
	if (mpt->m_polled_intr && reply_q == 0) {
		mptsas_log(mpt, CE_WARN,
		    "Unclaimed interrupt, rpq %d (Polling), istat 0x%x",
		    reply_q, istat);
		mpt->m_unclaimed_polled_interrupt_count++;
		mutex_exit(&rpqp->rpq_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	dma_sync_len = mpt->m_post_queue_depth * 8;
	dma_sync_offset = dma_sync_len * reply_q;
	(void) ddi_dma_sync(mpt->m_dma_post_queue_hdl,
	    dma_sync_offset, dma_sync_len, DDI_DMA_SYNC_FORCPU);

	/*
	 * Go around the reply queue and process each descriptor until
	 * we get to the next unused one.
	 * It seems to be an occupational hazard that we get interrupts
	 * with nothing to do. These are counted below.
	 */
	rpqidx = rpqp->rpq_index;
#ifndef __lock_lint
	_NOTE(CONSTCOND)
#endif
	while (TRUE) {
		reply_desc_union = (pMpi2ReplyDescriptorsUnion_t)
		    MPTSAS_GET_NEXT_REPLY(rpqp, rpqidx);

		if (ddi_get32(mpt->m_acc_post_queue_hdl,
		    &reply_desc_union->Words.Low) == 0xFFFFFFFF ||
		    ddi_get32(mpt->m_acc_post_queue_hdl,
		    &reply_desc_union->Words.High) == 0xFFFFFFFF) {
			break;
		}

		found++;

		ASSERT(ddi_get8(mpt->m_acc_post_queue_hdl,
		    &reply_desc_union->Default.MSIxIndex) == reply_q);

		/*
		 * Process it according to its type.
		 */
		mptsas_process_intr(mpt, rpqp, reply_desc_union);

		/*
		 * Clear the reply descriptor for re-use.
		 */
		ddi_put64(mpt->m_acc_post_queue_hdl,
		    &((uint64_t *)(void *)rpqp->rpq_queue)[rpqidx],
		    0xFFFFFFFFFFFFFFFF);

		/*
		 * Increment post index and roll over if needed.
		 */
		if (++rpqidx == mpt->m_post_queue_depth) {
			rpqidx = 0;
		}
	}

	if (found == 0) {
		rpqp->rpq_intr_unclaimed++;
		mutex_exit(&rpqp->rpq_mutex);
		mpt->m_unclaimed_nocmd_interrupt_count++;
		return (DDI_INTR_UNCLAIMED);
	}
	rpqp->rpq_index = rpqidx;

	rpqp->rpq_intr_count++;
	NDBG18(("%d: intr complete(%d), did %d loops", mpt->m_instance,
	    reply_q, found));

	(void) ddi_dma_sync(mpt->m_dma_post_queue_hdl,
	    dma_sync_offset, dma_sync_len, DDI_DMA_SYNC_FORDEV);

	mpt->m_interrupt_count++;

	/*
	 * Update the reply index if at least one reply was processed.
	 * For more than 8 reply queues on SAS3 controllers we have to do
	 * things a little different. See Chapter 20 in the MPI 2.5 spec.
	 */
	if (mpt->m_post_reply_qcount > 8) {
		/*
		 * The offsets from the base are multiples of 0x10.
		 * We are indexing into 32 bit quantities so calculate
		 * the index for that.
		 */
		i = (reply_q&~0x7) >> 1;
		ddi_put32(mpt->m_datap,
		    &mpt->m_reg->SuppReplyPostHostIndex[i],
		    rpqp->rpq_index |
		    ((reply_q&0x7)<<MPI2_RPHI_MSIX_INDEX_SHIFT));
		(void) ddi_get32(mpt->m_datap,
		    &mpt->m_reg->SuppReplyPostHostIndex[i]);
	} else {
		ddi_put32(mpt->m_datap,
		    &mpt->m_reg->ReplyPostHostIndex,
		    rpqp->rpq_index | (reply_q<<MPI2_RPHI_MSIX_INDEX_SHIFT));
		(void) ddi_get32(mpt->m_datap,
		    &mpt->m_reg->ReplyPostHostIndex);
	}

	/*
	 * If no helper threads are created, process the doneq in ISR. If
	 * helpers are created, use the doneq length as a metric to measure the
	 * load on the interrupt CPU. If it is long enough, which indicates the
	 * load is heavy, then we deliver the IO completions to the helpers.
	 * This measurement has some limitations, although it is simple and
	 * straightforward and works well for most of the cases at present.
	 * To always use the threads set mptsas_doneq_length_threshold_prop
	 * to zero in the mpt_sas3.conf file.
	 *
	 * Check the current reply queue done queue.
	 */
	mptsas_rpdoneq_empty(mpt, rpqp, B_FALSE);

	/*
	 * Check the main done queue. If we find something
	 * grab the mutex and check again before processing.
	 * Anything on this queue is not time critical so we always hand off
	 * to the threads (if there are any!).
	 */
	if (mpt->m_done.cl_len) {
		mutex_enter(&mpt->m_mutex);
		if (mpt->m_in_reset != TRUE && mpt->m_done.cl_len) {
			if (!mpt->m_doneq_thread_n) {
				mptsas_doneq_empty(mpt);
			} else {
				mptsas_deliver_doneq_thread(mpt, &mpt->m_done);
			}
		}
		mutex_exit(&mpt->m_mutex);
	}

	/*
	 * If there are queued cmd, start them now.
	 */
	if (mpt->m_wait.cl_len != 0 || mpt->m_ntwait != 0) {
		mutex_enter(&mpt->m_mutex);
		if (mpt->m_in_reset != TRUE && mpt->m_polled_intr == 0) {
			mptsas_restart_waitq(mpt);
		}
		mutex_exit(&mpt->m_mutex);
	}
	return (DDI_INTR_CLAIMED);
}

static void
mptsas_process_intr(mptsas_t *mpt, mptsas_reply_pqueue_t *rpqp,
    pMpi2ReplyDescriptorsUnion_t reply_desc_union)
{
	uint8_t	reply_type;

	/*
	 * Should get here with the reply queue mutex held, but not
	 * the main mpt mutex. Want to avoid grabbing that during
	 * normal operations if possible.
	 */
	ASSERT(mutex_owned(&rpqp->rpq_mutex));

	/*
	 * The reply is valid, process it according to its
	 * type.  Also, set a flag for updated the reply index
	 * after they've all been processed.
	 */
	reply_type = ddi_get8(mpt->m_acc_post_queue_hdl,
	    &reply_desc_union->Default.ReplyFlags);
	NDBG18(("%d: process_intr(rpq %d) reply_type 0x%x",
	    mpt->m_instance, rpqp->rpq_num, reply_type));
	reply_type &= MPI2_RPY_DESCRIPT_FLAGS_TYPE_MASK;
	if (reply_type == MPI2_RPY_DESCRIPT_FLAGS_SCSI_IO_SUCCESS ||
	    reply_type == MPI25_RPY_DESCRIPT_FLAGS_FAST_PATH_SCSI_IO_SUCCESS) {
		mptsas_handle_scsi_io_success(mpt, rpqp, reply_desc_union);
	} else if (reply_type == MPI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY) {
		mutex_enter(&mpt->m_mutex);
		mptsas_handle_address_reply(mpt, reply_desc_union);
		mutex_exit(&mpt->m_mutex);
	} else {
		mptsas_log(mpt, CE_WARN, "?Bad reply type %x", reply_type);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
	}
}

/*
 * handle qfull condition
 */
static void
mptsas_handle_qfull(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	mptsas_target_t	*ptgt = cmd->cmd_tgt_addr;

	NDBG27(("%d: handle_qfull: target %d, cmd 0x%p", mpt->m_instance,
	    ptgt->m_devhdl, (void *)cmd));

	mutex_enter(&ptgt->m_t_mutex);
	if ((++cmd->cmd_qfull_retries > ptgt->m_qfull_retries) ||
	    (ptgt->m_qfull_retries == 0)) {
		/*
		 * We have exhausted the retries on QFULL, or,
		 * the target driver has indicated that it
		 * wants to handle QFULL itself by setting
		 * qfull-retries capability to 0. In either case
		 * we want the target driver's QFULL handling
		 * to kick in. We do this by having pkt_reason
		 * as CMD_CMPLT and pkt_scbp as STATUS_QFULL.
		 */
		mptsas_set_throttle(mpt, ptgt, DRAIN_THROTTLE);
	} else {
		if (ptgt->m_reset_delay == 0) {
			NDBG27(("%d: Qfull targ %d - Set Throttle %d -> %d",
			    mpt->m_instance, ptgt->m_devhdl, ptgt->m_t_throttle,
			    max((ptgt->m_t_ncmds - 2), 0)));
			ptgt->m_t_throttle = max((ptgt->m_t_ncmds - 2), 0);
		}
		mutex_exit(&ptgt->m_t_mutex);

		cmd->cmd_flags &= ~(CFLAG_TRANFLAG);

		mptsas_retry_pkt(mpt, cmd);

		mutex_enter(&ptgt->m_t_mutex);
		/*
		 * when target gives queue full status with no commands
		 * outstanding (m_t_ncmds == 0), throttle is set to 0
		 * (HOLD_THROTTLE), and the queue full handling start
		 * (see psarc/1994/313); if there are commands outstanding,
		 * throttle is set to (m_t_ncmds - 2)
		 */
		if (ptgt->m_t_throttle == HOLD_THROTTLE) {
			/*
			 * By setting throttle to QFULL_THROTTLE, we
			 * avoid submitting new commands and in
			 * mptsas_restart_cmd find out slots which need
			 * their throttles to be cleared.
			 */
			mptsas_set_throttle(mpt, ptgt, QFULL_THROTTLE);
			if (mpt->m_restart_cmd_timeid == 0) {
				mpt->m_restart_cmd_timeid =
				    timeout(mptsas_restart_cmd, mpt,
				    ptgt->m_qfull_retry_interval);
			}
		}
	}
	mutex_exit(&ptgt->m_t_mutex);
}

mptsas_phymask_t
mptsas_physport_to_phymask(mptsas_t *mpt, uint8_t physport)
{
	mptsas_phymask_t	phy_mask = 0;
	uint8_t			i = 0;

	NDBG20(("%d physport_to_phymask enter", mpt->m_instance));

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * If physport is 0xFF, this is a RAID volume.  Use phymask of 0.
	 */
	if (physport == 0xFF) {
		return (0);
	}

	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		if (mpt->m_phy_info[i].attached_devhdl &&
		    (mpt->m_phy_info[i].phy_mask != 0) &&
		    (mpt->m_phy_info[i].port_num == physport)) {
			phy_mask = mpt->m_phy_info[i].phy_mask;
			break;
		}
	}
	NDBG20(("%d physport_to_phymask:physport :%x phymask :%x, ",
	    mpt->m_instance, physport, phy_mask));
	return (phy_mask);
}

/*
 * mpt free device handle after device gone, by use of passthrough
 */
static int
mptsas_free_devhdl(mptsas_t *mpt, uint16_t devhdl)
{
	Mpi2SasIoUnitControlRequest_t	req;
	Mpi2SasIoUnitControlReply_t	rep;
	int				ret;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Need to compose a SAS IO Unit Control request message
	 * and call mptsas_do_passthru() function
	 */
	bzero(&req, sizeof (req));
	bzero(&rep, sizeof (rep));

	req.Function = MPI2_FUNCTION_SAS_IO_UNIT_CONTROL;
	req.Operation = MPI2_SAS_OP_REMOVE_DEVICE;
	req.DevHandle = LE_16(devhdl);

	ret = mptsas_do_passthru(mpt, (uint8_t *)&req, (uint8_t *)&rep, NULL,
	    sizeof (req), sizeof (rep), 0, 0, NULL, 0, 60, FKIOCTL);
	if (ret != 0) {
		cmn_err(CE_WARN, "mptsas_free_devhdl: passthru SAS IO Unit "
		    "Control error %d", ret);
		return (DDI_FAILURE);
	}

	/* do passthrough success, check the ioc status */
	if (LE_16(rep.IOCStatus) != MPI2_IOCSTATUS_SUCCESS) {
		cmn_err(CE_WARN, "mptsas_free_devhdl: passthru SAS IO Unit "
		    "Control IOCStatus %d", LE_16(rep.IOCStatus));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
mptsas_update_phymask(mptsas_t *mpt)
{
	mptsas_phymask_t mask = 0, phy_mask;
	char		*phy_mask_name;
	uint8_t		current_port;
	int		i, j;

	NDBG20(("%d update phymask ", mpt->m_instance));

	ASSERT(mutex_owned(&mpt->m_mutex));

	(void) mptsas_get_sas_io_unit_page(mpt);

	phy_mask_name = kmem_zalloc(MPTSAS_MAX_PHYS, KM_SLEEP);

	for (i = 0; i < mpt->m_num_phys; i++) {
		phy_mask = 0x00;

		if (mpt->m_phy_info[i].attached_devhdl == 0)
			continue;

		bzero(phy_mask_name, sizeof (phy_mask_name));

		current_port = mpt->m_phy_info[i].port_num;

		if ((mask & (1 << i)) != 0)
			continue;

		for (j = 0; j < mpt->m_num_phys; j++) {
			if (mpt->m_phy_info[j].attached_devhdl &&
			    (mpt->m_phy_info[j].port_num == current_port)) {
				phy_mask |= (1 << j);
			}
		}
		mask = mask | phy_mask;

		for (j = 0; j < mpt->m_num_phys; j++) {
			if ((phy_mask >> j) & 0x01) {
				mpt->m_phy_info[j].phy_mask = phy_mask;
			}
		}

		(void) sprintf(phy_mask_name, "%x", phy_mask);

		mutex_exit(&mpt->m_mutex);
		/*
		 * register a iport, if the port has already been existed
		 * SCSA will do nothing and just return.
		 */
		(void) scsi_hba_iport_register(mpt->m_dip, phy_mask_name);
		mutex_enter(&mpt->m_mutex);
	}
	kmem_free(phy_mask_name, MPTSAS_MAX_PHYS);
	NDBG20(("%d update phymask return", mpt->m_instance));
}

static dev_info_t *
mptsas_find_parent(mptsas_t *mpt, mptsas_topo_change_list_t *topo_node)
{
	uint8_t			physport, flags;
	mptsas_phymask_t	phymask = 0;
	uint_t			event;
	char			phy_mask_name[MPTSAS_MAX_PHYS];
	dev_info_t		*parent;

	flags = topo_node->flags;
	event = topo_node->event;
	physport = topo_node->un.physport;

	if ((event & (MPTSAS_DR_EVENT_OFFLINE_TARGET |
	    MPTSAS_DR_EVENT_OFFLINE_SMP)) ||
	    (flags & MPTSAS_TOPO_FLAG_LUN_ASSOCIATED)) {
		/*
		 * For offline events or LUN_ASSOCIATED, phymask is known.
		 */
		phymask = topo_node->un.phymask;
	} else {

		mutex_enter(&mpt->m_mutex);
		if (flags == MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE) {
			/*
			 * If the direct attached device added or a
			 * phys disk is being unhidden, argument
			 * physport actually is PHY#, so we have to get
			 * phymask according PHY#.
			 */
			physport = mpt->m_phy_info[physport].port_num;
		}

		/*
		 * Translate physport to phymask so that we can search
		 * parent dip.
		 */
		phymask = mptsas_physport_to_phymask(mpt, physport);
		mutex_exit(&mpt->m_mutex);
	}

	bzero(phy_mask_name, MPTSAS_MAX_PHYS);
	/*
	 * For RAID topology change node, write the iport name
	 * as v0.
	 */
	if (flags & MPTSAS_TOPO_FLAG_RAID_ASSOCIATED) {
		(void) sprintf(phy_mask_name, "v0");
	} else {
		/*
		 * phymask can be 0 if the drive has been
		 * pulled by the time an add event is
		 * processed.  If phymask is 0, just skip this
		 * event and continue.
		 */
		if (phymask == 0) {
			return (NULL);
		}
		(void) sprintf(phy_mask_name, "%x", phymask);
	}
	parent = scsi_hba_iport_find(mpt->m_dip, phy_mask_name);
	if (parent == NULL) {
		mptsas_log(mpt, CE_WARN, "Failed to find an "
		    "iport for \"%s\", should not happen!", phy_mask_name);
	}
	return (parent);
}

/*
 * mptsas_handle_dr is a task handler for DR, the DR action includes:
 * 1. Directly attched Device Added/Removed.
 * 2. Expander Device Added/Removed.
 * 3. Indirectly Attached Device Added/Expander.
 * 4. LUNs of a existing device status change.
 * 5. RAID volume created/deleted.
 * 6. Member of RAID volume is released because of RAID deletion.
 * 7. Physical disks are removed because of RAID creation.
 */
static void
mptsas_handle_dr(void *args) {
	mptsas_topo_change_list_t	*topo_node = NULL;
	mptsas_topo_change_list_t	*save_node = NULL;
	mptsas_t			*mpt;
	dev_info_t			*parent = NULL;
	uint8_t				flags = 0;
	uint8_t				port_update = 0;
	uint_t				event;

	topo_node = (mptsas_topo_change_list_t *)args;

	mpt = topo_node->mpt;
	event = topo_node->event;
	flags = topo_node->flags;

	NDBG20(("%d handle_dr enter", mpt->m_instance));

	switch (event) {
	case MPTSAS_DR_EVENT_RECONFIG_TARGET:
		if ((flags == MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE) ||
		    (flags == MPTSAS_TOPO_FLAG_EXPANDER_ATTACHED_DEVICE) ||
		    (flags == MPTSAS_TOPO_FLAG_RAID_PHYSDRV_ASSOCIATED)) {
			/*
			 * Direct attached or expander attached device added
			 * into system or a Phys Disk that is being unhidden.
			 */
			port_update = 1;
		}
		break;
	case MPTSAS_DR_EVENT_RECONFIG_SMP:
		/*
		 * New expander added into system, it must be the head
		 * of topo_change_list_t
		 */
		port_update = 1;
		break;
	default:
		port_update = 0;
		break;
	}

	/*
	 * All cases port_update == 1 may cause initiator port form change
	 */
	mutex_enter(&mpt->m_mutex);
	if (mpt->m_port_chng && port_update) {
		/*
		 * mpt->m_port_chng flag indicates some PHYs of initiator
		 * port have changed to online. So when expander added or
		 * directly attached device online event come, we force to
		 * update port information by issueing SAS IO Unit Page and
		 * update PHYMASKs.
		 */
		(void) mptsas_update_phymask(mpt);
		mpt->m_port_chng = 0;

	}
	mutex_exit(&mpt->m_mutex);

	while (topo_node) {
		flags = topo_node->flags;
		event = topo_node->event;
		if (event == MPTSAS_DR_EVENT_REMOVE_HANDLE) {
			goto handle_topo_change;
		}
		if ((event == MPTSAS_DR_EVENT_RECONFIG_TARGET) &&
		    (flags == MPTSAS_TOPO_FLAG_RAID_PHYSDRV_ASSOCIATED)) {
			/*
			 * There is no any field in IR_CONFIG_CHANGE
			 * event indicate physport/phynum, let's get
			 * parent after SAS Device Page0 request.
			 */
			goto handle_topo_change;
		}

		if (parent == NULL) {
			parent = mptsas_find_parent(mpt, topo_node);

			if (parent == NULL) {
				save_node = topo_node;
				topo_node = topo_node->next;
				ASSERT(save_node);
				kmem_free(save_node,
				    sizeof (mptsas_topo_change_list_t));
				continue;
			}

		}
		ASSERT(parent);
handle_topo_change:

		mutex_enter(&mpt->m_mutex);
		/*
		 * If HBA is being reset, don't perform operations depending
		 * on the IOC. We must free the topo list, however.
		 */
		if (mpt->m_in_reset != TRUE) {
			mptsas_handle_topo_change(topo_node, parent);
		} else {
			NDBG20(("%d: skipping topo change received during "
				"reset", mpt->m_instance));
		}
		mutex_exit(&mpt->m_mutex);
		save_node = topo_node;
		topo_node = topo_node->next;
		ASSERT(save_node);
		kmem_free(save_node, sizeof (mptsas_topo_change_list_t));

		if ((flags == MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE) ||
		    (flags == MPTSAS_TOPO_FLAG_RAID_PHYSDRV_ASSOCIATED) ||
		    (flags == MPTSAS_TOPO_FLAG_RAID_ASSOCIATED)) {
			/*
			 * If direct attached device associated, make sure
			 * reset the parent before start the next one. But
			 * all devices associated with expander shares the
			 * parent.  Also, reset parent if this is for RAID.
			 */
			parent = NULL;
		}
	}
}

static void
mptsas_alloc_target_luninfo(mptsas_target_t *ptgt, uint16_t nluns)
{
	ptgt->m_t_luns = (mptsas_lun_t *)kmem_zalloc(
	    sizeof (mptsas_lun_t) * nluns, KM_SLEEP);
	ptgt->m_t_nluns = nluns;
}

static void
mptsas_free_target_luninfo(mptsas_target_t *ptgt)
{
	int	lidx;

	if (ptgt->m_t_luns != NULL) {
		ASSERT(ptgt->m_t_nluns != 0);
		for (lidx = 0; lidx < ptgt->m_t_nluns; lidx++) {
			if (ptgt->m_t_luns[lidx].l_guid != NULL)
				ddi_devid_free_guid(
				    ptgt->m_t_luns[lidx].l_guid);
		}
		kmem_free(ptgt->m_t_luns,
		    sizeof (mptsas_lun_t) * ptgt->m_t_nluns);
		ptgt->m_t_luns = NULL;
		ptgt->m_t_nluns = 0;
	}
}


static void
mptsas_offline_target(mptsas_t *mpt, mptsas_target_t *ptgt,
    uint8_t topo_flags, dev_info_t *parent)
{
	uint64_t	sas_wwn = 0;
	uint8_t		phy;
	char		wwn_str[MPTSAS_WWN_STRLEN];
	uint16_t	devhdl;
	int		circ = 0, circ1 = 0;
	int		rval = 0;

	ASSERT(mutex_owned(&mpt->m_mutex));
	ASSERT(mutex_owned(&ptgt->m_t_mutex));
	ASSERT(ptgt->m_ncfgluns == 0);

	sas_wwn = ptgt->m_addr.mta_wwn;
	phy = ptgt->m_phynum;
	devhdl = ptgt->m_devhdl;

	if (sas_wwn) {
		(void) sprintf(wwn_str, "w%016"PRIx64, sas_wwn);
	} else {
		(void) sprintf(wwn_str, "p%x", phy);
	}

	/*
	 * Set throttle to hold and devhdl to invalid before dropping the
	 * mutex in order that:
	 * o Another offline event doesn't race with us.
	 * o There are no further changes to the throttle.
	 * o No more commands are added to the waitq in mptsas_accept_pkt().
	 */
	mptsas_set_throttle(mpt, ptgt, HOLD_THROTTLE);
	ptgt->m_devhdl = MPTSAS_INVALID_DEVHDL;
	ptgt->m_reset_delay = 0;

	/*
	 * Abort all outstanding command for this device.
	 * Can't keep hold of the mutex as we wait for completion.
	 */
	mutex_exit(&ptgt->m_t_mutex);
	rval = mptsas_do_scsi_reset(mpt, devhdl, B_TRUE);

	NDBG20(("%d: offline_target: reset target "
	    "before offline target %d, phymask:%x, rval:%x", mpt->m_instance,
	    devhdl, ptgt->m_addr.mta_phymask, rval));

	mutex_enter(&ptgt->m_t_mutex);
	ASSERT(ptgt->m_t_ncmds == 0);
	mptsas_flush_target_waitq(mpt, ptgt, B_FALSE, 0, 0, STAT_ABORTED,
	    CMD_DEV_GONE);
	ASSERT(ptgt->m_t_wait.cl_len == 0);
	mutex_exit(&ptgt->m_t_mutex);
	mutex_exit(&mpt->m_mutex);

	ndi_devi_enter(scsi_vhci_dip, &circ);
	ndi_devi_enter(parent, &circ1);
	rval = mptsas_offline_targetdev(parent, wwn_str);
	ndi_devi_exit(parent, circ1);
	ndi_devi_exit(scsi_vhci_dip, circ);
	NDBG20(("%d: offline_target %s target %d, "
	    "phymask:%x, rval:%x", mpt->m_instance, wwn_str,
	    devhdl, ptgt->m_addr.mta_phymask, rval));

	/*
	 * Clear parent's props for SMHBA support
	 */
	if (topo_flags == MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE) {
		if (ddi_prop_update_string(DDI_DEV_T_NONE, parent,
		    SCSI_ADDR_PROP_ATTACHED_PORT, "") !=
		    DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
			    SCSI_ADDR_PROP_ATTACHED_PORT);
			mptsas_log(mpt, CE_WARN, "mptsas attached port "
			    "prop update failed");
		}
		if (ddi_prop_update_int(DDI_DEV_T_NONE, parent,
		    MPTSAS_NUM_PHYS, 0) != DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
			    MPTSAS_NUM_PHYS);
			mptsas_log(mpt, CE_WARN, "mptsas num phys "
			    "prop update failed");
		}
		if (ddi_prop_update_int(DDI_DEV_T_NONE, parent,
		    MPTSAS_VIRTUAL_PORT, 1) != DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
			    MPTSAS_VIRTUAL_PORT);
			mptsas_log(mpt, CE_WARN, "mptsas virtual port "
			    "prop update failed");
		}
	}

	mutex_enter(&ptgt->m_t_mutex);
	mptsas_free_target_luninfo(ptgt);
	mutex_exit(&ptgt->m_t_mutex);
	mutex_enter(&mpt->m_mutex);
	ptgt->m_led_status = 0;
	(void) mptsas_flush_led_status(mpt, ptgt);
	if (rval == DDI_SUCCESS) {
		mutex_destroy(&ptgt->m_t_mutex);
		cv_destroy(&ptgt->m_t_cv);
		refhash_remove(mpt->m_targets, ptgt);
		/* refhash_remove() will free the ptgt structure */
	} else {
		/*
		 * clean DR_INTRANSITION flag to allow I/O down to
		 * PHCI driver since failover finished.
		 */
		NDBG28(("%d: targ %d dr_flag to inactive.",
		    mpt->m_instance, devhdl));
		ptgt->m_tgt_unconfigured = 0;
		ptgt->m_dr_flag = MPTSAS_DR_INACTIVE;
		/* Clear any probe failure count. */
		ptgt->m_pcfail = 0;
	}
}

static int
mptsas_reconfig_target(mptsas_topo_change_list_t *topo_node,
    dev_info_t *parent, mptsas_target_t *ptgt, mptsas_tinit_state_t ntinit)
{
	mptsas_t	*mpt = (void *)topo_node->mpt;
	char		attached_wwnstr[MPTSAS_WWN_STRLEN];
	int		rval;
	int		circ = 0, circ1 = 0;
	uint16_t	attached_devhdl;
	boolean_t	was_inv;

	ASSERT(mutex_owned(&mpt->m_mutex));
	ASSERT(ntinit == TINIT_REPROBE || ntinit == TINIT_REPROBEW);
	mutex_enter(&ptgt->m_t_mutex);
	was_inv = (ptgt->m_t_init == TINIT_FOUND ||
	    ptgt->m_t_init == TINIT_ALLOCED);
	mptsas_config_wait(mpt, ptgt, ntinit);
	mutex_exit(&ptgt->m_t_mutex);
	mutex_exit(&mpt->m_mutex);
	rval = mptsas_probe_target(parent, ptgt);
	mutex_enter(&ptgt->m_t_mutex);
	ASSERT(ptgt->m_t_init == TINIT_REPROBE ||
	    ptgt->m_t_init == TINIT_REPROBEW);
	if (rval == DDI_SUCCESS) {
		ptgt->m_t_init = TINIT_RECONF;
		mutex_exit(&ptgt->m_t_mutex);
#ifdef MPTSAS_TEST
		if (mptsas_test_reset_while_online) {
			mptsas_test_reset_while_online = 0;
			(void) ddi_taskq_dispatch(mpt->m_reset_taskq,
			    mptsas_restart_ioc_task, (void *)mpt, DDI_SLEEP);
		}
#endif
		/*
		 * hold nexus for bus configure
		 */
		ndi_devi_enter(scsi_vhci_dip, &circ);
		ndi_devi_enter(parent, &circ1);
		rval = mptsas_config_target(parent, ptgt);
		/*
		 * release nexus for bus configure
		 */
		ndi_devi_exit(parent, circ1);
		ndi_devi_exit(scsi_vhci_dip, circ);
		mutex_enter(&ptgt->m_t_mutex);
		ASSERT(ptgt->m_t_init == TINIT_RECONF);
	}

	if (rval != DDI_SUCCESS && was_inv &&
	    (ptgt->m_cnfg_luns & TFGL_OFFLINE) == 0) {
		/*
		 * If the probe/config failed and there are no further actions
		 * scheduled we should do some tidying up in the target
		 * structure if it was originally found or allocated.
		 */
		mptsas_set_throttle(mpt, ptgt, HOLD_THROTTLE);
		ptgt->m_shdwhdl = ptgt->m_devhdl;
		ptgt->m_devhdl = MPTSAS_INVALID_DEVHDL;
		ptgt->m_tgt_unconfigured = 0;
		ptgt->m_dr_flag = MPTSAS_DR_INACTIVE;
		mptsas_free_target_luninfo(ptgt);
	}
	mptsas_clr_tgtcl(mpt, ptgt);
	mutex_exit(&ptgt->m_t_mutex);

	mutex_enter(&mpt->m_mutex);
	/*
	 * Add parent's props for SMHBA support
	 */
	if (rval == DDI_SUCCESS &&
	    topo_node->flags == MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE) {
		bzero(attached_wwnstr, sizeof (attached_wwnstr));
		(void) sprintf(attached_wwnstr, "w%016"PRIx64,
		    ptgt->m_addr.mta_wwn);

		if (ddi_prop_update_string(DDI_DEV_T_NONE, parent,
		    SCSI_ADDR_PROP_ATTACHED_PORT, attached_wwnstr)
		    != DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
			    SCSI_ADDR_PROP_ATTACHED_PORT);
			mptsas_log(mpt, CE_WARN,
			    "Failed to update attached-port prop");
		}
		if (ddi_prop_update_int(DDI_DEV_T_NONE, parent,
		    MPTSAS_NUM_PHYS, 1) != DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
			    MPTSAS_NUM_PHYS);
			mptsas_log(mpt, CE_WARN,
			    "Failed to create num-phys prop");
		}

		/*
		 * Update PHY info for smhba
		 */
		if (mptsas_smhba_phy_init(mpt)) {
			mptsas_log(mpt, CE_WARN, "mptsas phy"
			    " update failed");
		}

		/*
		 * topo_node->un.physport is really the PHY#
		 * for direct attached devices
		 */
		mptsas_smhba_set_one_phy_props(mpt, parent,
		    topo_node->un.physport, &attached_devhdl);

		if (ddi_prop_update_int(DDI_DEV_T_NONE, parent,
		    MPTSAS_VIRTUAL_PORT, 0) != DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
			    MPTSAS_VIRTUAL_PORT);
			mptsas_log(mpt, CE_WARN, "mptsas virtual-port"
			    " port prop update failed");
		}
	}
	return (rval);
}

static void
mptsas_handle_topo_change(mptsas_topo_change_list_t *topo_node,
    dev_info_t *parent)
{
	mptsas_target_t	*ptgt = NULL;
	mptsas_smp_t	*psmp = NULL;
	mptsas_t	*mpt = (void *)topo_node->mpt;
	uint16_t	devhdl;
	int		rval = 0;
	uint32_t	page_address;
	uint8_t		flags;
	dev_info_t	*lundip;
	int		circ1 = 0;
	char		attached_wwnstr[MPTSAS_WWN_STRLEN];

	NDBG20(("%d handle_topo_change enter, target %d,"
	    "event 0x%x, flags 0x%x, obj 0x%p", mpt->m_instance,
	    topo_node->devhdl, topo_node->event, topo_node->flags,
	    topo_node->object));

	ASSERT(mutex_owned(&mpt->m_mutex));

	switch (topo_node->event) {
	case MPTSAS_DR_EVENT_RECONFIG_TARGET:
	{
		char *phy_mask_name;
		mptsas_phymask_t phymask = 0;
		mptsas_tinit_state_t new_tinit = TINIT_REPROBEW;

		if (topo_node->flags == MPTSAS_TOPO_FLAG_RAID_ASSOCIATED) {
			/*
			 * Get latest RAID info.
			 */
			(void) mptsas_get_raid_info(mpt);
			ptgt = refhash_linear_search(mpt->m_targets,
			    mptsas_target_eval_devhdl, &topo_node->devhdl);
			if (ptgt == NULL)
				break;
		} else {
			ptgt = (void *)topo_node->object;
		}

		flags = topo_node->flags;
		if (ptgt == NULL) {
			/*
			 * If a Phys Disk was deleted, RAID info needs to be
			 * updated to reflect the new topology.
			 */
			(void) mptsas_get_raid_info(mpt);

			/*
			 * Get sas device page 0 by DevHandle to make sure if
			 * SSP/SATA end device exist.
			 */
			page_address = (MPI2_SAS_DEVICE_PGAD_FORM_HANDLE &
			    MPI2_SAS_DEVICE_PGAD_FORM_MASK) |
			    topo_node->devhdl;

			rval = mptsas_get_target_device_info(mpt, page_address,
			    &devhdl, &ptgt);
			if (rval == DEV_INFO_WRONG_DEVICE_TYPE) {
				mptsas_log(mpt, CE_NOTE,
				    "mptsas_handle_topo_change: target %d is "
				    "not a SAS/SATA device. \n",
				    topo_node->devhdl);
			} else if (rval != DEV_INFO_SUCCESS) {
				mptsas_log(mpt, CE_NOTE,
				    "mptsas_handle_topo_change: "
				    "get_target_device_info failed - %d",
				    rval);
			}
			mutex_exit(&ptgt->m_t_mutex);

			/*
			 * If rval is DEV_INFO_PHYS_DISK than there is nothing
			 * else to do, just leave.
			 */
			if (rval != DEV_INFO_SUCCESS) {
				return;
			}

			/*
			 * New probe state will be reprobe as a result
			 * of an event.
			 */
			new_tinit = TINIT_REPROBE;
		}

		ASSERT(ptgt->m_devhdl == topo_node->devhdl);
		devhdl = ptgt->m_devhdl;
		phymask = ptgt->m_addr.mta_phymask;

		if (flags == MPTSAS_TOPO_FLAG_RAID_PHYSDRV_ASSOCIATED) {
			phy_mask_name = kmem_zalloc(MPTSAS_MAX_PHYS, KM_SLEEP);
			(void) sprintf(phy_mask_name, "%x", phymask);
			parent = scsi_hba_iport_find(mpt->m_dip,
			    phy_mask_name);
			kmem_free(phy_mask_name, MPTSAS_MAX_PHYS);
			if (parent == NULL) {
				mptsas_log(mpt, CE_WARN, "Failed to find a "
				    "iport for PD, should not happen!");
				break;
			}
		}

		rval = DDI_SUCCESS;
		if (flags == MPTSAS_TOPO_FLAG_RAID_ASSOCIATED) {
			mutex_exit(&mpt->m_mutex);
			ndi_devi_enter(parent, &circ1);
			(void) mptsas_config_raid(parent, devhdl, &lundip);
			ndi_devi_exit(parent, circ1);
			mutex_enter(&mpt->m_mutex);
		} else {
			rval = mptsas_reconfig_target(topo_node, parent, ptgt,
			    new_tinit);
		}

		NDBG20(("%d handle_topo_change to online target %d, "
		    "phymask:%x%s.", mpt->m_instance, devhdl, phymask,
		    rval == DDI_SUCCESS ? "" : " Failed _config_target()."));
		break;
	}
	case MPTSAS_DR_EVENT_OFFLINE_TARGET:
	{
		boolean_t forced_offline = topo_node->object == NULL;

		devhdl = topo_node->devhdl;
		flags = topo_node->flags;
		ptgt = refhash_linear_search(mpt->m_targets,
		    mptsas_target_eval_devhdl, &devhdl);
		if (ptgt == NULL)
			break;

		mutex_enter(&ptgt->m_t_mutex);

		ASSERT(ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL);
		ASSERT(ptgt->m_devhdl == devhdl);

		/*
		 * In the middle of initial configuration.
		 * Could get in a big mess if we go ahead and try to offline
		 * at the moment because the target pointer is under use
		 * without mutex protection.
		 * Setting the TFGL_OFFLINE bit will cause the code to
		 * come back through here when the initial config has
		 * completed via a task queue.
		 */
		if (ptgt->m_cnfg_luns & TFGL_ACTIVE) {
			ptgt->m_cnfg_luns |= TFGL_OFFLINE;
			if (topo_node->object != NULL) {
				ptgt->m_cnfg_luns |= TFGL_FREEHDL;
			}
			mutex_exit(&ptgt->m_t_mutex);
			mptsas_log(mpt, CE_WARN, "Offline target event for "
			    "target %d while config in progress", devhdl);
			break;
		}

		if ((flags == MPTSAS_TOPO_FLAG_RAID_ASSOCIATED) ||
		    (flags == MPTSAS_TOPO_FLAG_RAID_PHYSDRV_ASSOCIATED)) {
			/*
			 * Get latest RAID info if RAID volume status changes
			 * or Phys Disk status changes
			 */
			(void) mptsas_get_raid_info(mpt);
		}

		/*
		 * If this is not the result of the HBA reporting the target
		 * as offline (rather the software took action to do this)
		 * we remember the devhdl as m_shdwhdl. Should we
		 * ever want to restore (online) the target we can then use
		 * this to ensure we continue to reference the target with the
		 * same device ID as the HBA.
		 */
		if (forced_offline)
			ptgt->m_shdwhdl = ptgt->m_devhdl;

		mptsas_offline_target(mpt, ptgt, flags, parent);
		/* mptsas_offline_target() will release the m_t_mutex */

		/*
		 * Send SAS IO Unit Control to free the dev handle.
		 * If this came through a forced offline due to multiple
		 * timeouts the object field will be NULL and in that case
		 * we do not try to free the handle as it will result in an
		 * error as per Section 12.3 in the MPI 2 spec.
		 */
		if (!forced_offline && ((flags ==
		    MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE) ||
		    (flags == MPTSAS_TOPO_FLAG_EXPANDER_ATTACHED_DEVICE))) {
			rval = mptsas_free_devhdl(mpt, devhdl);

			NDBG20(("%d handle_topo_change to remove "
			    "target %d, rval:%x", mpt->m_instance, devhdl,
			    rval));
		}

		break;
	}
	case MPTSAS_DR_EVENT_REMOVE_HANDLE:
	{
		devhdl = topo_node->devhdl;

		/*
		 * Do a reset first.
		 */
		rval = mptsas_do_scsi_reset(mpt, devhdl, B_TRUE);
		NDBG20(("%d: reset target %d before removal, rval:%x",
		    mpt->m_instance, devhdl, rval));

		/*
		 * Send SAS IO Unit Control to free the dev handle
		 */
		rval = mptsas_free_devhdl(mpt, devhdl);
		NDBG20(("%d: handle_topo_change to remove "
		    "devhdl:%d, rval:%x", mpt->m_instance, devhdl,
		    rval));
		break;
	}
	case MPTSAS_DR_EVENT_RECONFIG_SMP:
	{
		mptsas_smp_t smp;
		dev_info_t *smpdip;

		devhdl = topo_node->devhdl;

		page_address = (MPI2_SAS_EXPAND_PGAD_FORM_HNDL &
		    MPI2_SAS_EXPAND_PGAD_FORM_MASK) | (uint32_t)devhdl;
		rval = mptsas_get_sas_expander_page0(mpt, page_address, &smp);
		if (rval != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN,
			    "mptsas_handle_topo_change: failed to online smp, "
			    "handle %d", devhdl);
			return;
		}

		psmp = mptsas_smp_alloc(mpt, &smp);
		if (psmp == NULL) {
			mptsas_log(mpt, CE_WARN,
			    "mptsas_handle_topo_change: failed to alloc smp, "
			    "handle %d", devhdl);
			return;
		}

		mutex_exit(&mpt->m_mutex);
		ndi_devi_enter(parent, &circ1);
		(void) mptsas_online_smp(parent, psmp, &smpdip);
		ndi_devi_exit(parent, circ1);

		mutex_enter(&mpt->m_mutex);
		break;
	}
	case MPTSAS_DR_EVENT_OFFLINE_SMP:
	{
		devhdl = topo_node->devhdl;
		uint32_t dev_info;

		psmp = refhash_linear_search(mpt->m_smp_targets,
		    mptsas_smp_eval_devhdl, &devhdl);
		if (psmp == NULL)
			break;
		/*
		 * The mptsas_smp_t data is released only if the dip is offlined
		 * successfully.
		 */
		ASSERT(psmp->m_devhdl == devhdl);
		psmp->m_devhdl = MPTSAS_INVALID_DEVHDL;
		mutex_exit(&mpt->m_mutex);

		ndi_devi_enter(parent, &circ1);
		rval = mptsas_offline_smp(parent, psmp, NDI_DEVI_REMOVE);
		ndi_devi_exit(parent, circ1);

		dev_info = psmp->m_deviceinfo;
		if ((dev_info & DEVINFO_DIRECT_ATTACHED) ==
		    DEVINFO_DIRECT_ATTACHED) {
			if (ddi_prop_update_int(DDI_DEV_T_NONE, parent,
			    MPTSAS_VIRTUAL_PORT, 1) !=
			    DDI_PROP_SUCCESS) {
				(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
				    MPTSAS_VIRTUAL_PORT);
				mptsas_log(mpt, CE_WARN, "mptsas virtual port "
				    "prop update failed");
			}
			/*
			 * Check whether the smp connected to the iport,
			 */
			if (ddi_prop_update_int(DDI_DEV_T_NONE, parent,
			    MPTSAS_NUM_PHYS, 0) !=
			    DDI_PROP_SUCCESS) {
				(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
				    MPTSAS_NUM_PHYS);
				mptsas_log(mpt, CE_WARN, "mptsas num phys"
				    "prop update failed");
			}
			/*
			 * Clear parent's attached-port props
			 */
			bzero(attached_wwnstr, sizeof (attached_wwnstr));
			if (ddi_prop_update_string(DDI_DEV_T_NONE, parent,
			    SCSI_ADDR_PROP_ATTACHED_PORT, attached_wwnstr) !=
			    DDI_PROP_SUCCESS) {
				(void) ddi_prop_remove(DDI_DEV_T_NONE, parent,
				    SCSI_ADDR_PROP_ATTACHED_PORT);
				mptsas_log(mpt, CE_WARN, "mptsas attached port "
				    "prop update failed");
			}
		}

		mutex_enter(&mpt->m_mutex);
		NDBG20(("%d: handle_topo_change to remove devhdl:%d, "
		    "rval:%x", mpt->m_instance, devhdl, rval));
		if (rval == DDI_SUCCESS) {
			refhash_remove(mpt->m_smp_targets, psmp);
		}

		bzero(attached_wwnstr, sizeof (attached_wwnstr));
		break;
	}
	default:
		return;
	}
	NDBG20(("%d: handle_topo_change done for target %d.",
	    mpt->m_instance, topo_node->devhdl));
}

/*
 * Record the event if its type is enabled in mpt instance by ioctl.
 */
static void
mptsas_record_event(void *args)
{
	m_replyh_arg_t			*replyh_arg;
	pMpi2EventNotificationReply_t	eventreply;
	uint32_t			event, rfm;
	mptsas_t			*mpt;
	int				i, j;
	uint16_t			event_data_len;
	boolean_t			sendAEN = FALSE;

	replyh_arg = (m_replyh_arg_t *)args;
	rfm = replyh_arg->rfm;
	mpt = replyh_arg->mpt;

	eventreply = (pMpi2EventNotificationReply_t)
	    (mpt->m_reply_frame + (rfm -
	    (mpt->m_reply_frame_dma_addr&0xfffffffful)));
	event = ddi_get16(mpt->m_acc_reply_frame_hdl, &eventreply->Event);


	/*
	 * Generate a system event to let anyone who cares know that a
	 * LOG_ENTRY_ADDED event has occurred.  This is sent no matter what the
	 * event mask is set to.
	 */
	if (event == MPI2_EVENT_LOG_ENTRY_ADDED) {
		sendAEN = TRUE;
	}

	/*
	 * Record the event only if it is not masked.  Determine which dword
	 * and bit of event mask to test.
	 */
	i = (uint8_t)(event / 32);
	j = (uint8_t)(event % 32);
	if ((i < 4) && ((1 << j) & mpt->m_event_mask[i])) {
		i = mpt->m_event_index;
		mpt->m_events[i].Type = event;
		mpt->m_events[i].Number = ++mpt->m_event_number;
		bzero(mpt->m_events[i].Data, MPTSAS_MAX_EVENT_DATA_LENGTH * 4);
		event_data_len = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &eventreply->EventDataLength);

		if (event_data_len > 0) {
			/*
			 * Limit data to size in m_event entry
			 */
			if (event_data_len > MPTSAS_MAX_EVENT_DATA_LENGTH) {
				event_data_len = MPTSAS_MAX_EVENT_DATA_LENGTH;
			}
			for (j = 0; j < event_data_len; j++) {
				mpt->m_events[i].Data[j] =
				    ddi_get32(mpt->m_acc_reply_frame_hdl,
				    &(eventreply->EventData[j]));
			}

			/*
			 * check for index wrap-around
			 */
			if (++i == MPTSAS_EVENT_QUEUE_SIZE) {
				i = 0;
			}
			mpt->m_event_index = (uint8_t)i;

			/*
			 * Set flag to send the event.
			 */
			sendAEN = TRUE;
		}
	}

	/*
	 * Generate a system event if flag is set to let anyone who cares know
	 * that an event has occurred.
	 */
	if (sendAEN) {
		(void) ddi_log_sysevent(mpt->m_dip, DDI_VENDOR_LSI, "MPT_SAS",
		    "SAS", NULL, NULL, DDI_NOSLEEP);
	}
}

#define	SMP_RESET_IN_PROGRESS MPI2_EVENT_SAS_TOPO_LR_SMP_RESET_IN_PROGRESS
/*
 * handle sync events from ioc in interrupt
 * return value:
 * DDI_SUCCESS: The event is handled by this func
 * DDI_FAILURE: Event is not handled
 */
static int
mptsas_handle_event_sync(void *args)
{
	m_replyh_arg_t			*replyh_arg;
	pMpi2EventNotificationReply_t	eventreply;
	uint32_t			event, rfm;
	mptsas_t			*mpt;
	uint_t				iocstatus;

	replyh_arg = (m_replyh_arg_t *)args;
	rfm = replyh_arg->rfm;
	mpt = replyh_arg->mpt;

	ASSERT(mutex_owned(&mpt->m_mutex));

	eventreply = (pMpi2EventNotificationReply_t)
	    (mpt->m_reply_frame + (rfm -
	    (mpt->m_reply_frame_dma_addr&0xfffffffful)));
	event = ddi_get16(mpt->m_acc_reply_frame_hdl, &eventreply->Event);

	if ((iocstatus = ddi_get16(mpt->m_acc_reply_frame_hdl,
	    &eventreply->IOCStatus)) != 0) {
		if (iocstatus == MPI2_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE) {
			mptsas_log(mpt, CE_WARN,
			    "!mptsas_handle_event_sync: event 0x%x, "
			    "IOCStatus=0x%x, "
			    "IOCLogInfo=0x%x", event, iocstatus,
			    ddi_get32(mpt->m_acc_reply_frame_hdl,
			    &eventreply->IOCLogInfo));
		} else {
			mptsas_log(mpt, CE_WARN,
			    "mptsas_handle_event_sync: event 0x%x, "
			    "IOCStatus=0x%x, "
			    "(IOCLogInfo=0x%x)", event, iocstatus,
			    ddi_get32(mpt->m_acc_reply_frame_hdl,
			    &eventreply->IOCLogInfo));
		}
	}

	/*
	 * figure out what kind of event we got and handle accordingly
	 */
	switch (event) {
	case MPI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST:
	{
		pMpi2EventDataSasTopologyChangeList_t	sas_topo_change_list;
		uint8_t				num_entries, expstatus, phy;
		uint8_t				phystatus, physport, state, i;
		uint8_t				start_phy_num, link_rate, odr;
		uint16_t			dev_handle, reason_code;
		uint16_t			enc_handle, expd_handle;
		char				string[80], curr[80], prev[80];
		mptsas_topo_change_list_t	*topo_head = NULL;
		mptsas_topo_change_list_t	*topo_tail = NULL;
		mptsas_topo_change_list_t	*topo_node = NULL;
		mptsas_target_t			*ptgt;
		mptsas_smp_t			*psmp;
		uint8_t				flags = 0, exp_flag;
		smhba_info_t			*pSmhba = NULL;

		NDBG20(("%d: handle_event_sync: SAS topology change",
		    mpt->m_instance));

		sas_topo_change_list = (pMpi2EventDataSasTopologyChangeList_t)
		    eventreply->EventData;

		enc_handle = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &sas_topo_change_list->EnclosureHandle);
		expd_handle = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &sas_topo_change_list->ExpanderDevHandle);
		num_entries = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &sas_topo_change_list->NumEntries);
		start_phy_num = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &sas_topo_change_list->StartPhyNum);
		expstatus = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &sas_topo_change_list->ExpStatus);
		physport = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &sas_topo_change_list->PhysicalPort);

		string[0] = 0;
		if (expd_handle) {
			flags = MPTSAS_TOPO_FLAG_EXPANDER_ASSOCIATED;
			switch (expstatus) {
			case MPI2_EVENT_SAS_TOPO_ES_ADDED:
				(void) sprintf(string, " added");
				/*
				 * New expander device added
				 */
				mpt->m_port_chng = 1;
				topo_node = kmem_zalloc(
				    sizeof (mptsas_topo_change_list_t),
				    KM_SLEEP);
				topo_node->mpt = mpt;
				topo_node->event = MPTSAS_DR_EVENT_RECONFIG_SMP;
				topo_node->un.physport = physport;
				topo_node->devhdl = expd_handle;
				topo_node->flags = flags;
				topo_node->object = NULL;
				if (topo_head == NULL) {
					topo_head = topo_tail = topo_node;
				} else {
					topo_tail->next = topo_node;
					topo_tail = topo_node;
				}
				break;
			case MPI2_EVENT_SAS_TOPO_ES_NOT_RESPONDING:
				(void) sprintf(string, " not responding, "
				    "removed");
				psmp = refhash_linear_search(mpt->m_smp_targets,
				    mptsas_smp_eval_devhdl, &expd_handle);
				if (psmp == NULL)
					break;

				topo_node = kmem_zalloc(
				    sizeof (mptsas_topo_change_list_t),
				    KM_SLEEP);
				topo_node->mpt = mpt;
				topo_node->un.phymask =
				    psmp->m_addr.mta_phymask;
				topo_node->event = MPTSAS_DR_EVENT_OFFLINE_SMP;
				topo_node->devhdl = expd_handle;
				topo_node->flags = flags;
				topo_node->object = NULL;
				if (topo_head == NULL) {
					topo_head = topo_tail = topo_node;
				} else {
					topo_tail->next = topo_node;
					topo_tail = topo_node;
				}
				break;
			case MPI2_EVENT_SAS_TOPO_ES_RESPONDING:
				break;
			case MPI2_EVENT_SAS_TOPO_ES_DELAY_NOT_RESPONDING:
				(void) sprintf(string, " not responding, "
				    "delaying removal");
				break;
			default:
				break;
			}
		} else {
			flags = MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE;
		}

		NDBG20(("%d: SAS TOPOLOGY CHANGE for enclosure %x "
		    "expander %x%s\n", mpt->m_instance, enc_handle,
		    expd_handle, string));
		for (i = 0; i < num_entries; i++) {
			phy = i + start_phy_num;
			phystatus = ddi_get8(mpt->m_acc_reply_frame_hdl,
			    &sas_topo_change_list->PHY[i].PhyStatus);
			dev_handle = ddi_get16(mpt->m_acc_reply_frame_hdl,
			    &sas_topo_change_list->PHY[i].AttachedDevHandle);
			reason_code = phystatus & MPI2_EVENT_SAS_TOPO_RC_MASK;
			/*
			 * Filter out processing of Phy Vacant Status unless
			 * the reason code is "Not Responding".  Process all
			 * other combinations of Phy Status and Reason Codes.
			 */
			if ((phystatus &
			    MPI2_EVENT_SAS_TOPO_PHYSTATUS_VACANT) &&
			    (reason_code !=
			    MPI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING)) {
				continue;
			}
			curr[0] = 0;
			prev[0] = 0;
			string[0] = 0;
			switch (reason_code) {
			case MPI2_EVENT_SAS_TOPO_RC_TARG_ADDED:
			{
				NDBG20(("%d: phy %d physical_port %d "
				    "dev_handle %d added", mpt->m_instance, phy,
				    physport, dev_handle));
				link_rate = ddi_get8(mpt->m_acc_reply_frame_hdl,
				    &sas_topo_change_list->PHY[i].LinkRate);
				state = (link_rate &
				    MPI2_EVENT_SAS_TOPO_LR_CURRENT_MASK) >>
				    MPI2_EVENT_SAS_TOPO_LR_CURRENT_SHIFT;
				switch (state) {
				case MPI2_EVENT_SAS_TOPO_LR_PHY_DISABLED:
					(void) sprintf(curr, "is disabled");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_NEGOTIATION_FAILED:
					(void) sprintf(curr, "is offline, "
					    "failed speed negotiation");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_SATA_OOB_COMPLETE:
					(void) sprintf(curr, "SATA OOB "
					    "complete");
					break;
				case SMP_RESET_IN_PROGRESS:
					(void) sprintf(curr, "SMP reset in "
					    "progress");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_1_5:
					(void) sprintf(curr, "is online at "
					    "1.5 Gbps");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_3_0:
					(void) sprintf(curr, "is online at 3.0 "
					    "Gbps");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_6_0:
					(void) sprintf(curr, "is online at 6.0 "
					    "Gbps");
					break;
				case MPI25_EVENT_SAS_TOPO_LR_RATE_12_0:
					(void) sprintf(curr,
					    "is online at 12.0 Gbps");
					break;
				default:
					(void) sprintf(curr, "state is "
					    "unknown");
					break;
				}
				/*
				 * New target device added into the system.
				 * Set association flag according to if an
				 * expander is used or not.
				 */
				exp_flag =
				    MPTSAS_TOPO_FLAG_EXPANDER_ATTACHED_DEVICE;
				if (flags ==
				    MPTSAS_TOPO_FLAG_EXPANDER_ASSOCIATED) {
					flags = exp_flag;
				}
				topo_node = kmem_zalloc(
				    sizeof (mptsas_topo_change_list_t),
				    KM_SLEEP);
				topo_node->mpt = mpt;
				topo_node->event =
				    MPTSAS_DR_EVENT_RECONFIG_TARGET;
				if (expd_handle == 0) {
					/*
					 * Per MPI 2, if expander dev handle
					 * is 0, it's a directly attached
					 * device. So driver use PHY to decide
					 * which iport is associated
					 */
					physport = phy;
					mpt->m_port_chng = 1;
				}
				topo_node->un.physport = physport;
				topo_node->devhdl = dev_handle;
				topo_node->flags = flags;
				topo_node->object = NULL;
				if (topo_head == NULL) {
					topo_head = topo_tail = topo_node;
				} else {
					topo_tail->next = topo_node;
					topo_tail = topo_node;
				}
				break;
			}
			case MPI2_EVENT_SAS_TOPO_RC_TARG_NOT_RESPONDING:
			{
				NDBG20(("%d: phy %d physical_port %d "
				    "dev_handle %d removed", mpt->m_instance,
				    phy, physport, dev_handle));
				/*
				 * Set association flag according to if an
				 * expander is used or not.
				 */
				exp_flag =
				    MPTSAS_TOPO_FLAG_EXPANDER_ATTACHED_DEVICE;
				if (flags ==
				    MPTSAS_TOPO_FLAG_EXPANDER_ASSOCIATED) {
					flags = exp_flag;
				}
				/*
				 * Target device is removed from the system
				 * Before the device is really offline from
				 * from system.
				 */
				ptgt = refhash_linear_search(mpt->m_targets,
				    mptsas_target_eval_devhdl, &dev_handle);
				/*
				 * If ptgt is NULL here, it means that the
				 * DevHandle is not in the hash table.  This is
				 * reasonable sometimes.  For example, if a
				 * disk was pulled, then added, then pulled
				 * again, the disk will not have been put into
				 * the hash table because the add event will
				 * have an invalid phymask.  BUT, this does not
				 * mean that the DevHandle is invalid.  The
				 * controller will still have a valid DevHandle
				 * that must be removed.  To do this, use the
				 * MPTSAS_DR_EVENT_REMOVE_HANDLE event.
				 */
				if (ptgt == NULL) {
					NDBG20(("%d: no target for phy "
					    "%d physical_port %d dev_handle %d"
					    " removal", mpt->m_instance,
					    phy, physport, dev_handle));
					topo_node = kmem_zalloc(
					    sizeof (mptsas_topo_change_list_t),
					    KM_SLEEP);
					topo_node->mpt = mpt;
					topo_node->un.phymask = 0;
					topo_node->event =
					    MPTSAS_DR_EVENT_REMOVE_HANDLE;
					topo_node->devhdl = dev_handle;
					topo_node->flags = flags;
					topo_node->object = NULL;
					if (topo_head == NULL) {
						topo_head = topo_tail =
						    topo_node;
					} else {
						topo_tail->next = topo_node;
						topo_tail = topo_node;
					}
					break;
				}

				/*
				 * Update DR flag immediately avoid I/O failure
				 * before failover finish. We won't add
				 * any following commands into waitq, instead,
				 * we need return TRAN_BUSY in the tran_start
				 * context.
				 */
				odr = atomic_swap_8(&ptgt->m_dr_flag,
				    MPTSAS_DR_INTRANSITION);
				NDBG28(("%d: targ %d dr_flag (%d) to "
				    "intxtn-1.", mpt->m_instance,
				    ptgt->m_devhdl, odr));

				if (odr != MPTSAS_DR_INTRANSITION) {
					topo_node = kmem_zalloc(
					    sizeof (mptsas_topo_change_list_t),
					    KM_SLEEP);
					topo_node->mpt = mpt;
					topo_node->un.phymask =
					    ptgt->m_addr.mta_phymask;
					topo_node->event =
					    MPTSAS_DR_EVENT_OFFLINE_TARGET;
					topo_node->devhdl = dev_handle;
					topo_node->flags = flags;
					topo_node->object = (void *)ptgt;
					if (topo_head == NULL) {
						topo_head = topo_tail =
						    topo_node;
					} else {
						topo_tail->next = topo_node;
						topo_tail = topo_node;
					}
				}
				break;
			}
			case MPI2_EVENT_SAS_TOPO_RC_PHY_CHANGED:
				link_rate = ddi_get8(mpt->m_acc_reply_frame_hdl,
				    &sas_topo_change_list->PHY[i].LinkRate);
				state = (link_rate &
				    MPI2_EVENT_SAS_TOPO_LR_CURRENT_MASK) >>
				    MPI2_EVENT_SAS_TOPO_LR_CURRENT_SHIFT;
				pSmhba = &mpt->m_phy_info[i].smhba_info;
				pSmhba->negotiated_link_rate = state;
				switch (state) {
				case MPI2_EVENT_SAS_TOPO_LR_PHY_DISABLED:
					(void) sprintf(curr, "is disabled");
					mptsas_smhba_log_sysevent(mpt,
					    ESC_SAS_PHY_EVENT,
					    SAS_PHY_REMOVE,
					    &mpt->m_phy_info[i].smhba_info);
					mpt->m_phy_info[i].smhba_info.
					    negotiated_link_rate
					    = 0x1;
					break;
				case MPI2_EVENT_SAS_TOPO_LR_NEGOTIATION_FAILED:
					(void) sprintf(curr, "is offline, "
					    "failed speed negotiation");
					mptsas_smhba_log_sysevent(mpt,
					    ESC_SAS_PHY_EVENT,
					    SAS_PHY_OFFLINE,
					    &mpt->m_phy_info[i].smhba_info);
					break;
				case MPI2_EVENT_SAS_TOPO_LR_SATA_OOB_COMPLETE:
					(void) sprintf(curr, "SATA OOB "
					    "complete");
					break;
				case SMP_RESET_IN_PROGRESS:
					(void) sprintf(curr, "SMP reset in "
					    "progress");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_1_5:
					(void) sprintf(curr, "is online at "
					    "1.5 Gbps");
					if ((expd_handle == 0) &&
					    (enc_handle == 1)) {
						mpt->m_port_chng = 1;
					}
					mptsas_smhba_log_sysevent(mpt,
					    ESC_SAS_PHY_EVENT,
					    SAS_PHY_ONLINE,
					    &mpt->m_phy_info[i].smhba_info);
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_3_0:
					(void) sprintf(curr, "is online at 3.0 "
					    "Gbps");
					if ((expd_handle == 0) &&
					    (enc_handle == 1)) {
						mpt->m_port_chng = 1;
					}
					mptsas_smhba_log_sysevent(mpt,
					    ESC_SAS_PHY_EVENT,
					    SAS_PHY_ONLINE,
					    &mpt->m_phy_info[i].smhba_info);
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_6_0:
					(void) sprintf(curr, "is online at "
					    "6.0 Gbps");
					if ((expd_handle == 0) &&
					    (enc_handle == 1)) {
						mpt->m_port_chng = 1;
					}
					mptsas_smhba_log_sysevent(mpt,
					    ESC_SAS_PHY_EVENT,
					    SAS_PHY_ONLINE,
					    &mpt->m_phy_info[i].smhba_info);
					break;
				case MPI25_EVENT_SAS_TOPO_LR_RATE_12_0:
					(void) sprintf(curr, "is online at "
					    "12.0 Gbps");
					if ((expd_handle == 0) &&
					    (enc_handle == 1)) {
						mpt->m_port_chng = 1;
					}
					mptsas_smhba_log_sysevent(mpt,
					    ESC_SAS_PHY_EVENT,
					    SAS_PHY_ONLINE,
					    &mpt->m_phy_info[i].smhba_info);
					break;
				default:
					(void) sprintf(curr, "state is "
					    "unknown");
					break;
				}

				state = (link_rate &
				    MPI2_EVENT_SAS_TOPO_LR_PREV_MASK) >>
				    MPI2_EVENT_SAS_TOPO_LR_PREV_SHIFT;
				switch (state) {
				case MPI2_EVENT_SAS_TOPO_LR_PHY_DISABLED:
					(void) sprintf(prev, ", was disabled");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_NEGOTIATION_FAILED:
					(void) sprintf(prev, ", was offline, "
					    "failed speed negotiation");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_SATA_OOB_COMPLETE:
					(void) sprintf(prev, ", was SATA OOB "
					    "complete");
					break;
				case SMP_RESET_IN_PROGRESS:
					(void) sprintf(prev, ", was SMP reset "
					    "in progress");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_1_5:
					(void) sprintf(prev, ", was online at "
					    "1.5 Gbps");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_3_0:
					(void) sprintf(prev, ", was online at "
					    "3.0 Gbps");
					break;
				case MPI2_EVENT_SAS_TOPO_LR_RATE_6_0:
					(void) sprintf(prev, ", was online at "
					    "6.0 Gbps");
					break;
				case MPI25_EVENT_SAS_TOPO_LR_RATE_12_0:
					(void) sprintf(prev, ", was online at "
					    "12.0 Gbps");
					break;
				default:
				break;
				}
				(void) sprintf(&string[strlen(string)], "link "
				    "changed, ");
				break;
			case MPI2_EVENT_SAS_TOPO_RC_NO_CHANGE:
				continue;
			case MPI2_EVENT_SAS_TOPO_RC_DELAY_NOT_RESPONDING:
				(void) sprintf(&string[strlen(string)],
				    "target not responding, delaying "
				    "removal");
				break;
			}
			NDBG20(("%d: phy %d, target %d, %s%s%s\n",
			    mpt->m_instance, phy, dev_handle, string, curr,
			    prev));
		}
		if (topo_head != NULL) {
			/*
			 * Launch DR taskq to handle topology change
			 */
			if ((ddi_taskq_dispatch(mpt->m_dr_taskq,
			    mptsas_handle_dr, (void *)topo_head,
			    DDI_NOSLEEP)) != DDI_SUCCESS) {
				while (topo_head != NULL) {
					topo_node = topo_head;
					topo_head = topo_head->next;
					kmem_free(topo_node,
					    sizeof (mptsas_topo_change_list_t));
				}
				mptsas_log(mpt, CE_NOTE, "mptsas start taskq "
				    "for handle SAS DR event failed. \n");
			}
		}
		break;
	}
	case MPI2_EVENT_IR_CONFIGURATION_CHANGE_LIST:
	{
		Mpi2EventDataIrConfigChangeList_t	*irChangeList;
		mptsas_topo_change_list_t		*topo_head = NULL;
		mptsas_topo_change_list_t		*topo_tail = NULL;
		mptsas_topo_change_list_t		*topo_node = NULL;
		mptsas_target_t				*ptgt;
		uint8_t					odr;
		uint8_t					num_entries, i, reason;
		uint16_t				volhandle, diskhandle;

		irChangeList = (pMpi2EventDataIrConfigChangeList_t)
		    eventreply->EventData;
		num_entries = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &irChangeList->NumElements);

		NDBG20(("%d: IR_CONFIGURATION_CHANGE_LIST event "
		    "received", mpt->m_instance));

		for (i = 0; i < num_entries; i++) {
			reason = ddi_get8(mpt->m_acc_reply_frame_hdl,
			    &irChangeList->ConfigElement[i].ReasonCode);
			volhandle = ddi_get16(mpt->m_acc_reply_frame_hdl,
			    &irChangeList->ConfigElement[i].VolDevHandle);
			diskhandle = ddi_get16(mpt->m_acc_reply_frame_hdl,
			    &irChangeList->ConfigElement[i].PhysDiskDevHandle);

			switch (reason) {
			case MPI2_EVENT_IR_CHANGE_RC_ADDED:
			case MPI2_EVENT_IR_CHANGE_RC_VOLUME_CREATED:
			{
				NDBG20(("%d: volume added\n",
				    mpt->m_instance));

				topo_node = kmem_zalloc(
				    sizeof (mptsas_topo_change_list_t),
				    KM_SLEEP);

				topo_node->mpt = mpt;
				topo_node->event =
				    MPTSAS_DR_EVENT_RECONFIG_TARGET;
				topo_node->un.physport = 0xff;
				topo_node->devhdl = volhandle;
				topo_node->flags =
				    MPTSAS_TOPO_FLAG_RAID_ASSOCIATED;
				topo_node->object = NULL;
				if (topo_head == NULL) {
					topo_head = topo_tail = topo_node;
				} else {
					topo_tail->next = topo_node;
					topo_tail = topo_node;
				}
				break;
			}
			case MPI2_EVENT_IR_CHANGE_RC_REMOVED:
			case MPI2_EVENT_IR_CHANGE_RC_VOLUME_DELETED:
			{
				NDBG20(("%d: volume deleted\n",
				    mpt->m_instance));
				ptgt = refhash_linear_search(mpt->m_targets,
				    mptsas_target_eval_devhdl, &volhandle);
				if (ptgt == NULL)
					break;

				/*
				 * Clear any flags related to volume
				 */
				(void) mptsas_delete_volume(mpt, volhandle);

				/*
				 * Update DR flag immediately avoid I/O failure
				 */
				odr = atomic_swap_8(&ptgt->m_dr_flag,
				    MPTSAS_DR_INTRANSITION);
				NDBG28(("%d: targ %d dr_flag (%d) to "
				    "intxtn-2.", mpt->m_instance,
				    ptgt->m_devhdl, odr));

				if (odr != MPTSAS_DR_INTRANSITION) {
					topo_node = kmem_zalloc(
					    sizeof (mptsas_topo_change_list_t),
					    KM_SLEEP);
					topo_node->mpt = mpt;
					topo_node->un.phymask =
					    ptgt->m_addr.mta_phymask;
					topo_node->event =
					    MPTSAS_DR_EVENT_OFFLINE_TARGET;
					topo_node->devhdl = volhandle;
					topo_node->flags =
					    MPTSAS_TOPO_FLAG_RAID_ASSOCIATED;
					topo_node->object = (void *)ptgt;
					if (topo_head == NULL) {
						topo_head = topo_tail =
						    topo_node;
					} else {
						topo_tail->next = topo_node;
						topo_tail = topo_node;
					}
				}
				break;
			}
			case MPI2_EVENT_IR_CHANGE_RC_PD_CREATED:
			case MPI2_EVENT_IR_CHANGE_RC_HIDE:
			{
				ptgt = refhash_linear_search(mpt->m_targets,
				    mptsas_target_eval_devhdl, &diskhandle);
				if (ptgt == NULL)
					break;

				/*
				 * Update DR flag immediately avoid I/O failure
				 */
				odr = atomic_swap_8(&ptgt->m_dr_flag,
				    MPTSAS_DR_INTRANSITION);
				NDBG28(("%d: targ %d dr_flag (%d) to "
				    "intxtn-3.", mpt->m_instance,
				    ptgt->m_devhdl, odr));

				if (odr != MPTSAS_DR_INTRANSITION) {
					topo_node = kmem_zalloc(
					    sizeof (mptsas_topo_change_list_t),
					    KM_SLEEP);
					topo_node->mpt = mpt;
					topo_node->un.phymask =
					    ptgt->m_addr.mta_phymask;
					topo_node->event =
					    MPTSAS_DR_EVENT_OFFLINE_TARGET;
					topo_node->devhdl = diskhandle;
					topo_node->flags =
				    MPTSAS_TOPO_FLAG_RAID_PHYSDRV_ASSOCIATED;
					topo_node->object = (void *)ptgt;
					if (topo_head == NULL) {
						topo_head = topo_tail =
						    topo_node;
					} else {
						topo_tail->next = topo_node;
						topo_tail = topo_node;
					}
				}
				break;
			}
			case MPI2_EVENT_IR_CHANGE_RC_UNHIDE:
			case MPI2_EVENT_IR_CHANGE_RC_PD_DELETED:
			{
				/*
				 * The physical drive is released by a IR
				 * volume. But we cannot get the the physport
				 * or phynum from the event data, so we only
				 * can get the physport/phynum after SAS
				 * Device Page0 request for the devhdl.
				 */
				topo_node = kmem_zalloc(
				    sizeof (mptsas_topo_change_list_t),
				    KM_SLEEP);
				topo_node->mpt = mpt;
				topo_node->un.phymask = 0;
				topo_node->event =
				    MPTSAS_DR_EVENT_RECONFIG_TARGET;
				topo_node->devhdl = diskhandle;
				topo_node->flags =
				    MPTSAS_TOPO_FLAG_RAID_PHYSDRV_ASSOCIATED;
				topo_node->object = NULL;
				mpt->m_port_chng = 1;
				if (topo_head == NULL) {
					topo_head = topo_tail = topo_node;
				} else {
					topo_tail->next = topo_node;
					topo_tail = topo_node;
				}
				break;
			}
			default:
				break;
			}
		}

		if (topo_head != NULL) {
			/*
			 * Launch DR taskq to handle topology change
			 */
			if ((ddi_taskq_dispatch(mpt->m_dr_taskq,
			    mptsas_handle_dr, (void *)topo_head,
			    DDI_NOSLEEP)) != DDI_SUCCESS) {
				while (topo_head != NULL) {
					topo_node = topo_head;
					topo_head = topo_head->next;
					kmem_free(topo_node,
					    sizeof (mptsas_topo_change_list_t));
				}
				mptsas_log(mpt, CE_NOTE, "mptsas start taskq "
				    "for handle SAS DR event failed. \n");
			}
		}
		break;
	}
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * handle events from ioc
 */
static void
mptsas_handle_event(void *args)
{
	m_replyh_arg_t			*replyh_arg;
	pMpi2EventNotificationReply_t	eventreply;
	uint32_t			event, iocloginfo, rfm;
	uint32_t			status;
	uint8_t				port;
	mptsas_t			*mpt;
	uint_t				iocstatus;

	replyh_arg = (m_replyh_arg_t *)args;
	rfm = replyh_arg->rfm;
	mpt = replyh_arg->mpt;

	/*
	 * The m_replyh_args array gets zeroed during a full reset.
	 * It possible that happened while our task was queued.
	 * So if the values are zero just return.
	 */
	if (mpt == NULL)
		return;

	mutex_enter(&mpt->m_mutex);

	/*
	 * If HBA is being reset, drop incoming event.
	 */
	if (mpt->m_in_reset == TRUE) {
		NDBG20(("%d: dropping event received prior to reset",
		    mpt->m_instance));
		mutex_exit(&mpt->m_mutex);
		return;
	}

	eventreply = (pMpi2EventNotificationReply_t)
	    (mpt->m_reply_frame + (rfm -
	    (mpt->m_reply_frame_dma_addr&0xfffffffful)));
	event = ddi_get16(mpt->m_acc_reply_frame_hdl, &eventreply->Event);

	if ((iocstatus = ddi_get16(mpt->m_acc_reply_frame_hdl,
	    &eventreply->IOCStatus)) != 0) {
		if (iocstatus == MPI2_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE) {
			mptsas_log(mpt, CE_WARN,
			    "!mptsas_handle_event: IOCStatus=0x%x, "
			    "IOCLogInfo=0x%x", iocstatus,
			    ddi_get32(mpt->m_acc_reply_frame_hdl,
			    &eventreply->IOCLogInfo));
		} else {
			mptsas_log(mpt, CE_WARN,
			    "mptsas_handle_event: IOCStatus=0x%x, "
			    "IOCLogInfo=0x%x", iocstatus,
			    ddi_get32(mpt->m_acc_reply_frame_hdl,
			    &eventreply->IOCLogInfo));
		}
	}

	/*
	 * figure out what kind of event we got and handle accordingly
	 */
	switch (event) {
	case MPI2_EVENT_LOG_ENTRY_ADDED:
		break;
	case MPI2_EVENT_LOG_DATA:
		iocloginfo = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &eventreply->IOCLogInfo);
		NDBG20(("%d: log info %x received.\n", mpt->m_instance,
		    iocloginfo));
		break;
	case MPI2_EVENT_STATE_CHANGE:
		NDBG20(("%d: state change.", mpt->m_instance));
		break;
	case MPI2_EVENT_HARD_RESET_RECEIVED:
		NDBG20(("%d: event change.", mpt->m_instance));
		break;
	case MPI2_EVENT_SAS_DISCOVERY:
	{
		MPI2_EVENT_DATA_SAS_DISCOVERY	*sasdiscovery;
		char				string[80];
		uint8_t				rc;

		sasdiscovery =
		    (pMpi2EventDataSasDiscovery_t)eventreply->EventData;

		rc = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &sasdiscovery->ReasonCode);
		port = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &sasdiscovery->PhysicalPort);
		status = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &sasdiscovery->DiscoveryStatus);

		string[0] = 0;
		switch (rc) {
		case MPI2_EVENT_SAS_DISC_RC_STARTED:
			(void) sprintf(string, "STARTING");
			break;
		case MPI2_EVENT_SAS_DISC_RC_COMPLETED:
			(void) sprintf(string, "COMPLETED");
			break;
		default:
			(void) sprintf(string, "UNKNOWN");
			break;
		}

		NDBG20(("%d: SAS DISCOVERY is %s for port %d, status "
		    "%x", mpt->m_instance, string, port, status));

		break;
	}
	case MPI2_EVENT_EVENT_CHANGE:
		NDBG20(("%d: event change.", mpt->m_instance));
		break;
	case MPI2_EVENT_TASK_SET_FULL:
	{
		pMpi2EventDataTaskSetFull_t	taskfull;

		taskfull = (pMpi2EventDataTaskSetFull_t)eventreply->EventData;

		NDBG20(("%d: TASK_SET_FULL received, depth %d\n",
		    mpt->m_instance, ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &taskfull->CurrentDepth)));
		break;
	}
	case MPI2_EVENT_SAS_TOPOLOGY_CHANGE_LIST:
	{
		/*
		 * SAS TOPOLOGY CHANGE LIST Event has already been handled
		 * in mptsas_handle_event_sync() of interrupt context
		 */
		break;
	}
	case MPI2_EVENT_SAS_ENCL_DEVICE_STATUS_CHANGE:
	{
		pMpi2EventDataSasEnclDevStatusChange_t	encstatus;
		uint8_t					rc;
		char					string[80];

		encstatus = (pMpi2EventDataSasEnclDevStatusChange_t)
		    eventreply->EventData;

		rc = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &encstatus->ReasonCode);
		switch (rc) {
		case MPI2_EVENT_SAS_ENCL_RC_ADDED:
			(void) sprintf(string, "added");
			break;
		case MPI2_EVENT_SAS_ENCL_RC_NOT_RESPONDING:
			(void) sprintf(string, ", not responding");
			break;
		default:
		break;
		}
		NDBG20(("%d: ENCLOSURE STATUS CHANGE for enclosure "
		    "%x%s\n", mpt->m_instance,
		    ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &encstatus->EnclosureHandle), string));
		break;
	}

	/*
	 * MPI2_EVENT_SAS_DEVICE_STATUS_CHANGE is handled by
	 * mptsas_handle_event_sync,in here just send ack message.
	 */
	case MPI2_EVENT_SAS_DEVICE_STATUS_CHANGE:
	{
		pMpi2EventDataSasDeviceStatusChange_t	statuschange;
		uint8_t					rc;
		uint16_t				devhdl;
		uint64_t				wwn = 0;
		uint32_t				wwn_lo, wwn_hi;
		mptsas_target_t				*ptgt;

		statuschange = (pMpi2EventDataSasDeviceStatusChange_t)
		    eventreply->EventData;
		rc = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &statuschange->ReasonCode);
		wwn_lo = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    (uint32_t *)(void *)&statuschange->SASAddress);
		wwn_hi = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    (uint32_t *)(void *)&statuschange->SASAddress + 1);
		wwn = ((uint64_t)wwn_hi << 32) | wwn_lo;
		devhdl =  ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &statuschange->DevHandle);

		NDBG13(("%d: MPI2_EVENT_SAS_DEVICE_STATUS_CHANGE wwn "
		    "is %"PRIx64" rc 0x%x", mpt->m_instance, wwn, rc));

		switch (rc) {
		case MPI2_EVENT_SAS_DEV_STAT_RC_SMART_DATA:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: SMART data "
			    "received, ASC/ASCQ = %02x/%02x",
			    ddi_get8(mpt->m_acc_reply_frame_hdl,
			    &statuschange->ASC),
			    ddi_get8(mpt->m_acc_reply_frame_hdl,
			    &statuschange->ASCQ));
			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_UNSUPPORTED:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "Device not supported");
			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_INTERNAL_DEVICE_RESET:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "IOC internally generated the Target Reset "
			    "for devhdl:%d", devhdl);
			/*
			 * If we get one of these we should start
			 * our own target reset holdoff and prevent further
			 * resets to this target from vhci/sd during that time.
			 */
			if ((ptgt = refhash_linear_search(mpt->m_targets,
			    mptsas_target_eval_devhdl, &devhdl)) != NULL) {
				mutex_enter(&ptgt->m_t_mutex);
				mptsas_setup_target_reset_delay(mpt, ptgt, 0);
				mutex_exit(&ptgt->m_t_mutex);
			}

			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_CMP_INTERNAL_DEV_RESET:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "IOC's internally generated Target Reset "
			    "completed for devhdl:%d", devhdl);
			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_TASK_ABORT_INTERNAL:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "IOC internally generated Abort Task");
			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_CMP_TASK_ABORT_INTERNAL:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "IOC's internally generated Abort Task "
			    "completed");
			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_ABORT_TASK_SET_INTERNAL:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "IOC internally generated Abort Task Set");
			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_CLEAR_TASK_SET_INTERNAL:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "IOC internally generated Clear Task Set");
			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_QUERY_TASK_INTERNAL:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "IOC internally generated Query Task");
			break;

		case MPI2_EVENT_SAS_DEV_STAT_RC_ASYNC_NOTIFICATION:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "Device sent an Asynchronous Notification");
			break;

		default:
			mptsas_log(mpt, CE_NOTE, "?Dev Sts Chng: "
			    "Unknown ReasonCode 0x%x", rc);
			break;
		}
		break;
	}
	case MPI2_EVENT_IR_CONFIGURATION_CHANGE_LIST:
	{
		/*
		 * IR TOPOLOGY CHANGE LIST Event has already been handled
		 * in mpt_handle_event_sync() of interrupt context
		 */
		break;
	}
	case MPI2_EVENT_IR_OPERATION_STATUS:
	{
		Mpi2EventDataIrOperationStatus_t	*irOpStatus;
		char					reason_str[80];
		uint8_t					rc, percent;
		uint16_t				handle;

		irOpStatus = (pMpi2EventDataIrOperationStatus_t)
		    eventreply->EventData;
		rc = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &irOpStatus->RAIDOperation);
		percent = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &irOpStatus->PercentComplete);
		handle = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &irOpStatus->VolDevHandle);

		switch (rc) {
			case MPI2_EVENT_IR_RAIDOP_RESYNC:
				(void) sprintf(reason_str, "resync");
				break;
			case MPI2_EVENT_IR_RAIDOP_ONLINE_CAP_EXPANSION:
				(void) sprintf(reason_str, "online capacity "
				    "expansion");
				break;
			case MPI2_EVENT_IR_RAIDOP_CONSISTENCY_CHECK:
				(void) sprintf(reason_str, "consistency check");
				break;
			default:
				(void) sprintf(reason_str, "unknown reason %x",
				    rc);
		}

		NDBG20(("%d: raid operational status: (%s)"
		    "\thandle(0x%04x), percent complete(%d)\n",
		    mpt->m_instance, reason_str, handle, percent));
		break;
	}
	case MPI2_EVENT_SAS_BROADCAST_PRIMITIVE:
	{
		pMpi2EventDataSasBroadcastPrimitive_t	sas_broadcast;
		uint8_t					phy_num;
		uint8_t					primitive;

		sas_broadcast = (pMpi2EventDataSasBroadcastPrimitive_t)
		    eventreply->EventData;

		phy_num = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &sas_broadcast->PhyNum);
		primitive = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &sas_broadcast->Primitive);

		switch (primitive) {
		case MPI2_EVENT_PRIMITIVE_CHANGE:
			mptsas_smhba_log_sysevent(mpt,
			    ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_CHANGE,
			    &mpt->m_phy_info[phy_num].smhba_info);
			break;
		case MPI2_EVENT_PRIMITIVE_SES:
			/*
			 * Send broadcast event based on configuration.
			 */
			if (!mptsas_disable_broadcast_ses) {
				mptsas_smhba_log_sysevent(mpt,
				    ESC_SAS_HBA_PORT_BROADCAST,
				    SAS_PORT_BROADCAST_SES,
				    &mpt->m_phy_info[phy_num].smhba_info);
			}
			break;
		case MPI2_EVENT_PRIMITIVE_EXPANDER:
			mptsas_smhba_log_sysevent(mpt,
			    ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_D01_4,
			    &mpt->m_phy_info[phy_num].smhba_info);
			break;
		case MPI2_EVENT_PRIMITIVE_ASYNCHRONOUS_EVENT:
			mptsas_smhba_log_sysevent(mpt,
			    ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_D04_7,
			    &mpt->m_phy_info[phy_num].smhba_info);
			break;
		case MPI2_EVENT_PRIMITIVE_RESERVED3:
			mptsas_smhba_log_sysevent(mpt,
			    ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_D16_7,
			    &mpt->m_phy_info[phy_num].smhba_info);
			break;
		case MPI2_EVENT_PRIMITIVE_RESERVED4:
			mptsas_smhba_log_sysevent(mpt,
			    ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_D29_7,
			    &mpt->m_phy_info[phy_num].smhba_info);
			break;
		case MPI2_EVENT_PRIMITIVE_CHANGE0_RESERVED:
			mptsas_smhba_log_sysevent(mpt,
			    ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_D24_0,
			    &mpt->m_phy_info[phy_num].smhba_info);
			break;
		case MPI2_EVENT_PRIMITIVE_CHANGE1_RESERVED:
			mptsas_smhba_log_sysevent(mpt,
			    ESC_SAS_HBA_PORT_BROADCAST,
			    SAS_PORT_BROADCAST_D27_4,
			    &mpt->m_phy_info[phy_num].smhba_info);
			break;
		default:
			NDBG16(("%d: unknown BROADCAST PRIMITIVE"
			    " %x received",
			    mpt->m_instance, primitive));
			break;
		}
		NDBG16(("%d: sas broadcast primitive: "
		    "\tprimitive(0x%04x), phy(%d) complete\n",
		    mpt->m_instance, primitive, phy_num));
		break;
	}
	case MPI2_EVENT_IR_VOLUME:
	{
		Mpi2EventDataIrVolume_t		*irVolume;
		uint16_t			devhandle;
		uint32_t			state;
		int				config, vol;
		uint8_t				found = FALSE;

		irVolume = (pMpi2EventDataIrVolume_t)eventreply->EventData;
		state = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &irVolume->NewValue);
		devhandle = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &irVolume->VolDevHandle);

		NDBG20(("%d: EVENT_IR_VOLUME event is received",
		    mpt->m_instance));

		/*
		 * Get latest RAID info and then find the DevHandle for this
		 * event in the configuration.  If the DevHandle is not found
		 * just exit the event.
		 */
		(void) mptsas_get_raid_info(mpt);
		for (config = 0; (config < mpt->m_num_raid_configs) &&
		    (!found); config++) {
			for (vol = 0; vol < MPTSAS_MAX_RAIDVOLS; vol++) {
				if (mpt->m_raidconfig[config].m_raidvol[vol].
				    m_raidhandle == devhandle) {
					found = TRUE;
					break;
				}
			}
		}
		if (!found) {
			break;
		}

		switch (irVolume->ReasonCode) {
		case MPI2_EVENT_IR_VOLUME_RC_SETTINGS_CHANGED:
		{
			uint32_t i;
			mpt->m_raidconfig[config].m_raidvol[vol].m_settings =
			    state;

			i = state & MPI2_RAIDVOL0_SETTING_MASK_WRITE_CACHING;
			mptsas_log(mpt, CE_NOTE, " Volume %d settings changed"
			    ", auto-config of hot-swap drives is %s"
			    ", write caching is %s"
			    ", hot-spare pool mask is %02x\n",
			    vol, state &
			    MPI2_RAIDVOL0_SETTING_AUTO_CONFIG_HSWAP_DISABLE
			    ? "disabled" : "enabled",
			    i == MPI2_RAIDVOL0_SETTING_UNCHANGED
			    ? "controlled by member disks" :
			    i == MPI2_RAIDVOL0_SETTING_DISABLE_WRITE_CACHING
			    ? "disabled" :
			    i == MPI2_RAIDVOL0_SETTING_ENABLE_WRITE_CACHING
			    ? "enabled" :
			    "incorrectly set",
			    (state >> 16) & 0xff);
				break;
		}
		case MPI2_EVENT_IR_VOLUME_RC_STATE_CHANGED:
		{
			mpt->m_raidconfig[config].m_raidvol[vol].m_state =
			    (uint8_t)state;

			mptsas_log(mpt, CE_NOTE,
			    "Volume %d is now %s\n", vol,
			    state == MPI2_RAID_VOL_STATE_OPTIMAL
			    ? "optimal" :
			    state == MPI2_RAID_VOL_STATE_DEGRADED
			    ? "degraded" :
			    state == MPI2_RAID_VOL_STATE_ONLINE
			    ? "online" :
			    state == MPI2_RAID_VOL_STATE_INITIALIZING
			    ? "initializing" :
			    state == MPI2_RAID_VOL_STATE_FAILED
			    ? "failed" :
			    state == MPI2_RAID_VOL_STATE_MISSING
			    ? "missing" :
			    "state unknown");
			break;
		}
		case MPI2_EVENT_IR_VOLUME_RC_STATUS_FLAGS_CHANGED:
		{
			mpt->m_raidconfig[config].m_raidvol[vol].
			    m_statusflags = state;

			mptsas_log(mpt, CE_NOTE,
			    " Volume %d is now %s%s%s%s%s%s%s%s%s\n",
			    vol,
			    state & MPI2_RAIDVOL0_STATUS_FLAG_ENABLED
			    ? ", enabled" : ", disabled",
			    state & MPI2_RAIDVOL0_STATUS_FLAG_QUIESCED
			    ? ", quiesced" : "",
			    state & MPI2_RAIDVOL0_STATUS_FLAG_VOLUME_INACTIVE
			    ? ", inactive" : ", active",
			    state &
			    MPI2_RAIDVOL0_STATUS_FLAG_BAD_BLOCK_TABLE_FULL
			    ? ", bad block table is full" : "",
			    state &
			    MPI2_RAIDVOL0_STATUS_FLAG_RESYNC_IN_PROGRESS
			    ? ", resync in progress" : "",
			    state & MPI2_RAIDVOL0_STATUS_FLAG_BACKGROUND_INIT
			    ? ", background initialization in progress" : "",
			    state &
			    MPI2_RAIDVOL0_STATUS_FLAG_CAPACITY_EXPANSION
			    ? ", capacity expansion in progress" : "",
			    state &
			    MPI2_RAIDVOL0_STATUS_FLAG_CONSISTENCY_CHECK
			    ? ", consistency check in progress" : "",
			    state & MPI2_RAIDVOL0_STATUS_FLAG_DATA_SCRUB
			    ? ", data scrub in progress" : "");
			break;
		}
		default:
			break;
		}
		break;
	}
	case MPI2_EVENT_IR_PHYSICAL_DISK:
	{
		Mpi2EventDataIrPhysicalDisk_t	*irPhysDisk;
		uint16_t			devhandle, enchandle, slot;
		uint32_t			status, state;
		uint8_t				physdisknum, reason;

		irPhysDisk = (Mpi2EventDataIrPhysicalDisk_t *)
		    eventreply->EventData;
		physdisknum = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &irPhysDisk->PhysDiskNum);
		devhandle = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &irPhysDisk->PhysDiskDevHandle);
		enchandle = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &irPhysDisk->EnclosureHandle);
		slot = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &irPhysDisk->Slot);
		state = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &irPhysDisk->NewValue);
		reason = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &irPhysDisk->ReasonCode);

		NDBG20(("%d: EVENT_IR_PHYSICAL_DISK event is received",
		    mpt->m_instance));

		switch (reason) {
		case MPI2_EVENT_IR_PHYSDISK_RC_SETTINGS_CHANGED:
			mptsas_log(mpt, CE_NOTE,
			    " PhysDiskNum %d with DevHandle 0x%x in slot %d "
			    "for enclosure with handle 0x%x is now in hot "
			    "spare pool %d",
			    physdisknum, devhandle, slot, enchandle,
			    (state >> 16) & 0xff);
			break;

		case MPI2_EVENT_IR_PHYSDISK_RC_STATUS_FLAGS_CHANGED:
			status = state;
			mptsas_log(mpt, CE_NOTE,
			    " PhysDiskNum %d with DevHandle 0x%x in slot %d "
			    "for enclosure with handle 0x%x is now "
			    "%s%s%s%s%s\n", physdisknum, devhandle, slot,
			    enchandle,
			    status & MPI2_PHYSDISK0_STATUS_FLAG_INACTIVE_VOLUME
			    ? ", inactive" : ", active",
			    status & MPI2_PHYSDISK0_STATUS_FLAG_OUT_OF_SYNC
			    ? ", out of sync" : "",
			    status & MPI2_PHYSDISK0_STATUS_FLAG_QUIESCED
			    ? ", quiesced" : "",
			    status &
			    MPI2_PHYSDISK0_STATUS_FLAG_WRITE_CACHE_ENABLED
			    ? ", write cache enabled" : "",
			    status & MPI2_PHYSDISK0_STATUS_FLAG_OCE_TARGET
			    ? ", capacity expansion target" : "");
			break;

		case MPI2_EVENT_IR_PHYSDISK_RC_STATE_CHANGED:
			mptsas_log(mpt, CE_NOTE,
			    " PhysDiskNum %d with DevHandle 0x%x in slot %d "
			    "for enclosure with handle 0x%x is now %s\n",
			    physdisknum, devhandle, slot, enchandle,
			    state == MPI2_RAID_PD_STATE_OPTIMAL
			    ? "optimal" :
			    state == MPI2_RAID_PD_STATE_REBUILDING
			    ? "rebuilding" :
			    state == MPI2_RAID_PD_STATE_DEGRADED
			    ? "degraded" :
			    state == MPI2_RAID_PD_STATE_HOT_SPARE
			    ? "a hot spare" :
			    state == MPI2_RAID_PD_STATE_ONLINE
			    ? "online" :
			    state == MPI2_RAID_PD_STATE_OFFLINE
			    ? "offline" :
			    state == MPI2_RAID_PD_STATE_NOT_COMPATIBLE
			    ? "not compatible" :
			    state == MPI2_RAID_PD_STATE_NOT_CONFIGURED
			    ? "not configured" :
			    "state unknown");
			break;
		}
		break;
	}
	case MPI2_EVENT_ACTIVE_CABLE_EXCEPTION:
	{
		pMpi26EventDataActiveCableExcept_t	actcable;
		uint32_t power;
		uint8_t reason, id;

		actcable = (pMpi26EventDataActiveCableExcept_t)
		    eventreply->EventData;
		power = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &actcable->ActiveCablePowerRequirement);
		reason = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &actcable->ReasonCode);
		id = ddi_get8(mpt->m_acc_reply_frame_hdl,
		    &actcable->ReceptacleID);

		/*
		 * It'd be nice if this weren't just logging to the system but
		 * were telling FMA about the active cable problem and FMA was
		 * aware of the cable topology and state.
		 */
		switch (reason) {
		case MPI26_EVENT_ACTIVE_CABLE_PRESENT:
			/* Don't log anything if it's fine */
			break;
		case MPI26_EVENT_ACTIVE_CABLE_INSUFFICIENT_POWER:
			mptsas_log(mpt, CE_WARN, "An active cable (id %u) does "
			    "not have sufficient power to be enabled. "
			    "Devices connected to this cable will not be "
			    "visible to the system.", id);
			if (power == UINT32_MAX) {
				mptsas_log(mpt, CE_CONT, "The cable's power "
				    "requirements are unknown.\n");
			} else {
				mptsas_log(mpt, CE_CONT, "The cable requires "
				    "%u mW of power to function.\n", power);
			}
			break;
		case MPI26_EVENT_ACTIVE_CABLE_DEGRADED:
			mptsas_log(mpt, CE_WARN, "An active cable (id %u) is "
			    "degraded and not running at its full speed. "
			    "Some devices might not appear.", id);
			break;
		default:
			break;
		}
		break;
	}
	case MPI2_EVENT_PCIE_DEVICE_STATUS_CHANGE:
	case MPI2_EVENT_PCIE_ENUMERATION:
	case MPI2_EVENT_PCIE_TOPOLOGY_CHANGE_LIST:
	case MPI2_EVENT_PCIE_LINK_COUNTER:
		mptsas_log(mpt, CE_NOTE, "Unhandled mpt_sas PCIe device "
		    "event received (0x%x)", event);
		break;
	default:
		NDBG20(("%d: unknown event %x received",
		    mpt->m_instance, event));
		break;
	}

	/* Zero out our slot for this frame. */
	replyh_arg->rfm = 0;
	replyh_arg->mpt = NULL;

	/*
	 * Return the reply frame to the free queue.
	 */
	mptsas_return_replyframe(mpt, rfm);
	mutex_exit(&mpt->m_mutex);
}

/*
 * invoked from timeout() to restart qfull cmds with throttle == 0
 */
static void
mptsas_restart_cmd(void *arg)
{
	mptsas_t	*mpt = arg;
	mptsas_target_t	*ptgt = NULL;

	mutex_enter(&mpt->m_mutex);

	mpt->m_restart_cmd_timeid = 0;

	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mutex_enter(&ptgt->m_t_mutex);
		if (ptgt->m_reset_delay == 0) {
			if (ptgt->m_t_throttle == QFULL_THROTTLE) {
				mptsas_set_throttle(mpt, ptgt, MAX_THROTTLE);
				mptsas_restart_twaitq(mpt, ptgt);
			}
		}
		mutex_exit(&ptgt->m_t_mutex);
	}
	mutex_exit(&mpt->m_mutex);
}

mptsas_cmd_t *
mptsas_secure_cmd_from_slots(mptsas_slots_t *slots, uint16_t slot)
{
	mptsas_cmd_t	*slcmd;

	slcmd = atomic_swap_ptr(&slots->m_slot[slot], NULL);
	if (slcmd != NULL) {
		/* A little history for debug purposes */
		slcmd->cmd_oslot = (uint16_t)slcmd->cmd_slot;
		slcmd->cmd_slot = 0;
	}
	return (slcmd);
}

/*
 * Assume some checks have been done prior to calling this
 * function so we don't need to consider taking the m_mutex.
 *
 * Both versions assume this is the only thread handling the command so
 * the pointer needs to have been isolated from the slot array using
 * mptsas_secure_cmd_from_slots() prior to calling these.
 */
static void
mptsas_deref_tgtcmd(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	mptsas_target_t	*ptgt = cmd->cmd_tgt_addr;

	ASSERT(cmd != NULL);
	ASSERT(cmd->cmd_queued == CQ_NOTQUEUED);
	ASSERT((cmd->cmd_flags & (CFLAG_CMDIOC | CFLAG_TM_CMD)) == 0);
	ASSERT(mutex_owned(&ptgt->m_t_mutex));

	NDBG1(("%d: deref_tgtcmd: cmd=0x%p, flags "
	    "0x%x", mpt->m_instance, (void *)cmd, cmd->cmd_flags));
	ASSERT(mpt->m_ncmds != 0);
	atomic_dec_32(&mpt->m_ncmds);
	ASSERT(mpt->m_rep_post_queues[cmd->cmd_rpqidx].rpq_ncmds != 0);
	atomic_dec_32(
	    &mpt->m_rep_post_queues[cmd->cmd_rpqidx].rpq_ncmds);

	/*
	 * Decrement per target ncmds, we know this is not an
	 * IOC cmd and it therefore has a target associated with it.
	 */
	ASSERT(ptgt->m_t_ncmds != 0);
	ptgt->m_t_ncmds--;

	/*
	 * reset throttle if we just ran an untagged command
	 * to a tagged target.
	 * Note that we could be called as a result of a timeout so
	 * also check if held.
	 */
	if ((ptgt->m_t_ncmds == 0) &&
	    ((cmd->cmd_pkt_flags & FLAG_TAGMASK) == 0) &&
	    (ptgt->m_t_throttle > HOLD_THROTTLE)) {
		mptsas_set_throttle(mpt, ptgt, MAX_THROTTLE);
	}

	/*
	 * Remove this command from the active queue.
	 */
	if (cmd->cmd_active_expiration != 0) {
		TAILQ_REMOVE(&ptgt->m_active_cmdq, cmd,
		    cmd_active_link);
		cmd->cmd_active_expiration = 0;
	}
}

void
mptsas_deref_ioccmd(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	ASSERT(cmd != NULL);
	ASSERT(cmd->cmd_queued == CQ_NOTQUEUED);
	ASSERT(cmd->cmd_flags & CFLAG_CMDIOC);
	ASSERT((cmd->cmd_flags & CFLAG_TM_CMD) == 0);
	ASSERT(mutex_owned(&mpt->m_mutex));

	NDBG1(("%d: deref_ioccmd: cmd=0x%p, flags 0x%x",
	    mpt->m_instance, (void *)cmd, cmd->cmd_flags));
	ASSERT(mpt->m_ncmds != 0);
	atomic_dec_32(&mpt->m_ncmds);
	ASSERT(mpt->m_rep_post_queues[cmd->cmd_rpqidx].rpq_ncmds != 0);
	atomic_dec_32(
	    &mpt->m_rep_post_queues[cmd->cmd_rpqidx].rpq_ncmds);

	/*
	 * Remove this command from the active queue.
	 */
	if (cmd->cmd_active_expiration != 0) {
		TAILQ_REMOVE(&mpt->m_active_ioccmdq, cmd, cmd_active_link);
		cmd->cmd_active_expiration = 0;
		ASSERT(mpt->m_nioccmds > 0);
		mpt->m_nioccmds--;
	}
}

static void
mptsas_deref_cmd(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	ASSERT(cmd != NULL);
	ASSERT(cmd->cmd_queued == CQ_NOTQUEUED);

	/*
	 * Task Management cmds are removed in their own routines.  Also,
	 * we don't want to modify timeout based on TM cmds.
	 */
	if (cmd->cmd_flags & CFLAG_TM_CMD) {
		return;
	}

	if (cmd->cmd_flags & CFLAG_CMDIOC) {
		mptsas_deref_ioccmd(mpt, cmd);
	} else {
		mutex_enter(&cmd->cmd_tgt_addr->m_t_mutex);
		mptsas_deref_tgtcmd(mpt, cmd);
		mutex_exit(&cmd->cmd_tgt_addr->m_t_mutex);
	}
}

/*
 * accept all cmds on the waitq if any and then
 * start a fresh request from the top of the device queue.
 */
static void
mptsas_restart_hba(mptsas_t *mpt)
{
	ASSERT(mutex_owned(&mpt->m_mutex));

	mptsas_restart_waitq(mpt);
}

/* Restart a specific target. */
static void
mptsas_restart_twaitq(mptsas_t *mpt, mptsas_target_t *ptgt)
{
	mptsas_cmd_t	*cmd, *next_cmd;
#ifdef MPTSAS_DEBUG
	int		throt_exceeded = 0, failedsave = 0;

	NDBG7(("%d: restart_twaitq: targ %d, twqlen %d",
	    mpt->m_instance, ptgt->m_devhdl, ptgt->m_t_wait.cl_len));
#endif

	if ((ptgt->m_t_throttle == DRAIN_THROTTLE) && (ptgt->m_t_ncmds == 0)) {
		mptsas_set_throttle(mpt, ptgt, MAX_THROTTLE);
	}

	cmd = STAILQ_FIRST(&ptgt->m_t_wait.cl_q);
	while (cmd != NULL) {
		ASSERT(cmd->cmd_tgt_addr == ptgt);
		next_cmd = STAILQ_NEXT(cmd, cmd_link);

		if (ptgt->m_t_ncmds < ptgt->m_t_throttle) {
			mptsas_targwaitq_delete(mpt, ptgt, cmd);

			if (mptsas_save_cmd_to_slot(mpt, cmd) == TRUE) {
				ptgt->m_t_ncmds++;
				cmd->cmd_active_expiration = 0;
				(void) mptsas_start_cmd(mpt, cmd);
				mutex_enter(&ptgt->m_t_mutex);
				next_cmd = STAILQ_FIRST(&ptgt->m_t_wait.cl_q);
			} else {
				mptsas_targwaitq_add(mpt, ptgt, cmd);
#ifdef MPTSAS_DEBUG
				failedsave++;
#endif
			}
		} else {
#ifdef MPTSAS_DEBUG
			throt_exceeded++;
#endif
		}
		cmd = next_cmd;
	}

#ifdef MPTSAS_DEBUG
	if (ptgt->m_t_wait.cl_len != 0) {
		NDBG7(("%d: restart_twaitq: targ %d, twqlen %d, fail "
		    "save %d, throttle exceeded %d", mpt->m_instance,
		    ptgt->m_devhdl, ptgt->m_t_wait.cl_len, failedsave,
		    throt_exceeded));
	}
#endif
}

/*
 * Try to start all requests queued on any waitq's.
 */
static void
mptsas_restart_waitq(mptsas_t *mpt)
{
	mptsas_cmd_t	*cmd, *next_cmd;
	mptsas_target_t *ptgt = NULL;
#ifdef MPTSAS_DEBUG
	int		inreset = 0;
#endif

	NDBG7(("%d: restart_waitq: iocwqlen %d, targwqlen %d",
	    mpt->m_instance, mpt->m_wait.cl_len, mpt->m_ntwait));

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * If there is a reset delay, don't start any cmds.  Otherwise, start
	 * as many cmds as possible.
	 */
	cmd = STAILQ_FIRST(&mpt->m_wait.cl_q);

	while (cmd != NULL) {
		next_cmd = STAILQ_NEXT(cmd, cmd_link);
		if (cmd->cmd_flags & CFLAG_PASSTHRU) {
			if (mptsas_save_ioccmd(mpt, cmd) == TRUE) {
				/*
				 * passthru command get slot need
				 * set CFLAG_PREPARED.
				 */
				cmd->cmd_flags |= CFLAG_PREPARED;
				mptsas_waitq_delete(mpt, cmd);
				mptsas_start_passthru(mpt, cmd);
			}
			cmd = next_cmd;
			continue;
		}
		if (cmd->cmd_flags & CFLAG_CONFIG) {
			if (mptsas_save_ioccmd(mpt, cmd) == TRUE) {
				/*
				 * Send the config page request and delete it
				 * from the waitq.
				 */
				cmd->cmd_flags |= CFLAG_PREPARED;
				mptsas_waitq_delete(mpt, cmd);
				mptsas_start_config_page_access(mpt, cmd);
			}
			cmd = next_cmd;
			continue;
		}
		if (cmd->cmd_flags & CFLAG_FW_DIAG) {
			if (mptsas_save_ioccmd(mpt, cmd) == TRUE) {
				/*
				 * Send the FW Diag request and delete if from
				 * the waitq.
				 */
				cmd->cmd_flags |= CFLAG_PREPARED;
				mptsas_waitq_delete(mpt, cmd);
				mptsas_start_diag(mpt, cmd);
			}
			cmd = next_cmd;
			continue;
		}
		cmd = next_cmd;
	}

	/*
	 * For targets, if there is a reset delay, don't start any cmds.
	 * Otherwise, start as many cmds as possible.
	 */
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		if (ptgt->m_t_wait.cl_len != 0) {
			mutex_enter(&ptgt->m_t_mutex);
			if (ptgt->m_reset_delay == 0 &&
			    ptgt->m_t_throttle != HOLD_THROTTLE) {
				mptsas_restart_twaitq(mpt, ptgt);
			}
#ifdef MPTSAS_DEBUG
			else {
				inreset++;
			}
#endif
			mutex_exit(&ptgt->m_t_mutex);
		}
	}

#ifdef MPTSAS_DEBUG
	if (mpt->m_wait.cl_len != 0 || mpt->m_ntwait != 0) {
		NDBG7(("%d: restart_waitq: iocwqlen %d, targwqlen %d, "
		    "inreset/held %d", mpt->m_instance, mpt->m_wait.cl_len,
		    mpt->m_ntwait, inreset));
	}
#endif
}

/*
 * mpt tag type lookup
 */
static char mptsas_tag_lookup[] =
	{0, MSG_HEAD_QTAG, MSG_ORDERED_QTAG, 0, MSG_SIMPLE_QTAG};

/*
 * mptsas_start_cmd() is called with the target mutex held.
 * Need to release it before returning.
 */
static int
mptsas_start_cmd(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	struct scsi_pkt		*pkt = CMD2PKT(cmd);
	uint32_t		control = 0;
	caddr_t			mem, arsbuf;
	pMpi2SCSIIORequest_t	io_request;
	ddi_dma_handle_t	dma_hdl = mpt->m_dma_req_frame_hdl;
	ddi_acc_handle_t	acc_hdl = mpt->m_acc_req_frame_hdl;
	mptsas_target_t		*ptgt = cmd->cmd_tgt_addr;
	uint16_t		SMID, io_flags = 0, devhdl;
	uint8_t			MSIidx, ars_size;
	uint64_t		request_desc;
	uint32_t		ars_dmaaddrlow;
	boolean_t		use_fastpath;

	NDBG1(("%d: start_cmd: cmd=0x%p(0x%02x), flags 0x%x",
	    mpt->m_instance, (void *)cmd, cmd->cmd_cdb[0], cmd->cmd_flags));

	/*
	 * Get SMID and MSI index.
	 */
	SMID = cmd->cmd_slot;
	MSIidx = cmd->cmd_rpqidx;

	ASSERT((cmd->cmd_flags & CFLAG_TM_CMD) == 0);

	/*
	 * It is possible for back to back device reset to
	 * happen before the reset delay has expired.  That's
	 * ok, just let the device reset go out on the bus.
	 */
	if ((cmd->cmd_pkt_flags & FLAG_NOINTR) == 0) {
		ASSERT(ptgt->m_reset_delay == 0);
	}

	/*
	 * If a non-tagged cmd is submitted to an active tagged target
	 * then drain before submitting this cmd; SCSI-2 allows RQSENSE
	 * to be untagged
	 */
	if (((cmd->cmd_pkt_flags & FLAG_TAGMASK) == 0) &&
	    (ptgt->m_t_ncmds > 1) &&
	    (*(cmd->cmd_pkt->pkt_cdbp) != SCMD_REQUEST_SENSE)) {
		if ((cmd->cmd_pkt_flags & FLAG_NOINTR) == 0) {
			/*LINTED [E_FUNC_SET_NOT_USED]*/
			mptsas_cmd_t *slcmd;

			NDBG23(("%d: target=%d, untagged cmd, start draining\n",
			    mpt->m_instance, ptgt->m_devhdl));

			if (ptgt->m_reset_delay == 0) {
				mptsas_set_throttle(mpt, ptgt, DRAIN_THROTTLE);
			}

			slcmd = mptsas_secure_cmd_from_slots(mpt->m_active,
			    cmd->cmd_slot);
			ASSERT(slcmd == cmd);
			mptsas_deref_tgtcmd(mpt, cmd);
			cmd->cmd_pkt_flags |= FLAG_HEAD;
			mptsas_targwaitq_add(mpt, ptgt, cmd);
		}
		mutex_exit(&ptgt->m_t_mutex);
		return (DDI_FAILURE);
	}

	/*
	 * Set correct tag bits.
	 */
	if (cmd->cmd_pkt_flags & FLAG_TAGMASK) {
		switch (mptsas_tag_lookup[((cmd->cmd_pkt_flags &
		    FLAG_TAGMASK) >> 12)]) {
		case MSG_SIMPLE_QTAG:
			control |= MPI2_SCSIIO_CONTROL_SIMPLEQ;
			break;
		case MSG_HEAD_QTAG:
			control |= MPI2_SCSIIO_CONTROL_HEADOFQ;
			break;
		case MSG_ORDERED_QTAG:
			control |= MPI2_SCSIIO_CONTROL_ORDEREDQ;
			break;
		default:
			mptsas_log(mpt, CE_WARN, "mpt: Invalid tag type\n");
			break;
		}
	} else {
		if (*(cmd->cmd_pkt->pkt_cdbp) != SCMD_REQUEST_SENSE) {
			if (ptgt->m_t_throttle != 1) {
				NDBG27(("%d: NonTagd, targ %d - Set Throttle "
				    "%d -> 1", mpt->m_instance, ptgt->m_devhdl,
				    ptgt->m_t_throttle));
				ptgt->m_t_throttle = 1;
			}
		}
		control |= MPI2_SCSIIO_CONTROL_SIMPLEQ;
	}

	/*
	 * Set timeout. Although we have a few things to do before
	 * the command actually gets kicked off we are not going
	 * to fail now and setting the time here means we don't need
	 * to hold the target mutex or let go and then grab it again
	 * nearer the MPTSAS_START_CMD() call below.
	 */
	pkt->pkt_start = gethrtime();
	cmd->cmd_active_expiration =
	    pkt->pkt_start + (hrtime_t)pkt->pkt_time * (hrtime_t)NANOSEC;

	mptsas_insert_expiration(&ptgt->m_active_cmdq, cmd);
	devhdl = ptgt->m_devhdl;
	use_fastpath = (mptsas3_use_fastpath &&
	    ptgt->m_io_flags & MPI25_SAS_DEVICE0_FLAGS_ENABLED_FAST_PATH);
	mutex_exit(&ptgt->m_t_mutex);

	if (cmd->cmd_pkt_flags & FLAG_TLR) {
		control |= MPI2_SCSIIO_CONTROL_TLR_ON;
	}

	mem = mpt->m_req_frame + (mpt->m_req_frame_size * SMID);
	io_request = (pMpi2SCSIIORequest_t)mem;
	if (cmd->cmd_extrqslen != 0) {
		/*
		 * Mapping of the buffer index was done in
		 * mptsas_pkt_alloc_extern().
		 * Calculate the actual memomory address and
		 * DMA address with the same offset.
		 */
		arsbuf = mpt->m_extreq_sense +
		    (cmd->cmd_extrqsidx * mpt->m_req_sense_size);
		ars_size = cmd->cmd_extrqslen;
		ars_dmaaddrlow = (mpt->m_req_sense_dma_addr +
		    ((uintptr_t)arsbuf - (uintptr_t)mpt->m_req_sense)) &
		    0xffffffffull;
	} else {
		arsbuf = mpt->m_req_sense + (mpt->m_req_sense_size * (SMID-1));
		ars_size = mpt->m_req_sense_size;
		ars_dmaaddrlow = (mpt->m_req_sense_dma_addr +
		    (mpt->m_req_sense_size * (SMID-1))) &
		    0xffffffffull;
	}
	cmd->cmd_arq_buf = arsbuf;
	bzero(io_request, sizeof (Mpi2SCSIIORequest_t));
	bzero(arsbuf, ars_size);

	ddi_put8(acc_hdl, &io_request->SGLOffset0, offsetof
	    (MPI2_SCSI_IO_REQUEST, SGL) / 4);
	mptsas_init_std_hdr(acc_hdl, io_request, devhdl, Lun(cmd), 0,
	    MPI2_FUNCTION_SCSI_IO_REQUEST);

	(void) ddi_rep_put8(acc_hdl, (uint8_t *)pkt->pkt_cdbp,
	    io_request->CDB.CDB32, cmd->cmd_cdblen, DDI_DEV_AUTOINCR);

	io_flags = cmd->cmd_cdblen;
	if (use_fastpath) {
		io_flags |= MPI25_SCSIIO_IOFLAGS_FAST_PATH;
		request_desc = MPI25_REQ_DESCRIPT_FLAGS_FAST_PATH_SCSI_IO;
	} else {
		request_desc = MPI2_REQ_DESCRIPT_FLAGS_SCSI_IO;
	}
	ddi_put16(acc_hdl, &io_request->IoFlags, io_flags);

	/*
	 * setup the Scatter/Gather DMA list for this request
	 */
	if (cmd->cmd_cookiec > 0) {
		mptsas_sge_setup(mpt, cmd, &control, io_request, acc_hdl);
	} else {
		ddi_put32(acc_hdl, &io_request->SGL.MpiSimple.FlagsLength,
		    ((uint32_t)MPI2_SGE_FLAGS_LAST_ELEMENT |
		    MPI2_SGE_FLAGS_END_OF_BUFFER |
		    MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
		    MPI2_SGE_FLAGS_END_OF_LIST) << MPI2_SGE_FLAGS_SHIFT);
	}

	/*
	 * save ARQ information
	 */
	ddi_put8(acc_hdl, &io_request->SenseBufferLength, ars_size);
	ddi_put32(acc_hdl, &io_request->SenseBufferLowAddress, ars_dmaaddrlow);

	ddi_put32(acc_hdl, &io_request->Control, control);

	NDBG1(("%d: starting message=%d(0x%p), with cmd=0x%p",
	    mpt->m_instance, SMID, (void *)io_request, (void *)cmd));

	(void) ddi_dma_sync(dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);
	(void) ddi_dma_sync(mpt->m_dma_req_sense_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Build request descriptor and write it to the request desc post reg.
	 */
	request_desc |= (SMID << 16) + (MSIidx << 8);
	request_desc |= ((uint64_t)devhdl << 48);
	MPTSAS_START_CMD(mpt, request_desc);

#if 0
	/* Is this of any benefit here, what is it going to catch? */
	if ((mptsas_check_dma_handle(dma_hdl) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(acc_hdl) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		return (DDI_FAILURE);
	}
#endif
	return (DDI_SUCCESS);
}

/*
 * Select a helper thread to handle given doneq.
 * Note that we don't require to have the main m_mutex here, but worst case
 * is that we wont follow the thread rotation to the letter.
 * However must ensure we have the mutex that covers the source dlist when
 * we actually hand off.
 */
static void
mptsas_deliver_doneq_thread(mptsas_t *mpt, mptsas_cmd_list_t *dlist)
{
	uint32_t			t, i, j = mpt->m_doneq_next_thread;
	uint32_t			min = 0xffffffff;
	mptsas_doneq_thread_list_t	*item;

	/*
	 * No need to take indivudual list mutex's during the loop.
	 * We are only reading values and the worst that will happen is that
	 * we pick the wrong thread.
	 */
	for (i = 0; i < mpt->m_doneq_thread_n; i++) {
		item = &mpt->m_doneq_thread_id[j];

		/*
		 * If the completed command on help thread[i] less than
		 * doneq_thread_threshold, then pick the thread[j]. Otherwise
		 * pick a thread which has least completed command.
		 */
		if (item->done.cl_len < mpt->m_doneq_thread_threshold) {
			t = j;
			break;
		}
		if (item->done.cl_len < min) {
			min = item->done.cl_len;
			t = j;
		}
		if (++j == mpt->m_doneq_thread_n) {
			j = 0;
		}
	}
	item = &mpt->m_doneq_thread_id[t];
	mutex_enter(&item->mutex);
	mptsas_doneq_mv(dlist, item);
	cv_signal(&item->cv);
	mutex_exit(&item->mutex);

	/*
	 * Next time start at the next thread.
	 * This will minimize the potential of grabing a lock
	 * for a thread that is busy, either on a very busy systems
	 * or on one that is configured to do all command completion
	 * processing through threads.
	 */
	if (++t == mpt->m_doneq_thread_n) {
		t = 0;
	}
	mpt->m_doneq_next_thread = (uint16_t)t;
}

/*
 * Move one doneq to another.
 * There is no STAILQ definition for this, have to it ourselves.
 */
static void
mptsas_doneq_mv(mptsas_cmd_list_t *from, mptsas_doneq_thread_list_t *item)
{
	mptsas_cmd_list_t		*to = &item->done;
	mptsas_cmd_t			*cmd;

	if ((cmd = STAILQ_FIRST(&from->cl_q)) != NULL) {
		*to->cl_q.stqh_last = cmd;
		to->cl_q.stqh_last = from->cl_q.stqh_last;
		to->cl_len += from->cl_len;
		STAILQ_INIT(&from->cl_q);
		from->cl_len = 0;
	}
}

void
mptsas_fma_check(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);

	/* Check all acc and dma handles */
	if ((mptsas_check_acc_handle(mpt->m_datap) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_req_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_req_sense_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_reply_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_free_queue_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_post_queue_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_hshk_acc_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_config_handle) !=
	    DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip,
		    DDI_SERVICE_UNAFFECTED);
		ddi_fm_acc_err_clear(mpt->m_config_handle,
		    DDI_FME_VER0);
		mptsas_set_pkt_reason(mpt, cmd, CMD_TRAN_ERR, 0);
		pkt->pkt_statistics = 0;
	}
	if ((mptsas_check_dma_handle(mpt->m_dma_req_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_req_sense_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_reply_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_free_queue_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_post_queue_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_hshk_dma_hdl) !=
	    DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip,
		    DDI_SERVICE_UNAFFECTED);
		mptsas_set_pkt_reason(mpt, cmd, CMD_TRAN_ERR, 0);
		pkt->pkt_statistics = 0;
	}
	if (cmd->cmd_dmahandle &&
	    (mptsas_check_dma_handle(cmd->cmd_dmahandle) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		mptsas_set_pkt_reason(mpt, cmd, CMD_TRAN_ERR, 0);
		pkt->pkt_statistics = 0;
	}
	if ((cmd->cmd_extra_frames &&
	    ((mptsas_check_dma_handle(cmd->cmd_extra_frames->m_dma_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(cmd->cmd_extra_frames->m_acc_hdl) !=
	    DDI_SUCCESS)))) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		mptsas_set_pkt_reason(mpt, cmd, CMD_TRAN_ERR, 0);
		pkt->pkt_statistics = 0;
	}
}

/*
 * These routines manipulate the queue of commands that
 * are waiting for their completion routines to be called.
 * The queue is usually in FIFO order but on an MP system
 * it's possible for the completion routines to get out
 * of order. If that's a problem you need to add a global
 * mutex around the code that calls the completion routine
 * in the interrupt handler.
 */
static void
mptsas_doneq_add(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);

	NDBG1(("%d: doneq_add: cmd=0x%p", mpt->m_instance, (void *)cmd));

	ASSERT((cmd->cmd_flags & CFLAG_COMPLETED) == 0);
	ASSERT(STAILQ_NEXT(cmd, cmd_link) == NULL);

	cmd->cmd_flags |= CFLAG_FINISHED;
	cmd->cmd_flags &= ~CFLAG_IN_TRANSPORT;

	mptsas_fma_check(mpt, cmd);

	/*
	 * Only add scsi pkts that have completion routines and are
	 * not polled to the doneq. All interrupting cmds have callbacks.
	 */
	if (pkt != NULL && pkt->pkt_comp != NULL &&
	    (cmd->cmd_pkt_flags & FLAG_NOINTR) == 0) {
		STAILQ_INSERT_TAIL(&mpt->m_done.cl_q, cmd, cmd_link);
		mpt->m_done.cl_len++;
	}
}

static void
mptsas_rpdoneq_add(mptsas_t *mpt, mptsas_reply_pqueue_t *rpqp,
    mptsas_cmd_t *cmd)
{
	struct scsi_pkt		*pkt = CMD2PKT(cmd);
	mptsas_cmd_list_t	*dlist;

	NDBG1(("%d: rpdoneq_add: cmd=0x%p", mpt->m_instance,
	    (void *)cmd));

	ASSERT((cmd->cmd_flags & CFLAG_COMPLETED) == 0);
	ASSERT(STAILQ_NEXT(cmd, cmd_link) == NULL);

	cmd->cmd_flags |= CFLAG_FINISHED;
	cmd->cmd_flags &= ~CFLAG_IN_TRANSPORT;

	mptsas_fma_check(mpt, cmd);

	if (cmd->cmd_flags & CFLAG_CPUONREPQ)
		dlist = &rpqp->rpq_idone;
	else
		dlist = &rpqp->rpq_done;

	/*
	 * Only add scsi pkts that have completion routines and are
	 * not polled to the doneq. All interrupting cmds have callbacks.
	 */
	if (pkt != NULL && pkt->pkt_comp != NULL &&
	    (cmd->cmd_pkt_flags & FLAG_NOINTR) == 0) {
		STAILQ_INSERT_TAIL(&dlist->cl_q, cmd, cmd_link);
		dlist->cl_len++;
	}
}

static void
mptsas_doneq_empty(mptsas_t *mpt)
{
	mptsas_cmd_t	*cmd, *next;

	NDBG1(("%d: doneq_empty: len=0x%d", mpt->m_instance,
	    mpt->m_done.cl_len));
	cmd = STAILQ_FIRST(&mpt->m_done.cl_q);
	if (cmd != NULL) {
		STAILQ_INIT(&mpt->m_done.cl_q);
		mpt->m_done.cl_len = 0;

		mutex_exit(&mpt->m_mutex);
		/*
		 * run the completion routines of all the
		 * completed commands
		 */
		while (cmd != NULL) {
			next = STAILQ_NEXT(cmd, cmd_link);
			STAILQ_NEXT(cmd, cmd_link) = NULL;
			/* run this command's completion routine */
			mptsas_pkt_comp(cmd);
			cmd = next;
		}
		mutex_enter(&mpt->m_mutex);
	}
}

/*
 * Expects the replyq mutex to be held and has a side effect of dropping
 * the mutex to avoid the situation (in the hot performance path)
 * where it's re-acquired here only to be dropped on return from this
 * function.
 * Look at 2 queues, the first consists of commands that were identified
 * as being submitted on the same CPU that is servicing this interrupt.
 * To allow the cache coherency optimization to work we need to service
 * those here. The second queue can be punted to the threads if we are
 * under load.
 */
static void
mptsas_rpdoneq_empty(mptsas_t *mpt, mptsas_reply_pqueue_t *rpqp, boolean_t all)
{
	mptsas_cmd_t		*cmd = NULL, *icmd, *next;
	mptsas_cmd_list_t	*dl;
	int			totdlen;

	dl = &rpqp->rpq_idone;

	NDBG1(("%d: rpdoneq_empty(%d): ilen=%d, len=%d",
	    mpt->m_instance, rpqp->rpq_num, dl->cl_len, rpqp->rpq_done.cl_len));

	icmd = STAILQ_FIRST(&dl->cl_q);
	totdlen = dl->cl_len;
	if (icmd != NULL) {
		STAILQ_INIT(&dl->cl_q);
		dl->cl_len = 0;
	}

	dl = &rpqp->rpq_done;
	totdlen += dl->cl_len;
	if (totdlen <= mpt->m_doneq_length_threshold || all ||
	    !mpt->m_doneq_thread_n) {
		cmd = STAILQ_FIRST(&dl->cl_q);
		if (cmd != NULL) {
			STAILQ_INIT(&dl->cl_q);
			dl->cl_len = 0;
		}

	} else if (dl->cl_len != 0) {
		mptsas_deliver_doneq_thread(mpt, dl);
	}
	mutex_exit(&rpqp->rpq_mutex);

	/*
	 * Run the completion routines of all the completed commands we found.
	 */
	while (icmd != NULL) {
		next = STAILQ_NEXT(icmd, cmd_link);
		STAILQ_NEXT(icmd, cmd_link) = NULL;
		/* run this command's completion routine */
		mptsas_pkt_comp(icmd);
		icmd = next;
	}
	while (cmd != NULL) {
		next = STAILQ_NEXT(cmd, cmd_link);
		STAILQ_NEXT(cmd, cmd_link) = NULL;
		/* run this command's completion routine */
		mptsas_pkt_comp(cmd);
		cmd = next;
	}
}

/*
 * Empty the doneq's that might have been posted to during a poll.
 * This is really just repyq 0 and the main reply queue
 */
void
mptsas_doneq_apempty(mptsas_t *mpt)
{
	mptsas_reply_pqueue_t *rpqp = mpt->m_rep_post_queues;
	ASSERT(mutex_owned(&mpt->m_mutex));

	mutex_exit(&mpt->m_mutex);
	mutex_enter(&rpqp->rpq_mutex);
	mptsas_rpdoneq_empty(mpt, rpqp, B_TRUE);
	mutex_enter(&mpt->m_mutex);
	mptsas_doneq_empty(mpt);
}

/*
 * These routines manipulate the queue of pending IOC requests
 */
void
mptsas_waitq_add(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	NDBG7(("%d: waitq_add: cmd=0x%p", mpt->m_instance, (void *)cmd));

	cmd->cmd_queued = CQ_MAIN;
	mpt->m_wait.cl_len++;
	if (cmd->cmd_pkt_flags & FLAG_HEAD) {
		STAILQ_INSERT_HEAD(&mpt->m_wait.cl_q, cmd, cmd_link);
	} else {
		STAILQ_INSERT_TAIL(&mpt->m_wait.cl_q, cmd, cmd_link);
	}
}

static mptsas_cmd_t *
mptsas_waitq_rm(mptsas_t *mpt)
{
	mptsas_cmd_t	*cmd;

	ASSERT(mutex_owned(&mpt->m_mutex));

	cmd = STAILQ_FIRST(&mpt->m_wait.cl_q);

	NDBG7(("%d: waitq_rm: cmd=0x%p", mpt->m_instance, (void *)cmd));
	if (cmd) {
		ASSERT(cmd->cmd_queued == CQ_MAIN);
		STAILQ_REMOVE_HEAD(&mpt->m_wait.cl_q, cmd_link);
		STAILQ_NEXT(cmd, cmd_link) = NULL;
		ASSERT(mpt->m_wait.cl_len != 0);
		mpt->m_wait.cl_len--;
		cmd->cmd_queued = CQ_NOTQUEUED;
	}
	return (cmd);
}

/*
 * remove specified cmd from the middle of the wait queue.
 */
static void
mptsas_waitq_delete(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	ASSERT(mutex_owned(&mpt->m_mutex));
	ASSERT(cmd->cmd_queued == CQ_MAIN);

	NDBG7(("%d: waitq_delete: cmd=0x%p", mpt->m_instance,
	    (void *)cmd));

	ASSERT(mpt->m_wait.cl_len != 0);
	mpt->m_wait.cl_len--;
	cmd->cmd_queued = CQ_NOTQUEUED;

	STAILQ_REMOVE(&mpt->m_wait.cl_q, cmd, mptsas_cmd, cmd_link);
	STAILQ_NEXT(cmd, cmd_link) = NULL;
}

/*
 * These routines manipulate the queue of pending target requests
 */
static void
mptsas_targwaitq_add(mptsas_t *mpt, mptsas_target_t *ptgt, mptsas_cmd_t *cmd)
{
	NDBG7(("%d: targwaitq_add: targ %d ncmds %d, cmd=0x%p",
	    mpt->m_instance, ptgt->m_devhdl, ptgt->m_t_ncmds, (void *)cmd));
	ASSERT(mutex_owned(&ptgt->m_t_mutex));

	cmd->cmd_queued = CQ_TARGET;
	ptgt->m_t_wait.cl_len++;
	atomic_inc_16(&mpt->m_ntwait);
	if (cmd->cmd_pkt_flags & FLAG_HEAD) {
		STAILQ_INSERT_HEAD(&ptgt->m_t_wait.cl_q, cmd, cmd_link);
	} else {
		STAILQ_INSERT_TAIL(&ptgt->m_t_wait.cl_q, cmd, cmd_link);
	}
}

/*
 * remove specified cmd from the middle of the wait queue.
 */
static void
mptsas_targwaitq_delete(mptsas_t *mpt, mptsas_target_t *ptgt,
    mptsas_cmd_t *cmd)
{
	ASSERT(ptgt == cmd->cmd_tgt_addr);
	ASSERT(mutex_owned(&ptgt->m_t_mutex));
	ASSERT(cmd->cmd_queued == CQ_TARGET);

	NDBG7(("%d: targwaitq_delete: targ %d cmd=0x%p",
	    mpt->m_instance, ptgt->m_devhdl, (void *)cmd));

	atomic_dec_16(&mpt->m_ntwait);
	ASSERT(ptgt->m_t_wait.cl_len != 0);
	ptgt->m_t_wait.cl_len--;
	cmd->cmd_queued = CQ_NOTQUEUED;

	STAILQ_REMOVE(&ptgt->m_t_wait.cl_q, cmd, mptsas_cmd, cmd_link);
	STAILQ_NEXT(cmd, cmd_link) = NULL;
}

/*
 * device and bus reset handling
 *
 * Notes:
 *	- RESET_ALL:	reset the controller
 *	- RESET_TARGET:	reset the target specified in scsi_address
 */
static int
mptsas_scsi_reset(struct scsi_address *ap, int level)
{
	mptsas_t		*mpt = ADDR2MPT(ap);
	int			rval = FALSE;
	mptsas_tgt_private_t	*tgt_private;
	mptsas_target_t		*ptgt = NULL;


	mutex_enter(&mpt->m_mutex);
	if ((level == RESET_TARGET) || (level == RESET_LUN)) {

		tgt_private = (mptsas_tgt_private_t *)
		    ap->a_hba_tran->tran_tgt_private;
		ptgt = tgt_private->t_private;
		if (ptgt == NULL) {
			mutex_exit(&mpt->m_mutex);
			return (FALSE);
		}
		NDBG22(("%d: scsi_reset: target=%d level=%s",
		    mpt->m_instance, ptgt->m_devhdl,
		    level == RESET_TARGET ? "Target" : "Lun"));

		/*
		 * if we are not in panic set up a reset delay for this target.
		 * We wait for the reset to complete so must drop the
		 * mutex before initiating the reset.
		 */
		if (!ddi_in_panic()) {
			boolean_t	do_reset;
			boolean_t	wait;

			/*
			 * We can be called from an interrupt context due to
			 * sd attempting to reset targets if it sees certain
			 * error conditions. In this case do not wait for the
			 * reset attempt to complete.
			 */
			wait = servicing_interrupt() == 0;
			mutex_enter(&ptgt->m_t_mutex);
			do_reset = ptgt->m_reset_delay == 0;

			/*
			 * Setup the reset delay before doing the reset because
			 * we are going to drop the target mutex.
			 */
			if (do_reset)
				mptsas_setup_target_reset_delay(mpt, ptgt, 0);
			mutex_exit(&ptgt->m_t_mutex);
			if (do_reset) {
				rval = mptsas_do_scsi_reset(mpt, ptgt->m_devhdl,
				    wait);
				/*
				 * If it fails and we were waiting it must be a
				 * TM command failure. A small number of those
				 * will result in a reset to the HBA so we
				 * ignore them here.
				 */
				if (rval != TRUE && !wait) {
					/*
					 * If we were not waiting then the
					 * failure will be down to inability to
					 * use the single TM command slot. Set
					 * the delay 3 TICKs above it's normal
					 * value so the watch function will try
					 * again up to 3 times.
					 */
					mutex_enter(&ptgt->m_t_mutex);
					mptsas_setup_target_reset_delay(mpt,
					    ptgt, 3);
					mutex_exit(&ptgt->m_t_mutex);
				}
			} else {
				rval = TRUE;
			}
		} else {
			rval = mptsas_do_scsi_reset(mpt, ptgt->m_devhdl,
			    B_TRUE);
			drv_usecwait(mpt->m_scsi_reset_delay * 1000);
		}
	} else if (level == RESET_ALL) {
		NDBG22(("%d: scsi_reset: level=ALL", mpt->m_instance));
		mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
		if ((mptsas_restart_ioc(mpt, "scsi_reset: level=ALL")) ==
		    DDI_FAILURE) {
			mptsas_log(mpt, CE_WARN, "mptsas_scsi_reset: reset "
			    "adapter failed");
		} else {
			rval = TRUE;
		}
	}
	mutex_exit(&mpt->m_mutex);

	return (rval);
}

static int
mptsas_do_scsi_reset(mptsas_t *mpt, uint16_t devhdl, boolean_t wait)
{
	int		rval;
	uint8_t		config, disk;

	ASSERT(mutex_owned(&mpt->m_mutex));

	NDBG22(("%d: do_scsi_reset: target=%d, wait: %s", mpt->m_instance,
	    devhdl, wait?"Yes":"No"));

	/*
	 * Issue a Target Reset message to the target specified but not to a
	 * disk making up a raid volume.  Just look through the RAID config
	 * Phys Disk list of DevHandles.  If the target's DevHandle is in this
	 * list, then don't reset this target.
	 */
	for (config = 0; config < mpt->m_num_raid_configs; config++) {
		for (disk = 0; disk < MPTSAS_MAX_DISKS_IN_CONFIG; disk++) {
			if (devhdl == mpt->m_raidconfig[config].
			    m_physdisk_devhdl[disk]) {
				return (TRUE);
			}
		}
	}

	rval = mptsas_ioc_task_management(mpt,
	    MPI2_SCSITASKMGMT_TASKTYPE_TARGET_RESET, devhdl, 0, NULL, 0, 0,
	    wait);
	return (rval);
}

static int
mptsas_scsi_reset_notify(struct scsi_address *ap, int flag,
	void (*callback)(caddr_t), caddr_t arg)
{
	mptsas_t	*mpt = ADDR2MPT(ap);

	NDBG22(("%d: scsi_reset_notify: tgt=%d", mpt->m_instance,
	    ap->a_target));

	return (scsi_hba_reset_notify_setup(ap, flag, callback, arg,
	    &mpt->m_mutex, &mpt->m_reset_notify_listf));
}

static int
mptsas_get_name(struct scsi_device *sd, char *name, int len)
{
	dev_info_t	*lun_dip = NULL;

	ASSERT(sd != NULL);
	ASSERT(name != NULL);
	lun_dip = sd->sd_dev;
	ASSERT(lun_dip != NULL);

	if (mptsas_name_child(lun_dip, name, len) == DDI_SUCCESS) {
		return (1);
	} else {
		return (0);
	}
}

static int
mptsas_get_bus_addr(struct scsi_device *sd, char *name, int len)
{
	return (mptsas_get_name(sd, name, len));
}

static void
mptsas_set_throttle(mptsas_t *mpt, mptsas_target_t *ptgt, int what)
{
	ASSERT(what == HOLD_THROTTLE || what == MAX_THROTTLE ||
	    what == DRAIN_THROTTLE || what == QFULL_THROTTLE);

	/*
	 * if the bus is draining/quiesced, no changes to the throttles
	 * are allowed. Not allowing change of throttles during draining
	 * limits error recovery but will reduce draining time
	 *
	 * all throttles should have been set to HOLD_THROTTLE
	 */
	if (mpt->m_softstate & (MPTSAS_SS_QUIESCED | MPTSAS_SS_DRAINING) ||
	    ptgt->m_devhdl == MPTSAS_INVALID_DEVHDL) {
		return;
	}

	if (what == HOLD_THROTTLE) {
		if (ptgt->m_t_throttle != what) {
			NDBG27(("%d: Set Throttle tgt %d, %d -> HOLD",
			    mpt->m_instance, ptgt->m_devhdl,
			    ptgt->m_t_throttle));
		}
		ptgt->m_t_throttle = HOLD_THROTTLE;
	} else if (ptgt->m_reset_delay == 0) {
		if (what == MAX_THROTTLE) {
			what = ptgt->m_t_maxthrottle;
			if (ptgt->m_t_throttle != what) {
				NDBG27(("%d: Set Throttle tgt %d, %d -> "
				    "MAX(%d)", mpt->m_instance, ptgt->m_devhdl,
				    ptgt->m_t_throttle, what));
			}
		} else if (ptgt->m_t_throttle != what) {
			NDBG27(("%d: Set Throttle tgt %d, %d -> %s",
			    mpt->m_instance, ptgt->m_devhdl,
			    ptgt->m_t_throttle, what == DRAIN_THROTTLE ?
			    "DRAIN" : "QWAIT"));
		}
		ptgt->m_t_throttle = (int16_t)what;
	}
}

static void
mptsas_set_throttle_mtx(mptsas_t *mpt, mptsas_target_t *ptgt, int what)
{
	if (mpt->m_softstate & (MPTSAS_SS_QUIESCED | MPTSAS_SS_DRAINING)) {
		return;
	}

	mutex_enter(&ptgt->m_t_mutex);
	mptsas_set_throttle(mpt, ptgt, what);
	mutex_exit(&ptgt->m_t_mutex);
}

/*
 * The following structure and 2 functions are potentially in a race with
 * the replyq interrupts. To ensure we don't try to process a timeout for a
 * command that's about to complete use the atomic swap functionality of
 * the secure_cmd_from_slot function. We can't take the replyq mutex due to
 * deadlock possibilities, but we do have the target mutex so the entire
 * command isn't going to disappear from under us. However the interrupt
 * could have found the command and be waiting for the target mutex.
 */
typedef struct {
	ushort_t	ft_target;
	int		ft_lun;
	hrtime_t	ft_timestamp;
} flush_target_args_t;

static void
mptsas_flush_tcmd_treset(mptsas_t *mpt, mptsas_cmd_t *cmd, void *arg)
{
	uint_t			stat = STAT_DEV_RESET;
	uchar_t			reason = CMD_RESET;
	mptsas_cmd_t		*slcmd;
	flush_target_args_t	*ftap = (flush_target_args_t *)arg;

	if (Tgt(cmd) == ftap->ft_target) {
		uint16_t	slot = cmd->cmd_slot;

		slcmd = mptsas_secure_cmd_from_slots(mpt->m_active,
		    cmd->cmd_slot);
		if (slcmd == NULL)
			return;
		ASSERT(slcmd == cmd);
		if (cmd->cmd_tgt_addr->m_dr_flag == MPTSAS_DR_INTRANSITION) {
			reason = CMD_DEV_GONE;
			stat = STAT_ABORTED;
		} else if (cmd->cmd_active_expiration <= ftap->ft_timestamp) {
			/*
			 * When timeout requested, propagate
			 * proper reason and statistics to
			 * target drivers.
			 */
			reason = CMD_TIMEOUT;
			stat |= STAT_TIMEOUT;
		}
		NDBG25(("%d: flush_target_hba discovered non-"
		    "NULL cmd in slot %d, tasktype TARGET_RESET",
		    mpt->m_instance, slot));
		mptsas_dump_cmd(mpt, cmd);
		mptsas_deref_cmd(mpt, cmd);
		mptsas_set_pkt_reason(mpt, cmd, reason, stat);
		mptsas_doneq_add(mpt, cmd);
	}
}

static void
mptsas_flush_tcmd_common(mptsas_t *mpt, mptsas_cmd_t *cmd, void *arg,
    uint_t stat, uchar_t reason)
{
	flush_target_args_t	*ftap = (flush_target_args_t *)arg;
	mptsas_cmd_t		*slcmd;

	if ((Tgt(cmd) == ftap->ft_target) && (Lun(cmd) == ftap->ft_lun)) {
		uint16_t	slot = cmd->cmd_slot;

		slcmd = mptsas_secure_cmd_from_slots(mpt->m_active,
		    cmd->cmd_slot);
		if (slcmd == NULL)
			return;
		ASSERT(slcmd == cmd);
		if (cmd->cmd_active_expiration <= ftap->ft_timestamp) {
			stat |= STAT_TIMEOUT;
		}

		NDBG25(("%d: flush_target_hba discovered non-"
		    "NULL cmd in slot %d, tasktype LU_RESET", mpt->m_instance,
		    slot));
		mptsas_dump_cmd(mpt, cmd);
		mptsas_deref_cmd(mpt, cmd);
		mptsas_set_pkt_reason(mpt, cmd, reason, stat);
		mptsas_doneq_add(mpt, cmd);
	}
}

static void
mptsas_flush_tcmd_lureset(mptsas_t *mpt, mptsas_cmd_t *cmd, void *arg)
{
	mptsas_flush_tcmd_common(mpt, cmd, arg, STAT_DEV_RESET, CMD_RESET);
}

static void
mptsas_flush_tcmd_abrt_ts(mptsas_t *mpt, mptsas_cmd_t *cmd, void *arg)
{
	mptsas_flush_tcmd_common(mpt, cmd, arg, STAT_ABORTED, CMD_ABORTED);
}


/*
 * Clean up from a device reset.
 * For the case of target reset search for commands for a particular target.
 * For the case of abort task set this function searches for commands for a
 * particular target/lun.
 * Two flavours here. For a target reset we only need to flush commands that
 * were actually on the HBA.
 * For an offline we also need to flush the waitq, this is called specifically
 * during offline_target.
 */
static void
mptsas_flush_target_hba(mptsas_t *mpt, ushort_t target, int lun,
    uint8_t tasktype)
{
	flush_target_args_t	ftargs;
	void			(*fl_func)(mptsas_t *, mptsas_cmd_t *, void *);

	NDBG25(("%d: flush_target_hba: target=%d lun=%d",
	    mpt->m_instance, target, lun));

	ftargs.ft_timestamp = gethrtime();
	ftargs.ft_target = target;
	ftargs.ft_lun = lun;
	fl_func = NULL;

	/*
	 * Make sure the I/O Controller has flushed all cmds
	 * that are associated with this target for a target reset
	 * and target/lun for abort task set.
	 * Account for TM requests, which use the last SMID.
	 */
	switch (tasktype) {
	case MPI2_SCSITASKMGMT_TASKTYPE_TARGET_RESET:
		fl_func = mptsas_flush_tcmd_treset;
		break;
	case MPI2_SCSITASKMGMT_TASKTYPE_ABRT_TASK_SET:
		fl_func = mptsas_flush_tcmd_abrt_ts;
		break;
	case MPI2_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET:
		fl_func = mptsas_flush_tcmd_lureset;
		break;
	default:
		break;
	}

	if (fl_func != NULL) {
		mptsas_scan_slots(mpt, fl_func, &ftargs);
	}
	
	if (mpt->m_done.cl_len) {
		if (!mpt->m_doneq_thread_n) {
			mptsas_doneq_empty(mpt);
		} else {
			mptsas_deliver_doneq_thread(mpt, &mpt->m_done);
		}
	}
}

/*
 * Clean up hba state, abort all outstanding command and commands in waitq
 * reset timeout of all targets.
 */
static void
mptsas_flush_hba(mptsas_t *mpt)
{
	mptsas_cmd_t	*cmd;
	int		slot;
	uint_t		iocflags = 0;
	boolean_t	need_dqempty = B_FALSE;

	NDBG25(("%d: flush_hba", mpt->m_instance));

	/*
	 * The I/O Controller should have already sent back
	 * all commands via the scsi I/O reply frame.  Make
	 * sure all commands have been flushed.
	 * We are only ever called with interrupts disabled so there should
	 * be no need to grab any more mutex's to prevent commands from
	 * disappearing from the slot array, but use secure_cmd for
	 * consistency.
	 * Account for TM request, which use the last SMID.
	 */
	for (slot = 1; slot <= (mpt->m_active->m_n_normal + 1); slot++) {
		cmd = mptsas_secure_cmd_from_slots(mpt->m_active, slot);
		if (cmd == NULL)
			continue;

		if (cmd->cmd_flags & (CFLAG_CMDIOC | CFLAG_TM_CMD)) {
			/*
			 * Need to make sure to tell everyone that might be
			 * waiting on this command that it's going to fail.  If
			 * we get here, this command will never timeout because
			 * the active command table is going to be re-allocated,
			 * so there will be nothing to check against a time out.
			 * Instead, mark the command as failed due to reset.
			 */
			mptsas_set_pkt_reason(mpt, cmd, CMD_RESET,
			    STAT_BUS_RESET);
			if ((cmd->cmd_flags &
			    (CFLAG_PASSTHRU | CFLAG_CONFIG | CFLAG_FW_DIAG |
			    CFLAG_TM_CMD | CFLAG_FW_CMD))) {
				cmd->cmd_flags |= CFLAG_FINISHED;
				iocflags |= (cmd->cmd_flags & (CFLAG_PASSTHRU |
				    CFLAG_CONFIG | CFLAG_FW_DIAG |
				    CFLAG_TM_CMD | CFLAG_FW_CMD));
			}
			continue;
		}

		NDBG25(("%d: flush_hba discovered non-NULL cmd in "
		    "slot %d", mpt->m_instance, slot));
		mptsas_dump_cmd(mpt, cmd);

		mutex_enter(&cmd->cmd_tgt_addr->m_t_mutex);
		mptsas_deref_tgtcmd(mpt, cmd);
		mutex_exit(&cmd->cmd_tgt_addr->m_t_mutex);
		mptsas_set_pkt_reason(mpt, cmd, CMD_RESET, STAT_BUS_RESET);
		mptsas_doneq_add(mpt, cmd);
		need_dqempty = B_TRUE;
	}

	if (iocflags & CFLAG_PASSTHRU)
		cv_broadcast(&mpt->m_passthru_cv);
	if (iocflags & CFLAG_CONFIG)
		cv_broadcast(&mpt->m_config_cv);
	if (iocflags & CFLAG_FW_DIAG)
		cv_broadcast(&mpt->m_fw_diag_cv);
	if (iocflags & CFLAG_FW_CMD)
		cv_broadcast(&mpt->m_fw_cv);
	if (iocflags & CFLAG_TM_CMD)
		mptsas_cmplt_task_management(mpt);
	if (need_dqempty)
		mptsas_doneq_empty(mpt);
}

/*
 * Flush the waitq of this target's cmds with the specific cmd_flags
 * settings.
 */
static void
mptsas_flush_target_waitq(mptsas_t *mpt, mptsas_target_t *ptgt,
    boolean_t pkt_flags, uint32_t flags, uint32_t flgmsk, uint_t stat,
    uchar_t reason)
{
	mptsas_cmd_t		*cmd, *next;
	int			fcount = 0;

	ASSERT(mutex_owned(&mpt->m_mutex));
	ASSERT(mutex_owned(&ptgt->m_t_mutex));

	cmd = STAILQ_FIRST(&ptgt->m_t_wait.cl_q);

	while (cmd != NULL) {
		next = STAILQ_NEXT(cmd, cmd_link);
		if ((pkt_flags ? (cmd->cmd_pkt_flags & flgmsk) :
		    (cmd->cmd_flags & flgmsk)) == flags) {
			mptsas_targwaitq_delete(mpt, ptgt, cmd);
			fcount++;
			mptsas_set_pkt_reason(mpt, cmd, reason, stat);
			mptsas_doneq_add(mpt, cmd);
		}
		cmd = next;
	}

	NDBG25(("%d: flush_target_waitq, target %d, flushed %d cmds, "
	    "%sflags 0x%x(0x%x), reason %d(%s), stat 0x%x", mpt->m_instance,
	    ptgt->m_devhdl, fcount, pkt_flags ? "pkt_" : "cmd_", flags, flgmsk,
	    reason, scsi_rname(reason), stat));
	if (fcount != 0) {
		mutex_exit(&ptgt->m_t_mutex);
		mptsas_doneq_empty(mpt);
		mutex_enter(&ptgt->m_t_mutex);
	}
}

static void
mptsas_flush_alltarg_waitqs(mptsas_t *mpt, boolean_t only_cfgluns,
    boolean_t pkt_flags, uint32_t flags,
    uint32_t flgmsk, uint_t stat, uchar_t reason)
{
	mptsas_target_t	*ptgt;

	ASSERT(mutex_owned(&mpt->m_mutex));

	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mutex_enter(&ptgt->m_t_mutex);
		if (!only_cfgluns || ptgt->m_cnfg_luns != 0)
			mptsas_flush_target_waitq(mpt, ptgt, pkt_flags, flags,
			    flgmsk, stat, reason);
		mutex_exit(&ptgt->m_t_mutex);
	}
}

static void
mptsas_flush_waitq(mptsas_t *mpt, boolean_t forreset)
{
	mptsas_cmd_t	*cmd;
	uint_t		iocflags = 0;

	NDBG25(("%d: flush_waitq", mpt->m_instance));

	/*
	 * Flush the waitq. This will only contain IOC cmds.
	 */
	while ((cmd = mptsas_waitq_rm(mpt)) != NULL) {
		mptsas_set_pkt_reason(mpt, cmd,
		    forreset ? CMD_RESET : CMD_DEV_GONE,
		    forreset ? STAT_BUS_RESET : STAT_ABORTED);
		ASSERT(cmd->cmd_flags &
		    (CFLAG_PASSTHRU | CFLAG_CONFIG | CFLAG_FW_DIAG));
		cmd->cmd_flags |= CFLAG_FINISHED;
		iocflags |= (cmd->cmd_flags & (CFLAG_PASSTHRU |
		    CFLAG_CONFIG | CFLAG_FW_DIAG));
	}

	/* Note CFLAG_TM_CMD & CFLAG_FW_CMD are never put on the waitq */
	if (iocflags & CFLAG_PASSTHRU)
		cv_broadcast(&mpt->m_passthru_cv);
	if (iocflags & CFLAG_CONFIG)
		cv_broadcast(&mpt->m_config_cv);
	if (iocflags & CFLAG_FW_DIAG)
		cv_broadcast(&mpt->m_fw_diag_cv);
}

/*
 * set pkt_reason and OR in pkt_statistics flag
 */
static void
mptsas_set_pkt_reason(mptsas_t *mpt, mptsas_cmd_t *cmd, uchar_t reason,
    uint_t stat)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(mpt))
#endif

	ASSERT(cmd != NULL);

	if (cmd->cmd_pkt->pkt_reason == CMD_CMPLT) {
		NDBG0(("%d: set_pkt_reason: cmd=0x%p(0x%02x) "
		    "reason=%d(%s) stat=0x%x", mpt->m_instance, (void *)cmd,
		    cmd->cmd_cdb[0], reason, scsi_rname(reason), stat));
		cmd->cmd_pkt->pkt_reason = reason;
	} else {
		NDBG0(("%d: set_pkt_reason: cmd=0x%p(0x%02x) reason "
		    "already %d(%s), trying to set %d(%s), stat0x%x",
		    mpt->m_instance, (void *)cmd, cmd->cmd_cdb[0],
		    cmd->cmd_pkt->pkt_reason,
		    scsi_rname(cmd->cmd_pkt->pkt_reason),
		    reason, scsi_rname(reason), stat));
	}
	cmd->cmd_pkt->pkt_statistics |= stat;
}

static void
mptsas_start_watch_reset_delay()
{
	NDBG22(("mptsas_start_watch_reset_delay"));

	mutex_enter(&mptsas_global_mutex);
	if (mptsas_reset_watch == NULL && mptsas_timeouts_enabled) {
		mptsas_reset_watch = timeout(mptsas_watch_reset_delay, NULL,
		    drv_usectohz((clock_t)
		    MPTSAS_WATCH_RESET_DELAY_TICK * 1000));
		ASSERT(mptsas_reset_watch != NULL);
	}
	mutex_exit(&mptsas_global_mutex);
}

static void
mptsas_setup_bus_reset_delay(mptsas_t *mpt)
{
	mptsas_target_t	*ptgt = NULL;

	ASSERT(MUTEX_HELD(&mpt->m_mutex));

	NDBG22(("%d: setup_bus_reset_delay", mpt->m_instance));
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mutex_enter(&ptgt->m_t_mutex);
		mptsas_set_throttle(mpt, ptgt, HOLD_THROTTLE);
		ptgt->m_reset_delay = mpt->m_scsi_reset_delay;
		mutex_exit(&ptgt->m_t_mutex);
	}

	mptsas_start_watch_reset_delay();
}

/*
 * mptsas_watch_reset_delay(_subr) is invoked by timeout() and checks every
 * mpt instance for active reset delays
 */
static void
mptsas_watch_reset_delay(void *arg)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(arg))
#endif

	mptsas_t	*mpt;
	int		not_done = 0;

	NDBG22(("mptsas_watch_reset_delay"));

	mutex_enter(&mptsas_global_mutex);
	mptsas_reset_watch = 0;
	mutex_exit(&mptsas_global_mutex);
	rw_enter(&mptsas_global_rwlock, RW_READER);
	for (mpt = mptsas_head; mpt != NULL; mpt = mpt->m_next) {
		if (mpt->m_tran == 0) {
			continue;
		}
		mutex_enter(&mpt->m_mutex);
		not_done += mptsas_watch_reset_delay_subr(mpt);
		mutex_exit(&mpt->m_mutex);
	}
	rw_exit(&mptsas_global_rwlock);

	if (not_done) {
		mptsas_start_watch_reset_delay();
	}
}

static int
mptsas_watch_reset_delay_subr(mptsas_t *mpt)
{
	int		done = 0;
	mptsas_target_t	*ptgt = NULL;

	NDBG22(("%d: watch_reset_delay_subr", mpt->m_instance));

	ASSERT(mutex_owned(&mpt->m_mutex));

	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mutex_enter(&ptgt->m_t_mutex);
		if (ptgt->m_reset_delay != 0) {
			/*
			 * If a previous reset request through the scsi_reset
			 * entry point failed then the reset delay is set to
			 * 3 TICKs above the normal. If we find a delay above
			 * the normal value here try to reset again. Effectively
			 * we retry the reset 3 times.
			 */
			if (ptgt->m_reset_delay > mpt->m_scsi_reset_delay) {
				if (mptsas_do_scsi_reset(mpt, ptgt->m_devhdl,
				    B_FALSE) == TRUE) {
					/*
					 * That reset was kicked off so change
					 * the reset delay to it's normal
					 * value so we don't try to reset this
					 * target again the next time round.
					 */
					ptgt->m_reset_delay =
					    mpt->m_scsi_reset_delay;
				}
			}
			ptgt->m_reset_delay -= MPTSAS_WATCH_RESET_DELAY_TICK;
			if (ptgt->m_reset_delay <= 0) {
				ptgt->m_reset_delay = 0;
				mptsas_set_throttle(mpt, ptgt, MAX_THROTTLE);
				mptsas_restart_twaitq(mpt, ptgt);
			} else {
				done = -1;
			}
		}
		mutex_exit(&ptgt->m_t_mutex);
	}

	return (done);
}

static void
mptsas_setup_target_reset_delay(mptsas_t *mpt, mptsas_target_t	*ptgt,
    int eticks)
{
	boolean_t	start;

	ASSERT(MUTEX_HELD(&mpt->m_mutex));
	ASSERT(MUTEX_HELD(&ptgt->m_t_mutex));

	NDBG22(("%d: setup_target_reset_delay(%dms, targ 0x%x)",
	    mpt->m_instance, mpt->m_scsi_reset_delay, ptgt->m_devhdl));
	mptsas_set_throttle(mpt, ptgt, HOLD_THROTTLE);
	start = ptgt->m_reset_delay == 0;
	ptgt->m_reset_delay = mpt->m_scsi_reset_delay +
	    (eticks * MPTSAS_WATCH_RESET_DELAY_TICK);

	if (start)
		mptsas_start_watch_reset_delay();
}

#ifdef MPTSAS_TEST
static void
mptsas_test_reset(mptsas_t *mpt, uint16_t target)
{
	mptsas_target_t *ptgt;

	if ((ptgt = refhash_linear_search(mpt->m_targets,
	    mptsas_target_eval_devhdl, &target)) != NULL) {
		mutex_enter(&ptgt->m_t_mutex);
		if (mptsas_do_scsi_reset(mpt, target, B_FALSE) == TRUE) {
			NDBG22(("%d: test_reset success",
			    mpt->m_instance));
			if (mptsas_rtest_use_rdelay)
				mptsas_setup_target_reset_delay(mpt, ptgt, 0);
		} else {
			NDBG22(("%d: test_reset failed",
			    mpt->m_instance));
		}
		mutex_exit(&ptgt->m_t_mutex);
	}
}
#endif

/*
 * abort handling:
 *
 * Notes:
 *	- if pkt is not NULL, abort just that command
 *	- if pkt is NULL, abort all outstanding commands for target
 */
static int
mptsas_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	mptsas_t		*mpt = ADDR2MPT(ap);
	int			rval;
	mptsas_tgt_private_t	*tgt_private;
	int			target, lun;

	tgt_private = (mptsas_tgt_private_t *)ap->a_hba_tran->
	    tran_tgt_private;
	ASSERT(tgt_private != NULL);
	target = tgt_private->t_private->m_devhdl;
	lun = tgt_private->t_lun;

	NDBG23(("%d: scsi_abort: target=%d.%d", mpt->m_instance, target,
	    lun));

	mutex_enter(&mpt->m_mutex);
	rval = mptsas_do_scsi_abort(mpt, target, lun, pkt);
	mutex_exit(&mpt->m_mutex);
	return (rval);
}

static int
mptsas_do_scsi_abort(mptsas_t *mpt, int target, int lun, struct scsi_pkt *pkt)
{
	mptsas_cmd_t	*sp = NULL;
	mptsas_slots_t	*slots = mpt->m_active;
	int		rval = FALSE;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Abort the command pkt on the target/lun in ap.  If pkt is
	 * NULL, abort all outstanding commands on that target/lun.
	 * If you can abort them, return 1, else return 0.
	 * Each packet that's aborted should be sent back to the target
	 * driver through the callback routine, with pkt_reason set to
	 * CMD_ABORTED.
	 *
	 * abort cmd pkt on HBA hardware; clean out of outstanding
	 * command lists, etc.
	 */
	if (pkt != NULL) {
		/* abort the specified packet */
		sp = PKT2CMD(pkt);

		if (sp->cmd_queued != CQ_NOTQUEUED) {
			NDBG23(("%d: do_scsi_abort: queued sp=0x%p "
			    "aborted", mpt->m_instance, (void *)sp));
			if (sp->cmd_queued == CQ_MAIN) {
				mptsas_waitq_delete(mpt, sp);
			} else {
				mptsas_target_t	*ptgt = sp->cmd_tgt_addr;

				ASSERT(sp->cmd_queued == CQ_TARGET);
				mutex_enter(&ptgt->m_t_mutex);
				mptsas_targwaitq_delete(mpt, ptgt, sp);
				mutex_exit(&ptgt->m_t_mutex);
			}
			mptsas_set_pkt_reason(mpt, sp, CMD_ABORTED,
			    STAT_ABORTED);
			mptsas_doneq_add(mpt, sp);
			rval = TRUE;
		} else if (slots->m_slot[sp->cmd_slot] != NULL) {
			rval = mptsas_ioc_task_management(mpt,
			    MPI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK, target,
			    lun, NULL, 0, 0, B_TRUE);
		}
	} else {

		/*
		 * If pkt is NULL then abort task set
		 */
		rval = mptsas_ioc_task_management(mpt,
		    MPI2_SCSITASKMGMT_TASKTYPE_ABRT_TASK_SET, target, lun,
		    NULL, 0, 0, B_TRUE);
	}
	return (rval);
}

/*
 * capability handling:
 * (*tran_getcap).  Get the capability named, and return its value.
 */
static int
mptsas_scsi_getcap(struct scsi_address *ap, char *cap, int tgtonly)
{
	mptsas_t	*mpt = ADDR2MPT(ap);
	int		ckey;
	int		rval = FALSE;

	NDBG24(("%d: scsi_getcap: target=%d, cap=%s tgtonly=%x",
	    mpt->m_instance, ap->a_target, cap, tgtonly));

	mutex_enter(&mpt->m_mutex);

	if ((mptsas_scsi_capchk(cap, tgtonly, &ckey)) != TRUE) {
		mutex_exit(&mpt->m_mutex);
		return (UNDEFINED);
	}

	switch (ckey) {
	case SCSI_CAP_DMA_MAX:
		rval = (int)mpt->m_msg_dma_attr.dma_attr_maxxfer;
		break;
	case SCSI_CAP_ARQ:
		rval = TRUE;
		break;
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_UNTAGGED_QING:
		rval = TRUE;
		break;
	case SCSI_CAP_TAGGED_QING:
		rval = TRUE;
		break;
	case SCSI_CAP_RESET_NOTIFICATION:
		rval = TRUE;
		break;
	case SCSI_CAP_LINKED_CMDS:
		rval = FALSE;
		break;
	case SCSI_CAP_QFULL_RETRIES:
		rval = ((mptsas_tgt_private_t *)(ap->a_hba_tran->
		    tran_tgt_private))->t_private->m_qfull_retries;
		break;
	case SCSI_CAP_QFULL_RETRY_INTERVAL:
		rval = drv_hztousec(((mptsas_tgt_private_t *)
		    (ap->a_hba_tran->tran_tgt_private))->
		    t_private->m_qfull_retry_interval) / 1000;
		break;
	case SCSI_CAP_CDB_LEN:
		rval = CDB_GROUP4;
		break;
	case SCSI_CAP_INTERCONNECT_TYPE:
		rval = INTERCONNECT_SAS;
		break;
	case SCSI_CAP_TRAN_LAYER_RETRIES:
		if (mpt->m_ioc_capabilities &
		    MPI2_IOCFACTS_CAPABILITY_TLR)
			rval = TRUE;
		else
			rval = FALSE;
		break;
	default:
		rval = UNDEFINED;
		break;
	}

	NDBG24(("%d: scsi_getcap: %s, rval=%x", mpt->m_instance,
	    cap, rval));

	mutex_exit(&mpt->m_mutex);
	return (rval);
}

/*
 * (*tran_setcap).  Set the capability named to the value given.
 */
static int
mptsas_scsi_setcap(struct scsi_address *ap, char *cap, int value, int tgtonly)
{
	mptsas_t	*mpt = ADDR2MPT(ap);
	mptsas_target_t	*ptgt;
	int		ckey;
	int		rval = FALSE;

	NDBG24(("%d: scsi_setcap: target=%d, cap=%s value=%x tgtonly=%x",
	    mpt->m_instance, ap->a_target, cap, value, tgtonly));

	if (!tgtonly) {
		return (rval);
	}

	mutex_enter(&mpt->m_mutex);

	if ((mptsas_scsi_capchk(cap, tgtonly, &ckey)) != TRUE) {
		mutex_exit(&mpt->m_mutex);
		return (UNDEFINED);
	}

	switch (ckey) {
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_INITIATOR_ID:
	case SCSI_CAP_LINKED_CMDS:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_RESET_NOTIFICATION:
		/*
		 * None of these are settable via
		 * the capability interface.
		 */
		break;
	case SCSI_CAP_ARQ:
		/*
		 * We cannot turn off arq so return false if asked to
		 */
		if (value) {
			rval = TRUE;
		} else {
			rval = FALSE;
		}
		break;
	case SCSI_CAP_TAGGED_QING:
		ptgt = ((mptsas_tgt_private_t *)
		    (ap->a_hba_tran->tran_tgt_private))->t_private;
		mptsas_set_throttle_mtx(mpt, ptgt, MAX_THROTTLE);
		rval = TRUE;
		break;
	case SCSI_CAP_QFULL_RETRIES:
		((mptsas_tgt_private_t *)(ap->a_hba_tran->tran_tgt_private))->
		    t_private->m_qfull_retries = (uchar_t)value;
		rval = TRUE;
		break;
	case SCSI_CAP_QFULL_RETRY_INTERVAL:
		((mptsas_tgt_private_t *)(ap->a_hba_tran->tran_tgt_private))->
		    t_private->m_qfull_retry_interval =
		    drv_usectohz(value * 1000);
		rval = TRUE;
		break;
	default:
		rval = UNDEFINED;
		break;
	}
	mutex_exit(&mpt->m_mutex);
	return (rval);
}

/*
 * Utility routine for mptsas_ifsetcap/ifgetcap
 */
/*ARGSUSED*/
static int
mptsas_scsi_capchk(char *cap, int tgtonly, int *cidxp)
{
	NDBG24(("mptsas_scsi_capchk: cap=%s", cap));

	if (!cap)
		return (FALSE);

	*cidxp = scsi_hba_lookup_capstr(cap);
	return (TRUE);
}

static int
mptsas_alloc_active_slots(mptsas_t *mpt, int flag)
{
	mptsas_slots_t	*old_active = mpt->m_active;
	mptsas_slots_t	*new_active;
	size_t		size;

	/*
	 * if there are active commands, then we cannot
	 * change size of active slots array.
	 */
	ASSERT(mpt->m_ncmds == 0);

	size = MPTSAS_SLOTS_SIZE(mpt);
	new_active = kmem_zalloc(size, flag);
	if (new_active == NULL) {
		NDBG1(("%d: new active alloc failed", mpt->m_instance));
		return (-1);
	}
	/*
	 * Since SMID 0 is reserved and the TM slot is reserved, the
	 * number of slots that can be used at any one time is
	 * m_max_requests - 2.
	 */
	new_active->m_n_normal = (mpt->m_max_requests - 2);
	new_active->m_size = size;
	new_active->m_rotor = 1;
	if (old_active)
		mptsas_free_active_slots(mpt);
	mpt->m_active = new_active;

	return (0);
}

static void
mptsas_free_active_slots(mptsas_t *mpt)
{
	mptsas_slots_t	*active = mpt->m_active;
	size_t		size;

	if (active == NULL)
		return;
	size = active->m_size;
	kmem_free(active, size);
	mpt->m_active = NULL;
}

/*
 * Error logging, printing, and debug print routines.
 */
static char *mptsas_label = "mpt_sas3";

/*PRINTFLIKE3*/
void
mptsas_log(mptsas_t *mpt, int level, char *fmt, ...)
{
	dev_info_t	*dev;
	va_list		ap;

	if (mpt) {
		dev = mpt->m_dip;
	} else {
		dev = 0;
	}

	mutex_enter(&mptsas_log_mutex);

	va_start(ap, fmt);
	(void) vsprintf(mptsas_log_buf, fmt, ap);
	va_end(ap);

	if (level == CE_CONT) {
		scsi_log(dev, mptsas_label, level, "%s\n", mptsas_log_buf);
	} else {
		scsi_log(dev, mptsas_label, level, "%s", mptsas_log_buf);
	}

	mutex_exit(&mptsas_log_mutex);
}

#ifdef MPTSAS_DEBUG
/*
 * Use a circular buffer to log messages to private memory.
 * No mutexes, so there is the opportunity for this to miss lines.
 * But it's fast and does not hold up the proceedings too much.
 */
static mptsas_dbglog_t mptsas_dbglog_bufs;
static uint8_t mptsas_dbglog_idx = 0;

/*PRINTFLIKE1*/
void
mptsas_debug_log(char *fmt, ...)
{
	va_list		ap;
	uint8_t		idx;

	idx = atomic_inc_8_nv(&mptsas_dbglog_idx);

	va_start(ap, fmt);
	(void) vsnprintf(mptsas_dbglog_bufs.buf[idx],
	    sizeof (mptsas_dbglog_bufs.buf[0]), fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
void
mptsas_printf(char *fmt, ...)
{
	dev_info_t	*dev = 0;
	va_list		ap;

	mutex_enter(&mptsas_log_mutex);

	va_start(ap, fmt);
	(void) vsprintf(mptsas_log_buf, fmt, ap);
	va_end(ap);

#ifdef PROM_PRINTF
	prom_printf("%s:\t%s\n", mptsas_label, mptsas_log_buf);
#else
	scsi_log(dev, mptsas_label, CE_CONT, "!%s\n", mptsas_log_buf);
#endif
	mutex_exit(&mptsas_log_mutex);
}
#endif

/*
 * timeout handling
 */
static void
mptsas_watch(void *arg)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(arg))
#endif

	mptsas_t	*mpt;
	uint32_t	doorbell;
	int		kickintr;

	NDBG30(("mptsas_watch"));

	rw_enter(&mptsas_global_rwlock, RW_READER);
	for (mpt = mptsas_head; mpt != (mptsas_t *)NULL; mpt = mpt->m_next) {

		mutex_enter(&mpt->m_mutex);

		/* Skip device if not powered on */
		if (mpt->m_options & MPTSAS_OPT_PM) {
			if (mpt->m_power_level == PM_LEVEL_D0) {
				(void) pm_busy_component(mpt->m_dip, 0);
				mpt->m_busy = 1;
			} else {
				mutex_exit(&mpt->m_mutex);
				continue;
			}
		}

		/*
		 * Check if controller is in a FAULT state. If so, reset it.
		 */
		doorbell = ddi_get32(mpt->m_datap, &mpt->m_reg->Doorbell);
		if ((doorbell & MPI2_IOC_STATE_MASK) == MPI2_IOC_STATE_FAULT) {
			doorbell &= MPI2_DOORBELL_DATA_MASK;
			mptsas_log(mpt, CE_WARN, "MPT Firmware Fault, "
			    "code: %04x", doorbell);
			mpt->m_softstate |= MPTSAS_SS_RESET_INWATCH;
		}
		if (mpt->m_failed_tm_cmds >= mptsas_max_failed_tm_cmds) {
			mptsas_log(mpt, CE_WARN, "mptsas3%d: Failed %d TM "
			    "commands, Reset IOC", mpt->m_instance,
			    mpt->m_failed_tm_cmds);
			mpt->m_failed_tm_cmds = 0;
			mpt->m_softstate |= MPTSAS_SS_RESET_INWATCH;
		}
		if (mpt->m_failed_cfg_cmds >= mptsas_max_failed_cfg_cmds) {
			mptsas_log(mpt, CE_WARN, "mptsas3%d: Failed %d config "
			    "commands, Reset IOC", mpt->m_instance,
			    mpt->m_failed_tm_cmds);
			mpt->m_failed_cfg_cmds = 0;
			mpt->m_softstate |= MPTSAS_SS_RESET_INWATCH;
		}
		if (mpt->m_softstate & MPTSAS_SS_RESET_INWATCH) {
			doorbell = ddi_get32(mpt->m_datap,
			    &mpt->m_reg->Doorbell);
			mptsas_log(mpt, CE_WARN, "MPT Forced Reset, "
			    "doorbell: %04x", doorbell);
			mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
			if (mpt->m_softstate & MPTSAS_SS_MUR_INWATCH)
				mpt->m_softstate |= MPTSAS_SS_MSG_UNIT_RESET;
			mpt->m_softstate &= ~(MPTSAS_SS_RESET_INWATCH|
			    MPTSAS_SS_MUR_INWATCH);
			/*
			 * Attempting to reset the IOC from the watch
			 * function runs the risk of being unable to timeout
			 * commands during that process. So dispatch a task.
			 */
			(void) ddi_taskq_dispatch(mpt->m_reset_taskq,
			    mptsas_restart_ioc_task, (void *)mpt, DDI_SLEEP);
		}

		/*
		 * Call mptsas_watchsubr provided we are not in the middle
		 * of a reset.
		 */
		if (mpt->m_in_reset == TRUE)
			kickintr = FALSE;
		else
			kickintr = mptsas_watchsubr(mpt);

		if (mpt->m_options & MPTSAS_OPT_PM) {
			mpt->m_busy = 0;
			(void) pm_idle_component(mpt->m_dip, 0);
		}

		mutex_exit(&mpt->m_mutex);
		if (kickintr &&
		    (MPTSAS_GET_ISTAT(mpt) &
		    MPI2_HIS_REPLY_DESCRIPTOR_INTERRUPT)) {
			intptr_t i;

			mptsas_log(mpt, CE_NOTE,
			    "?Found int pending after none for 3 seconds");
			for (i = 0; i < mpt->m_post_reply_qcount; i++) {
				(void) mptsas_intr((caddr_t)mpt, (caddr_t)i);
			}

			/*
			 * Calling the interrupt routine manually screws up the
			 * reply queue mappings. Reset, a real interrupt will
			 * correct it if neccessary.
			 */
			if (mpt->m_cpu_to_repq[CPU_SEQID] >= 0)
				mpt->m_cpu_to_repq[CPU_SEQID] = -1;
		}
	}
	rw_exit(&mptsas_global_rwlock);

	mutex_enter(&mptsas_global_mutex);
	if (mptsas_timeouts_enabled)
		mptsas_timeout_id = timeout(mptsas_watch, NULL, mptsas_tick);
	mutex_exit(&mptsas_global_mutex);
}

static int
mptsas_watchsubr(mptsas_t *mpt)
{
	int		foundint = 0;
	uint_t		ctout_flags;
	mptsas_cmd_t	*cmd, *slcmd;
	mptsas_target_t	*ptgt = NULL;
	hrtime_t	timestamp = gethrtime();
	boolean_t	restart_hba = B_FALSE;

	ASSERT(MUTEX_HELD(&mpt->m_mutex));

	NDBG30(("%d: watchsubr: ncmds %d, nstarted %d, "
	    "lastint %lld", mpt->m_instance, mpt->m_ncmds, mpt->m_ncstarted,
	    (timestamp - mpt->m_lastintr_tstamp)));

	mpt->m_lncstarted = mpt->m_ncstarted;
	mpt->m_ncstarted = 0;

	/*
	 * Try to check for a missed interrupt. Currently looks for
	 * no interrupts in the last 3 seconds together with the
	 * interrupt flag being set. Obviously the is not infallible
	 * but mptsas_intr() can cope with spurious calls.
	 */
	if (mpt->m_interrupt_count == mpt->m_wsinterrupt_count &&
	    mpt->m_polled_intr == 0 &&
	    (timestamp - mpt->m_lastintr_tstamp) > 3000000000ll &&
	    (MPTSAS_GET_ISTAT(mpt) & MPI2_HIS_REPLY_DESCRIPTOR_INTERRUPT)) {
		foundint = 1;
	}
	mpt->m_wsinterrupt_count = mpt->m_interrupt_count;

	/*
	 * Check for IOC commands stuck in active queue.
	 * Note that Task Management commands (CFLAG_TM_CMD) and Firmware
	 * commands (CFLAG_FW_CMD) get added to this list so also need to
	 * check for them.
	 */
	ctout_flags = 0;
	TAILQ_FOREACH_REVERSE(cmd, &mpt->m_active_ioccmdq,
	    mptsas_active_cmdq, cmd_active_link) {
		ASSERT(cmd->cmd_flags &
		    (CFLAG_PASSTHRU | CFLAG_CONFIG | CFLAG_FW_DIAG |
		    CFLAG_TM_CMD | CFLAG_FW_CMD));

		/*
		 * We need to do secure cmd from slot here and check
		 * the result.
		 */
		if (cmd->cmd_active_expiration <= timestamp) {
			slcmd = mptsas_secure_cmd_from_slots(mpt->m_active,
			    cmd->cmd_slot);
			if (slcmd == NULL)
				continue;
			ASSERT(slcmd == cmd);

			/*
			 * IOC or TM command timeout.
			 */
			cmd->cmd_flags |= (CFLAG_FINISHED | CFLAG_TIMEOUT);
			ctout_flags |= cmd->cmd_flags & (CFLAG_PASSTHRU |
			    CFLAG_CONFIG | CFLAG_FW_DIAG | CFLAG_TM_CMD |
			    CFLAG_FW_CMD);
		} else {
			/*
			 * We are in reverse timeout order, so the remainder
			 * should be fine.
			 */
			break;
		}
	}
	if (ctout_flags & CFLAG_PASSTHRU)
		cv_broadcast(&mpt->m_passthru_cv);
	if (ctout_flags & CFLAG_CONFIG)
		cv_broadcast(&mpt->m_config_cv);
	if (ctout_flags & CFLAG_FW_DIAG)
		cv_broadcast(&mpt->m_fw_diag_cv);
	if (ctout_flags & CFLAG_FW_CMD)
		cv_broadcast(&mpt->m_fw_cv);
	if (ctout_flags & CFLAG_TM_CMD)
		mptsas_cmplt_task_management(mpt);

	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mutex_enter(&ptgt->m_t_mutex);
		/*
		 * If we were draining due to a qfull condition,
		 * go back to full throttle.
		 */
		if ((ptgt->m_t_throttle < ptgt->m_t_maxthrottle) &&
		    (ptgt->m_t_throttle > HOLD_THROTTLE) &&
		    (ptgt->m_t_ncmds < ptgt->m_t_throttle)) {
			mptsas_set_throttle(mpt, ptgt, MAX_THROTTLE);
			restart_hba = B_TRUE;
		}

#ifdef AUTO_OFFLINE_TARGETS
		DTRACE_PROBE2(mptsas__watch__subr, mptsas_t *, mpt,
		    mptsas_target_t *, ptgt);

		/*
		 * Check if a set period of time has passed with
		 * m_timeout_ncmd at non zero. If it has and this target is
		 * still here we may have recovered.
		 * So reset the timed out count to prevent taking the
		 * target offline due to occasional spurious problems.
		 */
		if (ptgt->m_timeout_ncmd > 0) {
			ptgt->m_timeout_interval +=
			    mptsas_scsi_watchdog_tick;
		}

		if (ptgt->m_timeout_interval > mptsas_tgt_offline_timeout) {
			DTRACE_PROBE2(mptsas__timeout__reset,
			    mptsas_t *, mpt,
			    mptsas_target_t *, ptgt);
			ptgt->m_timeout_interval = 0;
			ptgt->m_timeout_ncmd = 0;
		}
#endif
		cmd = TAILQ_LAST(&ptgt->m_active_cmdq, mptsas_active_cmdq);
		if (cmd != NULL) {
			ASSERT(cmd->cmd_active_expiration != 0);

			/*
			 * At this point we have the main mutex and the per
			 * target mutex but not the replyq mutex. So the command
			 * cannot disappear from the target list. However it's
			 * possible for a replyq interrupt to be in the
			 * process of handling it and be stalled on the target
			 * mutex.
			 * This isn't really a problem unless we decide we
			 * want to actually remove the command and we defer
			 * that until the target has been reset.
			 */
			if (cmd->cmd_active_expiration <= timestamp) {
				/*
				 * Earliest command timeout expired.
				 * Drain throttle.
				 */
				mptsas_set_throttle(mpt, ptgt, DRAIN_THROTTLE);

				/*
				 * Check for remaining commands.
				 */
				cmd = TAILQ_FIRST(&ptgt->m_active_cmdq);
				if (cmd->cmd_active_expiration > timestamp) {
					/*
					 * Wait for remaining commands to
					 * complete or time out.
					 */
					NDBG23(("%d: command timed out, pending"
					    "drain", mpt->m_instance));
				} else {
					/*
					 * All command timeouts expired.
					 */
					ptgt->m_timeout_count++;
#ifdef AUTO_OFFLINE_TARGETS
					/*
					 * mptsas_target_cmds_expired() will
					 * drop the target mutex.
					 */
					mptsas_target_cmds_expired(mpt, ptgt,
					    cmd);
#else
					mutex_exit(&ptgt->m_t_mutex);

					/*
					 * All command timeouts expired.
					 */
					mptsas_log(mpt, CE_NOTE,
					    "Timeout of %d seconds "
					    "expired with %d commands on "
					    "target %d lun %d.",
					    cmd->cmd_pkt->pkt_time,
					    ptgt->m_t_ncmds,
					    ptgt->m_devhdl, Lun(cmd));

					mptsas_cmd_timeout(mpt, ptgt);
#endif
					continue;
				}
			} else if (cmd->cmd_active_expiration <= timestamp +
			    (hrtime_t)mptsas_scsi_watchdog_tick * NANOSEC) {
				NDBG23(("%d: pending timeout",
				    mpt->m_instance));
				mptsas_set_throttle(mpt, ptgt, DRAIN_THROTTLE);
			}
		}
#ifdef MPTSAS_TEST
		if (mptsas_test_offline_target & (1<<mpt->m_instance) &&
		    ptgt->m_devhdl == (uint16_t)
		    (mptsas_test_offline_target>>16)) {
			mptsas_dispatch_offline_tgt(mpt, ptgt, B_FALSE);
			mptsas_test_offline_target = 0;
		}
#endif
		mutex_exit(&ptgt->m_t_mutex);
	}

	/* It's possible that timeouts added commands to the doneq */
	if (mpt->m_done.cl_len != 0) {
		mptsas_doneq_empty(mpt);
	}
	if (restart_hba == B_TRUE) {
		mptsas_restart_hba(mpt);
	}

#ifdef MPTSAS_TEST
	if (mptsas_test_reset_target & (1<<mpt->m_instance)) {
		mptsas_test_reset(mpt,
		    (uint16_t)(mptsas_test_reset_target>>16));
		mptsas_test_reset_target = 0;
	}
	if (mptsas_test_online_target & (1<<mpt->m_instance)) {
		uint16_t	devhdl;

		devhdl = (uint16_t)(mptsas_test_online_target>>16);
		mptsas_test_online_target = 0;

		ptgt = refhash_linear_search(mpt->m_targets,
		    mptsas_target_eval_shdwhdl, &devhdl);

		if (ptgt == NULL) {
			mptsas_log(mpt, CE_NOTE,
			    "?Cannot find target %d to online", devhdl);
		} else if (ptgt->m_shdwhdl == MPTSAS_INVALID_DEVHDL ||
		    ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL) {
			/*
			 * Can only restore a target that has been offlined by
			 * software. devhdl will be invalid while shadow isn't.
			 */
			mptsas_log(mpt, CE_NOTE,
			    "?Target %d not offlined by S/W, cannot online",
			    devhdl);
		} else {
			mptsas_dispatch_reconf_tgt(mpt, ptgt, devhdl,
			    DDI_SLEEP, ptgt->m_deviceinfo &
			    DEVINFO_DIRECT_ATTACHED ?
			    MPTSAS_TOPO_FLAG_DIRECT_ATTACHED_DEVICE :
			    MPTSAS_TOPO_FLAG_EXPANDER_ATTACHED_DEVICE);
		}
	}
#endif
	return (foundint);
}

/*
 * Timeout recovery functions.
 *
 * mptsas_timeout_target() - complete all commands on the target list
 *                           with TIMEOUT error.
 * mptsas_cmd_timeout() -    Determine the exact course of action for
 *                           command timeouts.
 */
static void
mptsas_timeout_target(mptsas_t *mpt, mptsas_target_t *ptgt)
{
	mptsas_cmd_t	*cmd, *slcmd;
	uint16_t	slot;
	uint_t		stat = STAT_TIMEOUT;
	uchar_t		reason = CMD_TIMEOUT;

	ASSERT(mutex_owned(&ptgt->m_t_mutex));
	NDBG29(("%d: timeout_target %d", mpt->m_instance,
	    ptgt->m_devhdl));

	if (ptgt->m_dr_flag == MPTSAS_DR_INTRANSITION) {
		reason = CMD_DEV_GONE;
		stat = STAT_ABORTED;
	}

	/*
	 * Traverse the active list.
	 * However, still need to secure the commands from the slot mechanism
	 * prior to erroring them.
	 */
	cmd = TAILQ_FIRST(&ptgt->m_active_cmdq);
	while (cmd != NULL) {
		slot = cmd->cmd_slot;
		slcmd = mptsas_secure_cmd_from_slots(mpt->m_active, slot);
		if (slcmd == NULL) {
			cmd = TAILQ_NEXT(cmd, cmd_active_link);
			continue;
		}
		ASSERT(slcmd == cmd);
		cmd = TAILQ_NEXT(cmd, cmd_active_link);
		mptsas_dump_cmd(mpt, slcmd);
		mptsas_deref_tgtcmd(mpt, slcmd);
		mptsas_set_pkt_reason(mpt, slcmd, reason, stat);
		mptsas_doneq_add(mpt, slcmd);
	}
}

static void
mptsas_cmd_timeout(mptsas_t *mpt, mptsas_target_t *ptgt)
{
	uint16_t	devhdl;
	uint64_t	sas_wwn;
	uint8_t		phy;
	char		wwn_str[MPTSAS_WWN_STRLEN];

	devhdl = ptgt->m_devhdl;
	sas_wwn = ptgt->m_addr.mta_wwn;
	phy = ptgt->m_phynum;
	if (sas_wwn == 0) {
		(void) sprintf(wwn_str, "p%x", phy);
	} else {
		(void) sprintf(wwn_str, "w%016"PRIx64, sas_wwn);
	}

	NDBG29(("%d: cmd_timeout: target=%d", mpt->m_instance, devhdl));
	mptsas_log(mpt, CE_WARN, "Disconnected command timeout for "
	    "target %d %s,  enclosure %u .", devhdl, wwn_str,
	    ptgt->m_enclosure);

	mutex_enter(&ptgt->m_t_mutex);
	if (ptgt->m_dr_flag == MPTSAS_DR_INTRANSITION) {
		NDBG29(("%d: cmd_timeout while dr set, targ %d",
		    mpt->m_instance, devhdl));

		/*
		 * Target has been marked as going away and will be offlined
		 * soon. In this case do not try to reset it again, simply
		 * error the commands.
		 */
		mptsas_timeout_target(mpt, ptgt);
	} else {

		/*
		 * Abort all outstanding commands on the device.
		 * This is kicked off by resetting the target. When the task
		 * management for that completes the target will get flushed
		 * in mptsas_check_task_mgt().
		 */
		if (mptsas_do_scsi_reset(mpt, devhdl, B_FALSE) != TRUE) {
			/*
			 * The reset can fail if you power off a JBOD while
			 * there is activity on it and we come through here
			 * trying to reset many targets one after the other.
			 * If we didn't get to issue the reset we must flush
			 * any commands here.
			 */
			NDBG29(("%d: cmd_timeout: targ %d reset failed",
			    mpt->m_instance, ptgt->m_devhdl));
			mptsas_timeout_target(mpt, ptgt);
		} else {
			mptsas_setup_target_reset_delay(mpt, ptgt, 0);
		}
	}
	mutex_exit(&ptgt->m_t_mutex);
}

/*
 * Device / Hotplug control
 */
static int
mptsas_scsi_quiesce(dev_info_t *dip)
{
	mptsas_t	*mpt;
	scsi_hba_tran_t	*tran;

	tran = ddi_get_driver_private(dip);
	if (tran == NULL || (mpt = TRAN2MPT(tran)) == NULL)
		return (-1);

	return (mptsas_quiesce_bus(mpt));
}

static int
mptsas_scsi_unquiesce(dev_info_t *dip)
{
	mptsas_t		*mpt;
	scsi_hba_tran_t	*tran;

	tran = ddi_get_driver_private(dip);
	if (tran == NULL || (mpt = TRAN2MPT(tran)) == NULL)
		return (-1);

	return (mptsas_unquiesce_bus(mpt));
}

static int
mptsas_quiesce_bus(mptsas_t *mpt)
{
	mptsas_target_t	*ptgt = NULL;

	NDBG28(("%d: quiesce_bus", mpt->m_instance));
	mutex_enter(&mpt->m_mutex);

	/* Set all the throttles to zero */
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mptsas_set_throttle_mtx(mpt, ptgt, HOLD_THROTTLE);
	}

	/* If there are any outstanding commands in the queue */
	while (mpt->m_ncmds) {
		mpt->m_softstate |= MPTSAS_SS_DRAINING;
		mpt->m_quiesce_timeid = timeout(mptsas_ncmds_checkdrain,
		    mpt, (MPTSAS_QUIESCE_TIMEOUT * drv_usectohz(1000000)));
		if (cv_wait_sig(&mpt->m_cv, &mpt->m_mutex) == 0) {
			/*
			 * Quiesce has been interrupted
			 */
			mpt->m_softstate &= ~MPTSAS_SS_DRAINING;
			for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
			    ptgt = refhash_next(mpt->m_targets, ptgt)) {
				mptsas_set_throttle_mtx(mpt, ptgt,
				    MAX_THROTTLE);
			}
			mptsas_restart_hba(mpt);
			if (mpt->m_quiesce_timeid != 0) {
				timeout_id_t tid = mpt->m_quiesce_timeid;
				mpt->m_quiesce_timeid = 0;
				mutex_exit(&mpt->m_mutex);
				(void) untimeout(tid);
				return (-1);
			}
			mutex_exit(&mpt->m_mutex);
			return (-1);
		} else {
			/* Bus has been quiesced */
			ASSERT(mpt->m_quiesce_timeid == 0);
			mpt->m_softstate &= ~MPTSAS_SS_DRAINING;
		}
	}
	/* Bus was not busy - QUIESCED */
	mpt->m_softstate |= MPTSAS_SS_QUIESCED;
	mutex_exit(&mpt->m_mutex);

	return (0);
}

static int
mptsas_unquiesce_bus(mptsas_t *mpt)
{
	mptsas_target_t	*ptgt = NULL;

	NDBG28(("%d: unquiesce_bus", mpt->m_instance));
	mutex_enter(&mpt->m_mutex);
	mpt->m_softstate &= ~MPTSAS_SS_QUIESCED;
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mptsas_set_throttle_mtx(mpt, ptgt, MAX_THROTTLE);
	}
	mptsas_restart_hba(mpt);
	mutex_exit(&mpt->m_mutex);
	return (0);
}

static void
mptsas_ncmds_checkdrain(void *arg)
{
	mptsas_t	*mpt = arg;
	mptsas_target_t	*ptgt = NULL;

	mutex_enter(&mpt->m_mutex);
	if (mpt->m_softstate & MPTSAS_SS_DRAINING) {
		mpt->m_quiesce_timeid = 0;
		if (mpt->m_ncmds == 0) {
			/* Command queue has been drained */
			cv_broadcast(&mpt->m_cv);
		} else {
			/*
			 * The throttle may have been reset because
			 * of a SCSI bus reset
			 */
			for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
			    ptgt = refhash_next(mpt->m_targets, ptgt)) {
				mptsas_set_throttle_mtx(mpt, ptgt,
				    HOLD_THROTTLE);
			}

			mpt->m_quiesce_timeid = timeout(mptsas_ncmds_checkdrain,
			    mpt, (MPTSAS_QUIESCE_TIMEOUT *
			    drv_usectohz(1000000)));
		}
	}
	mutex_exit(&mpt->m_mutex);
}

/*ARGSUSED*/
static void
mptsas_dump_cmd(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	int	i;
	uint8_t	*cp = (uchar_t *)cmd->cmd_pkt->pkt_cdbp;
	char	buf[128];

	buf[0] = '\0';
	NDBG25(("Cmd (0x%p) dump for Target %d Lun %d:\n", (void *)cmd,
	    Tgt(cmd), Lun(cmd)));
	(void) sprintf(&buf[0], "\tcdb=[");
	for (i = 0; i < (int)cmd->cmd_cdblen; i++) {
		(void) sprintf(&buf[strlen(buf)], " 0x%x", *cp++);
	}
	(void) sprintf(&buf[strlen(buf)], " ]");
	NDBG25(("%s\n", buf));
	NDBG25(("pkt_flags=0x%x pkt_statistics=0x%x pkt_state=0x%x\n",
	    cmd->cmd_pkt->pkt_flags, cmd->cmd_pkt->pkt_statistics,
	    cmd->cmd_pkt->pkt_state));
	NDBG25(("pkt_scbp=0x%x cmd_flags=0x%x\n", cmd->cmd_pkt->pkt_scbp ?
	    *(cmd->cmd_pkt->pkt_scbp) : 0, cmd->cmd_flags));
}

static void
mptsas_passthru_sge(ddi_acc_handle_t acc_hdl, mptsas_pt_request_t *pt,
    pMpi2SGESimple64_t sgep)
{
	uint32_t		sge_flags;
	uint32_t		data_size, dataout_size;
	ddi_dma_cookie_t	data_cookie;
	ddi_dma_cookie_t	dataout_cookie;

	data_size = pt->data_size;
	dataout_size = pt->dataout_size;
	data_cookie = pt->data_cookie;
	dataout_cookie = pt->dataout_cookie;

	if (dataout_size) {
		sge_flags = dataout_size |
		    ((uint32_t)(MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
		    MPI2_SGE_FLAGS_END_OF_BUFFER |
		    MPI2_SGE_FLAGS_HOST_TO_IOC |
		    MPI2_SGE_FLAGS_64_BIT_ADDRESSING) <<
		    MPI2_SGE_FLAGS_SHIFT);
		ddi_put32(acc_hdl, &sgep->FlagsLength, sge_flags);
		ddi_put32(acc_hdl, &sgep->Address.Low,
		    (uint32_t)(dataout_cookie.dmac_laddress & 0xffffffffull));
		ddi_put32(acc_hdl, &sgep->Address.High,
		    (uint32_t)(dataout_cookie.dmac_laddress >> 32));
		sgep++;
	}
	sge_flags = data_size;
	sge_flags |= ((uint32_t)(MPI2_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI2_SGE_FLAGS_LAST_ELEMENT |
	    MPI2_SGE_FLAGS_END_OF_BUFFER |
	    MPI2_SGE_FLAGS_END_OF_LIST |
	    MPI2_SGE_FLAGS_64_BIT_ADDRESSING) <<
	    MPI2_SGE_FLAGS_SHIFT);
	if (pt->direction == MPTSAS_PASS_THRU_DIRECTION_WRITE) {
		sge_flags |= ((uint32_t)(MPI2_SGE_FLAGS_HOST_TO_IOC) <<
		    MPI2_SGE_FLAGS_SHIFT);
	} else {
		sge_flags |= ((uint32_t)(MPI2_SGE_FLAGS_IOC_TO_HOST) <<
		    MPI2_SGE_FLAGS_SHIFT);
	}
	ddi_put32(acc_hdl, &sgep->FlagsLength, sge_flags);
	ddi_put32(acc_hdl, &sgep->Address.Low,
	    (uint32_t)(data_cookie.dmac_laddress & 0xffffffffull));
	ddi_put32(acc_hdl, &sgep->Address.High,
	    (uint32_t)(data_cookie.dmac_laddress >> 32));
}

static void
mptsas_passthru_ieee_sge(ddi_acc_handle_t acc_hdl, mptsas_pt_request_t *pt,
    pMpi2IeeeSgeSimple64_t ieeesgep)
{
	uint8_t			sge_flags;
	uint32_t		data_size, dataout_size;
	ddi_dma_cookie_t	data_cookie;
	ddi_dma_cookie_t	dataout_cookie;

	data_size = pt->data_size;
	dataout_size = pt->dataout_size;
	data_cookie = pt->data_cookie;
	dataout_cookie = pt->dataout_cookie;

	sge_flags = (MPI2_IEEE_SGE_FLAGS_SIMPLE_ELEMENT |
	    MPI2_IEEE_SGE_FLAGS_SYSTEM_ADDR);
	if (dataout_size) {
		ddi_put32(acc_hdl, &ieeesgep->Length, dataout_size);
		ddi_put32(acc_hdl, &ieeesgep->Address.Low,
		    (uint32_t)(dataout_cookie.dmac_laddress &
		    0xffffffffull));
		ddi_put32(acc_hdl, &ieeesgep->Address.High,
		    (uint32_t)(dataout_cookie.dmac_laddress >> 32));
		ddi_put8(acc_hdl, &ieeesgep->Flags, sge_flags);
		ieeesgep++;
	}
	sge_flags |= MPI25_IEEE_SGE_FLAGS_END_OF_LIST;
	ddi_put32(acc_hdl, &ieeesgep->Length, data_size);
	ddi_put32(acc_hdl, &ieeesgep->Address.Low,
	    (uint32_t)(data_cookie.dmac_laddress & 0xffffffffull));
	ddi_put32(acc_hdl, &ieeesgep->Address.High,
	    (uint32_t)(data_cookie.dmac_laddress >> 32));
	ddi_put8(acc_hdl, &ieeesgep->Flags, sge_flags);
}

static void
mptsas_start_passthru(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	caddr_t			memp;
	pMPI2RequestHeader_t	request_hdrp;
	struct scsi_pkt		*pkt = cmd->cmd_pkt;
	mptsas_pt_request_t	*pt = pkt->pkt_ha_private;
	uint32_t		request_size;
	uint64_t		request_desc = 0;
	uint8_t			desc_type;
	uint16_t		SMID;
	uint8_t			*request, function;
	ddi_dma_handle_t	dma_hdl = mpt->m_dma_req_frame_hdl;
	ddi_acc_handle_t	acc_hdl = mpt->m_acc_req_frame_hdl;

	desc_type = MPI2_REQ_DESCRIPT_FLAGS_DEFAULT_TYPE;

	request = pt->request;
	request_size = pt->request_size;

	SMID = cmd->cmd_slot;

	/*
	 * Store the passthrough message in memory location
	 * corresponding to our slot number
	 */
	memp = mpt->m_req_frame + (mpt->m_req_frame_size * SMID);
	request_hdrp = (pMPI2RequestHeader_t)memp;
	bzero(memp, mpt->m_req_frame_size);

	bcopy(request, memp, request_size);

	NDBG15(("%d: start_passthru: Func 0x%x, MsgFlags 0x%x, "
	    "size=%d, in %d, out %d, SMID %d", mpt->m_instance,
	    request_hdrp->Function, request_hdrp->MsgFlags, request_size,
	    pt->data_size, pt->dataout_size, SMID));

	/*
	 * Add an SGE, even if the length is zero.
	 */
	if (mpt->m_MPI25 && pt->simple == 0) {
		mptsas_passthru_ieee_sge(acc_hdl, pt,
		    (pMpi2IeeeSgeSimple64_t)
		    ((uint8_t *)request_hdrp + pt->sgl_offset));
	} else {
		mptsas_passthru_sge(acc_hdl, pt,
		    (pMpi2SGESimple64_t)
		    ((uint8_t *)request_hdrp + pt->sgl_offset));
	}

	function = request_hdrp->Function;
	if ((function == MPI2_FUNCTION_SCSI_IO_REQUEST) ||
	    (function == MPI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH)) {
		pMpi2SCSIIORequest_t	scsi_io_req;
		caddr_t			arsbuf;
		uint8_t			ars_size;
		uint32_t		ars_dmaaddrlow;

		NDBG15(("%d: start_passthru: Is SCSI IO Req",
		    mpt->m_instance));
		scsi_io_req = (pMpi2SCSIIORequest_t)request_hdrp;

		if (cmd->cmd_extrqslen != 0) {
			/*
			 * Mapping of the buffer index was done in
			 * mptsas_do_passthru().
			 * Calculate the actual buffer address and
			 * DMA address with the same offset.
			 */
			arsbuf = mpt->m_extreq_sense +
			    (cmd->cmd_extrqsidx * mpt->m_req_sense_size);
			ars_size = cmd->cmd_extrqslen;
			ars_dmaaddrlow = (mpt->m_req_sense_dma_addr +
			    ((uintptr_t)arsbuf - (uintptr_t)mpt->m_req_sense)) &
			    0xffffffffull;
		} else {
			arsbuf = mpt->m_req_sense +
			    (mpt->m_req_sense_size * (SMID-1));
			ars_size = mpt->m_req_sense_size;
			ars_dmaaddrlow = (mpt->m_req_sense_dma_addr +
			    (mpt->m_req_sense_size * (SMID-1))) &
			    0xffffffffull;
		}
		cmd->cmd_arq_buf = arsbuf;
		bzero(arsbuf, ars_size);

		ddi_put8(acc_hdl, &scsi_io_req->SenseBufferLength, ars_size);
		ddi_put32(acc_hdl, &scsi_io_req->SenseBufferLowAddress,
		    ars_dmaaddrlow);

		/*
		 * Put SGE for data and data_out buffer at the end of
		 * scsi_io_request message header.(64 bytes in total)
		 * Set SGLOffset0 value
		 */
		ddi_put8(acc_hdl, &scsi_io_req->SGLOffset0,
		    offsetof(MPI2_SCSI_IO_REQUEST, SGL) / 4);

		/*
		 * Setup descriptor info.  RAID passthrough must use the
		 * default request descriptor which is already set, so if this
		 * is a SCSI IO request, change the descriptor to SCSI IO.
		 */
		if (function == MPI2_FUNCTION_SCSI_IO_REQUEST) {
			desc_type = MPI2_REQ_DESCRIPT_FLAGS_SCSI_IO;
			request_desc = (((uint64_t)ddi_get16(acc_hdl,
			    &scsi_io_req->DevHandle)) << 48);
		}
		(void) ddi_dma_sync(mpt->m_dma_req_sense_hdl, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		pkt->pkt_start = gethrtime();
	}

	/*
	 * We must wait till the message has been completed before
	 * beginning the next message so we wait for this one to
	 * finish.
	 */
	(void) ddi_dma_sync(dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV);
	request_desc |= ((SMID << 16) | desc_type);
	cmd->cmd_rfm = 0;
	MPTSAS_START_CMD(mpt, request_desc);
	if ((mptsas_check_dma_handle(dma_hdl) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(acc_hdl) != DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
	}
}

typedef void (mps_pre_f)(mptsas_t *, mptsas_pt_request_t *);
static mps_pre_f	mpi_pre_ioc_facts;
static mps_pre_f	mpi_pre_port_facts;
static mps_pre_f	mpi_pre_fw_download;
static mps_pre_f	mpi_pre_fw_25_download;
static mps_pre_f	mpi_pre_fw_upload;
static mps_pre_f	mpi_pre_fw_25_upload;
static mps_pre_f	mpi_pre_sata_passthrough;
static mps_pre_f	mpi_pre_smp_passthrough;
static mps_pre_f	mpi_pre_config;
static mps_pre_f	mpi_pre_sas_io_unit_control;
static mps_pre_f	mpi_pre_scsi_io_req;

/*
 * Prepare the pt for a SAS2 FW_DOWNLOAD request.
 */
static void
mpi_pre_fw_download(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
	pMpi2FWDownloadTCSGE_t tcsge;
	pMpi2FWDownloadRequest req;

	/*
	 * If SAS3, call separate function.
	 */
	if (mpt->m_MPI25) {
		mpi_pre_fw_25_download(mpt, pt);
		return;
	}

	/*
	 * User requests should come in with the Transaction
	 * context element where the SGL will go. Putting the
	 * SGL after that seems to work, but don't really know
	 * why. Other drivers tend to create an extra SGL and
	 * refer to the TCE through that.
	 */
	req = (pMpi2FWDownloadRequest)pt->request;
	tcsge = (pMpi2FWDownloadTCSGE_t)&req->SGL;
	if (tcsge->ContextSize != 0 || tcsge->DetailsLength != 12 ||
	    tcsge->Flags != MPI2_SGE_FLAGS_TRANSACTION_ELEMENT) {
		mptsas_log(mpt, CE_WARN, "FW Download tce invalid!");
	}

	pt->sgl_offset = offsetof(MPI2_FW_DOWNLOAD_REQUEST, SGL) +
	    sizeof (*tcsge);
	if (pt->request_size != pt->sgl_offset) {
		NDBG15(("%d: mpi_pre_fw_download(): Incorrect req size, "
		    "0x%x, should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    (int)pt->request_size, (int)pt->sgl_offset,
		    (int)pt->dataout_size));
	}
	if (pt->data_size < sizeof (MPI2_FW_DOWNLOAD_REPLY)) {
		NDBG15(("%d: mpi_pre_fw_download(): Incorrect rep size, "
		    "0x%x, should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_FW_DOWNLOAD_REPLY)));
	}
}

/*
 * Prepare the pt for a SAS3 FW_DOWNLOAD request.
 */
static void
mpi_pre_fw_25_download(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
	pMpi2FWDownloadTCSGE_t tcsge;
	pMpi2FWDownloadRequest req2;
	pMpi25FWDownloadRequest req25;

	/*
	 * User requests should come in with the Transaction
	 * context element where the SGL will go. The new firmware
	 * Doesn't use TCE and has space in the main request for
	 * this information. So move to the right place.
	 */
	req2 = (pMpi2FWDownloadRequest)pt->request;
	req25 = (pMpi25FWDownloadRequest)pt->request;
	tcsge = (pMpi2FWDownloadTCSGE_t)&req2->SGL;
	if (tcsge->ContextSize != 0 || tcsge->DetailsLength != 12 ||
	    tcsge->Flags != MPI2_SGE_FLAGS_TRANSACTION_ELEMENT) {
		mptsas_log(mpt, CE_WARN, "FW Download tce invalid!");
	}
	req25->ImageOffset = tcsge->ImageOffset;
	req25->ImageSize = tcsge->ImageSize;

	pt->sgl_offset = offsetof(MPI25_FW_DOWNLOAD_REQUEST, SGL);
	if (pt->request_size != pt->sgl_offset) {
		NDBG15(("%d: mpi_pre_fw_25_download(): Incorrect req size, "
		    "0x%x, should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size, pt->sgl_offset,
		    pt->dataout_size));
	}
	if (pt->data_size < sizeof (MPI2_FW_DOWNLOAD_REPLY)) {
		NDBG15(("%d: mpi_pre_fw_25_download(): Incorrect rep size, "
		    "0x%x, should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_FW_UPLOAD_REPLY)));
	}
}

/*
 * Prepare the pt for a SAS2 FW_UPLOAD request.
 */
static void
mpi_pre_fw_upload(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
	pMpi2FWUploadTCSGE_t tcsge;
	pMpi2FWUploadRequest_t req;

	/*
	 * If SAS3, call separate function.
	 */
	if (mpt->m_MPI25) {
		mpi_pre_fw_25_upload(mpt, pt);
		return;
	}

	/*
	 * User requests should come in with the Transaction
	 * context element where the SGL will go. Putting the
	 * SGL after that seems to work, but don't really know
	 * why. Other drivers tend to create an extra SGL and
	 * refer to the TCE through that.
	 */
	req = (pMpi2FWUploadRequest_t)pt->request;
	tcsge = (pMpi2FWUploadTCSGE_t)&req->SGL;
	if (tcsge->ContextSize != 0 || tcsge->DetailsLength != 12 ||
	    tcsge->Flags != MPI2_SGE_FLAGS_TRANSACTION_ELEMENT) {
		mptsas_log(mpt, CE_WARN, "FW Upload tce invalid!");
	}

	pt->sgl_offset = offsetof(MPI2_FW_UPLOAD_REQUEST, SGL) +
	    sizeof (*tcsge);
	if (pt->request_size != pt->sgl_offset) {
		NDBG15(("%d: mpi_pre_fw_upload(): Incorrect req size, "
		    "0x%x, should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size, pt->sgl_offset,
		    pt->dataout_size));
	}
	if (pt->data_size < sizeof (MPI2_FW_UPLOAD_REPLY)) {
		NDBG15(("%d: mpi_pre_fw_upload(): Incorrect rep size, "
		    "0x%x, should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_FW_UPLOAD_REPLY)));
	}
}

/*
 * Prepare the pt a SAS3 FW_UPLOAD request.
 */
static void
mpi_pre_fw_25_upload(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
	pMpi2FWUploadTCSGE_t tcsge;
	pMpi2FWUploadRequest_t req2;
	pMpi25FWUploadRequest_t req25;

	/*
	 * User requests should come in with the Transaction
	 * context element where the SGL will go. The new firmware
	 * Doesn't use TCE and has space in the main request for
	 * this information. So move to the right place.
	 */
	req2 = (pMpi2FWUploadRequest_t)pt->request;
	req25 = (pMpi25FWUploadRequest_t)pt->request;
	tcsge = (pMpi2FWUploadTCSGE_t)&req2->SGL;
	if (tcsge->ContextSize != 0 || tcsge->DetailsLength != 12 ||
	    tcsge->Flags != MPI2_SGE_FLAGS_TRANSACTION_ELEMENT) {
		mptsas_log(mpt, CE_WARN, "FW Upload tce invalid!");
	}
	req25->ImageOffset = tcsge->ImageOffset;
	req25->ImageSize = tcsge->ImageSize;

	pt->sgl_offset = offsetof(MPI25_FW_UPLOAD_REQUEST, SGL);
	if (pt->request_size != pt->sgl_offset) {
		NDBG15(("%d: mpi_pre_fw_25_upload(): Incorrect req size, "
		    "0x%x, should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size, pt->sgl_offset,
		    pt->dataout_size));
	}
	if (pt->data_size < sizeof (MPI2_FW_UPLOAD_REPLY)) {
		NDBG15(("%d: mpi_pre_fw_25_upload(): Incorrect rep size, "
		    "0x%x, should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_FW_UPLOAD_REPLY)));
	}
}

/*
 * Prepare the pt for an IOC_FACTS request.
 */
static void
mpi_pre_ioc_facts(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(mpt))
#endif
	if (pt->request_size != sizeof (MPI2_IOC_FACTS_REQUEST)) {
		NDBG15(("%d: mpi_pre_ioc_facts(): Incorrect req size, "
		    "0x%x, should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size,
		    (int)sizeof (MPI2_IOC_FACTS_REQUEST),
		    pt->dataout_size));
	}
	if (pt->data_size != sizeof (MPI2_IOC_FACTS_REPLY)) {
		NDBG15(("%d: mpi_pre_ioc_facts(): Incorrect rep size, "
		    "0x%x, should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_IOC_FACTS_REPLY)));
	}
	pt->sgl_offset = (uint16_t)pt->request_size;
}

/*
 * Prepare the pt for a PORT_FACTS request.
 */
static void
mpi_pre_port_facts(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(mpt))
#endif
	if (pt->request_size != sizeof (MPI2_PORT_FACTS_REQUEST)) {
		NDBG15(("%d: mpi_pre_port_facts(): Incorrect req size, "
		    "0x%x, should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size,
		    (int)sizeof (MPI2_PORT_FACTS_REQUEST),
		    pt->dataout_size));
	}
	if (pt->data_size != sizeof (MPI2_PORT_FACTS_REPLY)) {
		NDBG15(("%d: mpi_pre_port_facts(): Incorrect rep size, "
		    "0x%x, should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_PORT_FACTS_REPLY)));
	}
	pt->sgl_offset = (uint16_t)pt->request_size;
}

/*
 * Prepare pt for a SATA_PASSTHROUGH request.
 */
static void
mpi_pre_sata_passthrough(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(mpt))
#endif
	pt->sgl_offset = offsetof(MPI2_SATA_PASSTHROUGH_REQUEST, SGL);
	if (pt->request_size != pt->sgl_offset) {
		NDBG15(("%d: mpi_pre_sata_passthrough(): Incorrect req size, "
		    "0x%x, should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size, pt->sgl_offset,
		    pt->dataout_size));
	}
	if (pt->data_size != sizeof (MPI2_SATA_PASSTHROUGH_REPLY)) {
		NDBG15(("%d: mpi_pre_sata_passthrough(): Incorrect rep size, "
		    "0x%x, should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_SATA_PASSTHROUGH_REPLY)));
	}
}

static void
mpi_pre_smp_passthrough(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(mpt))
#endif
	pt->sgl_offset = offsetof(MPI2_SMP_PASSTHROUGH_REQUEST, SGL);
	if (pt->request_size != pt->sgl_offset) {
		NDBG15(("%d: mpi_pre_smp_passthrough(): Incorrect req size, "
		    "0x%x, should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size, pt->sgl_offset,
		    pt->dataout_size));
	}
	if (pt->data_size != sizeof (MPI2_SMP_PASSTHROUGH_REPLY)) {
		NDBG15(("%d: mpi_pre_smp_passthrough(): Incorrect rep size, "
		    "0x%x, should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_SMP_PASSTHROUGH_REPLY)));
	}
}

/*
 * Prepare pt for a CONFIG request.
 */
static void
mpi_pre_config(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(mpt))
#endif
	pt->sgl_offset = offsetof(MPI2_CONFIG_REQUEST, PageBufferSGE);
	if (pt->request_size != pt->sgl_offset) {
		NDBG15(("%d: mpi_pre_config(): Incorrect req size, 0x%x, "
		    "should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size, pt->sgl_offset, pt->dataout_size));
	}
	if (pt->data_size != sizeof (MPI2_CONFIG_REPLY)) {
		NDBG15(("%d: mpi_pre_config(): Incorrect rep size, 0x%x, "
		    "should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_CONFIG_REPLY)));
	}
	pt->simple = 1;
}

/*
 * Prepare pt for a SCSI_IO_REQ request.
 */
static void
mpi_pre_scsi_io_req(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(mpt))
#endif
	pt->sgl_offset = offsetof(MPI2_SCSI_IO_REQUEST, SGL);
	if (pt->request_size != pt->sgl_offset) {
		NDBG15(("%d: mpi_pre_config(): Incorrect req size, 0x%x, "
		    "should be 0x%x, dataoutsz 0x%x", mpt->m_instance,
		    pt->request_size, pt->sgl_offset, pt->dataout_size));
	}
	if (pt->data_size != sizeof (MPI2_SCSI_IO_REPLY)) {
		NDBG15(("%d: mpi_pre_config(): Incorrect rep size, 0x%x, "
		    "should be 0x%x", mpt->m_instance, pt->data_size,
		    (int)sizeof (MPI2_SCSI_IO_REPLY)));
	}
}

/*
 * Prepare the mps_command for a SAS_IO_UNIT_CONTROL request.
 */
static void
mpi_pre_sas_io_unit_control(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(mpt))
#endif
	pt->sgl_offset = (uint16_t)pt->request_size;
}

/*
 * A set of functions to prepare an mps_command for the various
 * supported requests.
 */
struct mps_func {
	U8		Function;
	char		*Name;
	mps_pre_f	*f_pre;
} mps_func_list[] = {
	{ MPI2_FUNCTION_IOC_FACTS, "IOC_FACTS",		mpi_pre_ioc_facts },
	{ MPI2_FUNCTION_PORT_FACTS, "PORT_FACTS",	mpi_pre_port_facts },
	{ MPI2_FUNCTION_FW_DOWNLOAD, "FW_DOWNLOAD",	mpi_pre_fw_download },
	{ MPI2_FUNCTION_FW_UPLOAD, "FW_UPLOAD",		mpi_pre_fw_upload },
	{ MPI2_FUNCTION_SATA_PASSTHROUGH, "SATA_PASSTHROUGH",
	    mpi_pre_sata_passthrough },
	{ MPI2_FUNCTION_SMP_PASSTHROUGH, "SMP_PASSTHROUGH",
	    mpi_pre_smp_passthrough},
	{ MPI2_FUNCTION_SCSI_IO_REQUEST, "SCSI_IO_REQUEST",
	    mpi_pre_scsi_io_req},
	{ MPI2_FUNCTION_CONFIG, "CONFIG",		mpi_pre_config},
	{ MPI2_FUNCTION_SAS_IO_UNIT_CONTROL, "SAS_IO_UNIT_CONTROL",
	    mpi_pre_sas_io_unit_control },
	{ 0xFF, NULL,				NULL } /* list end */
};

static void
mptsas_prep_sgl_offset(mptsas_t *mpt, mptsas_pt_request_t *pt)
{
	pMPI2RequestHeader_t	hdr;
	struct mps_func		*f;

	hdr = (pMPI2RequestHeader_t)pt->request;

	for (f = mps_func_list; f->f_pre != NULL; f++) {
		if (hdr->Function == f->Function) {
			f->f_pre(mpt, pt);
			NDBG15(("%d: prep_sgl_offset: Function %s,"
			    " sgl_offset 0x%x", mpt->m_instance, f->Name,
			    pt->sgl_offset));
			return;
		}
	}
	NDBG15(("%d: prep_sgl_offset: Unknown Function 0x%02x,"
	    " returning req_size 0x%x for sgl_offset", mpt->m_instance,
	    hdr->Function, pt->request_size));
	pt->sgl_offset = (uint16_t)pt->request_size;
}


static int
mptsas_do_passthru(mptsas_t *mpt, uint8_t *request, uint8_t *reply,
    uint8_t *data, uint32_t request_size, uint32_t reply_size,
    uint32_t data_size, uint8_t direction, uint8_t *dataout,
    uint32_t dataout_size, short timeout, int mode)
{
	mptsas_pt_request_t		pt;
	mptsas_dma_alloc_state_t	data_dma_state;
	mptsas_dma_alloc_state_t	dataout_dma_state;
	mptsas_cmd_t			*cmd = NULL;
	struct scsi_pkt			*pkt;
	uint32_t			reply_len = 0, sense_len = 0;
	pMPI2RequestHeader_t		request_msg;
	pMPI2DefaultReply_t		reply_msg;
	Mpi2SCSIIOReply_t		rep_msg;
	int				status = 0, pt_flags = 0, rv = 0;
	uint8_t				function;

	ASSERT(mutex_owned(&mpt->m_mutex));

	reply_msg = (pMPI2DefaultReply_t)(&rep_msg);
	bzero(reply_msg, sizeof (MPI2_DEFAULT_REPLY));
	request_msg = kmem_zalloc(request_size, KM_SLEEP);

	mutex_exit(&mpt->m_mutex);
	/*
	 * copy in the request buffer since it could be used by
	 * another thread when the pt request into waitq
	 */
	if (ddi_copyin(request, request_msg, request_size, mode)) {
		mutex_enter(&mpt->m_mutex);
		status = EFAULT;
		mptsas_log(mpt, CE_WARN, "failed to copy request data");
		goto out;
	}
	NDBG15(("%d: do_passthru: mode 0x%x, size 0x%x, Func 0x%x",
	    mpt->m_instance, mode, request_size, request_msg->Function));
	mutex_enter(&mpt->m_mutex);

	function = request_msg->Function;
	if (function == MPI2_FUNCTION_SCSI_TASK_MGMT) {
		pMpi2SCSITaskManagementRequest_t	task;
		task = (pMpi2SCSITaskManagementRequest_t)request_msg;
		mptsas_setup_bus_reset_delay(mpt);
		rv = mptsas_ioc_task_management(mpt, task->TaskType,
		    task->DevHandle, (int)task->LUN[1], reply, reply_size,
		    mode, B_TRUE);

		if (rv != TRUE) {
			status = EIO;
			mptsas_log(mpt, CE_WARN, "task management failed");
		}
		goto out;
	}

	if (data_size != 0) {
		data_dma_state.size = data_size;
		if (mptsas_dma_alloc(mpt, &data_dma_state) != DDI_SUCCESS) {
			status = ENOMEM;
			mptsas_log(mpt, CE_WARN, "failed to alloc DMA "
			    "resource");
			goto out;
		}
		pt_flags |= MPTSAS_DATA_ALLOCATED;
		if (direction == MPTSAS_PASS_THRU_DIRECTION_WRITE) {
			mutex_exit(&mpt->m_mutex);
			if (ddi_copyin(data, (uint8_t *)
			    data_dma_state.memp, data_size, mode)) {
				mutex_enter(&mpt->m_mutex);
				status = EFAULT;
				mptsas_log(mpt, CE_WARN, "failed to "
				    "copy read data");
				goto out;
			}
			mutex_enter(&mpt->m_mutex);
		}
	}
	else
		bzero(&data_dma_state, sizeof (data_dma_state));

	if (dataout_size != 0) {
		dataout_dma_state.size = dataout_size;
		if (mptsas_dma_alloc(mpt, &dataout_dma_state) != DDI_SUCCESS) {
			status = ENOMEM;
			mptsas_log(mpt, CE_WARN, "failed to alloc DMA "
			    "resource");
			goto out;
		}
		pt_flags |= MPTSAS_DATAOUT_ALLOCATED;
		mutex_exit(&mpt->m_mutex);
		if (ddi_copyin(dataout, (uint8_t *)
		    dataout_dma_state.memp, dataout_size, mode)) {
			mutex_enter(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "failed to copy out data");
			status = EFAULT;
			goto out;
		}
		mutex_enter(&mpt->m_mutex);
	}
	else
		bzero(&dataout_dma_state, sizeof (dataout_dma_state));

	mptsas_request_from_pool(mpt, &cmd, &pkt);
	pt_flags |= MPTSAS_REQUEST_POOL_CMD;

	bzero((caddr_t)&pt, sizeof (pt));

	pt.request = (uint8_t *)request_msg;
	pt.direction = direction;
	pt.simple = 0;
	pt.request_size = request_size;
	pt.data_size = data_size;
	pt.dataout_size = dataout_size;
	pt.data_cookie = data_dma_state.cookie;
	pt.dataout_cookie = dataout_dma_state.cookie;
	mptsas_prep_sgl_offset(mpt, &pt);

	/*
	 * Form a blank cmd/pkt to store the acknowledgement message
	 */
	pkt->pkt_cdbp		= (opaque_t)&cmd->cmd_cdb[0];
	pkt->pkt_scbp		= (opaque_t)&cmd->cmd_scb;
	pkt->pkt_ha_private	= (opaque_t)&pt;
	pkt->pkt_flags		= FLAG_HEAD;
	pkt->pkt_time		= timeout;
	cmd->cmd_pkt		= pkt;
	cmd->cmd_flags		= CFLAG_CMDIOC | CFLAG_PASSTHRU;

	if ((function == MPI2_FUNCTION_SCSI_IO_REQUEST) ||
	    (function == MPI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH)) {
		uint8_t			com, cdb_group_id;

		pkt->pkt_cdbp = ((pMpi2SCSIIORequest_t)request_msg)->CDB.CDB32;
		com = pkt->pkt_cdbp[0];
		cdb_group_id = CDB_GROUPID(com);
		switch (cdb_group_id) {
		case CDB_GROUPID_0: cmd->cmd_cdblen = CDB_GROUP0; break;
		case CDB_GROUPID_1: cmd->cmd_cdblen = CDB_GROUP1; break;
		case CDB_GROUPID_2: cmd->cmd_cdblen = CDB_GROUP2; break;
		case CDB_GROUPID_4: cmd->cmd_cdblen = CDB_GROUP4; break;
		case CDB_GROUPID_5: cmd->cmd_cdblen = CDB_GROUP5; break;
		default:
			NDBG15(("%d: do_passthru: SCSI_IO, reserved "
			    "CDBGROUP 0x%x requested!", mpt->m_instance,
			    cdb_group_id));
			break;
		}

		reply_len = sizeof (MPI2_SCSI_IO_REPLY);
		sense_len = reply_size - reply_len;
		mptsas_cmdarqsize(mpt, cmd, sense_len);
	} else {
		reply_len = reply_size;
		sense_len = 0;
	}

	NDBG15(("%d: do_passthru: %s, dsz 0x%x, dosz 0x%x, replen 0x%x, "
	    "snslen 0x%x", mpt->m_instance,
	    (direction == MPTSAS_PASS_THRU_DIRECTION_WRITE)?"Write":"Read",
	    data_size, dataout_size, reply_len, sense_len));

	/*
	 * Save the command in a slot
	 */
	if (mptsas_save_ioccmd(mpt, cmd) == TRUE) {
		/*
		 * Once passthru command get slot, set cmd_flags
		 * CFLAG_PREPARED.
		 */
		cmd->cmd_flags |= CFLAG_PREPARED;
		mptsas_start_passthru(mpt, cmd);
	} else if (mpt->m_in_reset == TRUE) {
		mptsas_set_pkt_reason(mpt, cmd, CMD_RESET, STAT_BUS_RESET);
		status = EAGAIN;
		mptsas_log(mpt, CE_WARN, "passthru while reset");
		goto out;
	} else {
		mptsas_waitq_add(mpt, cmd);
	}

	while ((cmd->cmd_flags & CFLAG_FINISHED) == 0) {
		cv_wait(&mpt->m_passthru_cv, &mpt->m_mutex);
	}

	NDBG15(("%d: do_passthru: Cmd complete, flags 0x%x, rfm 0x%x "
	    "pktreason 0x%x", mpt->m_instance, cmd->cmd_flags, cmd->cmd_rfm,
	    pkt->pkt_reason));

	if (cmd->cmd_flags & CFLAG_TIMEOUT) {
		status = ETIMEDOUT;
		pt_flags |= MPTSAS_CMD_TIMEOUT;
		goto out;
	}

	if (cmd->cmd_rfm) {
		/*
		 * cmd_rfm is zero means the command reply is a CONTEXT
		 * reply and no PCI Write to post the free reply SMFA
		 * because no reply message frame is used.
		 * cmd_rfm is non-zero means the reply is a ADDRESS
		 * reply and reply message frame is used.
		 */
		pt_flags |= MPTSAS_ADDRESS_REPLY;
		(void) ddi_dma_sync(mpt->m_dma_reply_frame_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		reply_msg = (pMPI2DefaultReply_t)
		    (mpt->m_reply_frame + (cmd->cmd_rfm -
		    (mpt->m_reply_frame_dma_addr&0xfffffffful)));
	}

	mptsas_fma_check(mpt, cmd);
	if (pkt->pkt_reason != CMD_CMPLT) {
		switch (pkt->pkt_reason) {
		case CMD_TRAN_ERR:
			status = EAGAIN;
			mptsas_log(mpt, CE_WARN, "passthru fma error");
			break;
		case CMD_RESET:
			status = EAGAIN;
			mptsas_log(mpt, CE_WARN, "ioc reset abort passthru");
			break;
		case CMD_INCOMPLETE:
			status = EIO;
			mptsas_log(mpt, CE_WARN,
			    "passthrough command incomplete");
			break;
		default:
			status = EIO;
			mptsas_log(mpt, CE_WARN, "mptsas_do_passthru: Bad pkt "
			    "reason 0x%x(%s)", pkt->pkt_reason,
			    scsi_rname(pkt->pkt_reason));
			break;
		}
		goto out;
	}

	mutex_exit(&mpt->m_mutex);
	if (cmd->cmd_flags & CFLAG_PREPARED) {
		if ((function == MPI2_FUNCTION_SCSI_IO_REQUEST) ||
		    (function == MPI2_FUNCTION_RAID_SCSI_IO_PASSTHROUGH)) {
			reply_len = sizeof (MPI2_SCSI_IO_REPLY);
			sense_len = cmd->cmd_extrqslen ?
			    min(sense_len, cmd->cmd_extrqslen) :
			    min(sense_len, cmd->cmd_rqslen);
		} else {
			reply_len = reply_size;
			sense_len = 0;
		}

		if (ddi_copyout((uint8_t *)reply_msg, reply, reply_len, mode)) {
			mutex_enter(&mpt->m_mutex);
			status = EFAULT;
			mptsas_log(mpt, CE_WARN, "passthru failed to copy out "
			    "reply data");
			goto out;
		}
		if (sense_len != 0) {
			(void) ddi_dma_sync(mpt->m_dma_req_sense_hdl,
			    0, 0, DDI_DMA_SYNC_FORCPU);
			if (ddi_copyout(cmd->cmd_arq_buf, reply + reply_len,
			    sense_len, mode)) {
				mutex_enter(&mpt->m_mutex);
				status = EFAULT;
				mptsas_log(mpt, CE_WARN, "passthru failed to "
				    "copy out sense data");
				goto out;
			}
		}
	}

	if (data_size) {
		if (direction != MPTSAS_PASS_THRU_DIRECTION_WRITE) {
			(void) ddi_dma_sync(data_dma_state.handle, 0, 0,
			    DDI_DMA_SYNC_FORCPU);
			if (ddi_copyout((uint8_t *)(data_dma_state.memp),
			    data, data_size, mode)) {
				mutex_enter(&mpt->m_mutex);
				status = EFAULT;
				mptsas_log(mpt, CE_WARN, "passthru failed to "
				    "copy out the reply data");
				goto out;
			}
		}
	}
	mutex_enter(&mpt->m_mutex);
out:
	/*
	 * Put the reply frame back on the free queue, increment the free
	 * index, and write the new index to the free index register.  But only
	 * if this reply is an ADDRESS reply.
	 */
	if (pt_flags & MPTSAS_ADDRESS_REPLY) {
		mptsas_return_replyframe(mpt, cmd->cmd_rfm);
	}
	if (cmd) {
		if (cmd->cmd_extrqslen != 0) {
			rmfree(mpt->m_erqsense_map, cmd->cmd_extrqschunks,
			    cmd->cmd_extrqsidx + 1);
		}
		if (cmd->cmd_flags & CFLAG_PREPARED) {
			mptsas_deref_ioccmd(mpt, cmd);
		}
	}
	if (pt_flags & MPTSAS_REQUEST_POOL_CMD)
		mptsas_return_to_pool(mpt, cmd);
	if (pt_flags & MPTSAS_DATA_ALLOCATED) {
		if (mptsas_check_dma_handle(data_dma_state.handle) !=
		    DDI_SUCCESS) {
			ddi_fm_service_impact(mpt->m_dip,
			    DDI_SERVICE_UNAFFECTED);
			status = EFAULT;
		}
		mptsas_dma_free(&data_dma_state);
	}
	if (pt_flags & MPTSAS_DATAOUT_ALLOCATED) {
		if (mptsas_check_dma_handle(dataout_dma_state.handle) !=
		    DDI_SUCCESS) {
			ddi_fm_service_impact(mpt->m_dip,
			    DDI_SERVICE_UNAFFECTED);
			status = EFAULT;
		}
		mptsas_dma_free(&dataout_dma_state);
	}
	if (pt_flags & MPTSAS_CMD_TIMEOUT) {
		mptsas_log(mpt, CE_WARN, "mptsas_do_passthru: Cmd Timeout, "
		    "schedule reset in watch!");
		mpt->m_softstate |= MPTSAS_SS_RESET_INWATCH;
	}
	if (request_msg)
		kmem_free(request_msg, request_size);
	NDBG15(("%d: do_passthru: Done status 0x%x", mpt->m_instance,
	    status));

	return (status);
}

static int
mptsas_pass_thru(mptsas_t *mpt, mptsas_pass_thru_t *data, int mode)
{
	/*
	 * If timeout is 0, set timeout to default of 60 seconds.
	 */
	if (data->Timeout == 0) {
		data->Timeout = MPTSAS_PASS_THRU_TIME_DEFAULT;
	}

	if (((data->DataSize == 0) &&
	    (data->DataDirection == MPTSAS_PASS_THRU_DIRECTION_NONE)) ||
	    ((data->DataSize != 0) &&
	    ((data->DataDirection == MPTSAS_PASS_THRU_DIRECTION_READ) ||
	    (data->DataDirection == MPTSAS_PASS_THRU_DIRECTION_WRITE) ||
	    ((data->DataDirection == MPTSAS_PASS_THRU_DIRECTION_BOTH) &&
	    (data->DataOutSize != 0))))) {
		if (data->DataDirection == MPTSAS_PASS_THRU_DIRECTION_BOTH) {
			data->DataDirection = MPTSAS_PASS_THRU_DIRECTION_READ;
		} else {
			data->DataOutSize = 0;
		}
		/*
		 * Send passthru request messages
		 */
		return (mptsas_do_passthru(mpt,
		    (uint8_t *)((uintptr_t)data->PtrRequest),
		    (uint8_t *)((uintptr_t)data->PtrReply),
		    (uint8_t *)((uintptr_t)data->PtrData),
		    data->RequestSize, data->ReplySize,
		    data->DataSize, (uint8_t)data->DataDirection,
		    (uint8_t *)((uintptr_t)data->PtrDataOut),
		    data->DataOutSize, data->Timeout, mode));
	} else {
		return (EINVAL);
	}
}

static uint8_t
mptsas_get_fw_diag_buffer_number(mptsas_t *mpt, uint32_t unique_id)
{
	uint8_t	index;

	for (index = 0; index < MPI2_DIAG_BUF_TYPE_COUNT; index++) {
		if (mpt->m_fw_diag_buffer_list[index].unique_id == unique_id) {
			return (index);
		}
	}

	return (MPTSAS_FW_DIAGNOSTIC_UID_NOT_FOUND);
}

static void
mptsas_start_diag(mptsas_t *mpt, mptsas_cmd_t *cmd)
{
	pMpi2DiagBufferPostRequest_t	pDiag_post_msg;
	pMpi2DiagReleaseRequest_t	pDiag_release_msg;
	struct scsi_pkt			*pkt = cmd->cmd_pkt;
	mptsas_diag_request_t		*diag = pkt->pkt_ha_private;
	uint32_t			i;
	uint64_t			request_desc;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Form the diag message depending on the post or release function.
	 */
	if (diag->function == MPI2_FUNCTION_DIAG_BUFFER_POST) {
		pDiag_post_msg = (pMpi2DiagBufferPostRequest_t)
		    (mpt->m_req_frame + (mpt->m_req_frame_size *
		    cmd->cmd_slot));
		bzero(pDiag_post_msg, mpt->m_req_frame_size);
		ddi_put8(mpt->m_acc_req_frame_hdl, &pDiag_post_msg->Function,
		    diag->function);
		ddi_put8(mpt->m_acc_req_frame_hdl, &pDiag_post_msg->BufferType,
		    diag->pBuffer->buffer_type);
		ddi_put8(mpt->m_acc_req_frame_hdl,
		    &pDiag_post_msg->ExtendedType,
		    diag->pBuffer->extended_type);
		ddi_put32(mpt->m_acc_req_frame_hdl,
		    &pDiag_post_msg->BufferLength,
		    diag->pBuffer->buffer_data.size);
		for (i = 0; i < (sizeof (pDiag_post_msg->ProductSpecific) / 4);
		    i++) {
			ddi_put32(mpt->m_acc_req_frame_hdl,
			    &pDiag_post_msg->ProductSpecific[i],
			    diag->pBuffer->product_specific[i]);
		}
		ddi_put32(mpt->m_acc_req_frame_hdl,
		    &pDiag_post_msg->BufferAddress.Low,
		    (uint32_t)(diag->pBuffer->buffer_data.cookie.dmac_laddress
		    & 0xffffffffull));
		ddi_put32(mpt->m_acc_req_frame_hdl,
		    &pDiag_post_msg->BufferAddress.High,
		    (uint32_t)(diag->pBuffer->buffer_data.cookie.dmac_laddress
		    >> 32));
	} else {
		pDiag_release_msg = (pMpi2DiagReleaseRequest_t)
		    (mpt->m_req_frame + (mpt->m_req_frame_size *
		    cmd->cmd_slot));
		bzero(pDiag_release_msg, mpt->m_req_frame_size);
		ddi_put8(mpt->m_acc_req_frame_hdl,
		    &pDiag_release_msg->Function, diag->function);
		ddi_put8(mpt->m_acc_req_frame_hdl,
		    &pDiag_release_msg->BufferType,
		    diag->pBuffer->buffer_type);
	}

	/*
	 * Send the message
	 */
	(void) ddi_dma_sync(mpt->m_dma_req_frame_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);
	request_desc = (cmd->cmd_slot << 16) |
	    MPI2_REQ_DESCRIPT_FLAGS_DEFAULT_TYPE;
	cmd->cmd_rfm = 0;
	MPTSAS_START_CMD(mpt, request_desc);
	if ((mptsas_check_dma_handle(mpt->m_dma_req_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_req_frame_hdl) !=
	    DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
	}
}

static int
mptsas_post_fw_diag_buffer(mptsas_t *mpt,
    mptsas_fw_diagnostic_buffer_t *pBuffer, uint32_t *return_code)
{
	mptsas_diag_request_t		diag;
	int				status, post_flags = 0;
	mptsas_cmd_t			*cmd = NULL;
	struct scsi_pkt			*pkt;
	pMpi2DiagBufferPostReply_t	reply;
	uint16_t			iocstatus;
	uint32_t			iocloginfo, transfer_length;

	/*
	 * If buffer is not enabled, just leave.
	 */
	*return_code = MPTSAS_FW_DIAG_ERROR_POST_FAILED;
	if (!pBuffer->enabled) {
		status = DDI_FAILURE;
		goto out;
	}

	/*
	 * Clear some flags initially.
	 */
	pBuffer->force_release = FALSE;
	pBuffer->valid_data = FALSE;
	pBuffer->owned_by_firmware = FALSE;

	/*
	 * Get a cmd buffer from the cmd buffer pool
	 */
	mptsas_request_from_pool(mpt, &cmd, &pkt);
	post_flags |= MPTSAS_REQUEST_POOL_CMD;

	bzero((caddr_t)cmd, sizeof (*cmd));
	bzero((caddr_t)pkt, scsi_pkt_size());

	diag.pBuffer = pBuffer;
	diag.function = MPI2_FUNCTION_DIAG_BUFFER_POST;

	/*
	 * Form a blank cmd/pkt to store the acknowledgement message
	 */
	pkt->pkt_ha_private	= (opaque_t)&diag;
	pkt->pkt_flags		= FLAG_HEAD;
	pkt->pkt_time		= 60;
	cmd->cmd_pkt		= pkt;
	cmd->cmd_flags		= CFLAG_CMDIOC | CFLAG_FW_DIAG;

	/*
	 * Save the command in a slot
	 */
	if (mptsas_save_ioccmd(mpt, cmd) == TRUE) {
		/*
		 * Once passthru command get slot, set cmd_flags
		 * CFLAG_PREPARED.
		 */
		cmd->cmd_flags |= CFLAG_PREPARED;
		mptsas_start_diag(mpt, cmd);
	} else {
		mptsas_waitq_add(mpt, cmd);
	}

	while ((cmd->cmd_flags & CFLAG_FINISHED) == 0) {
		cv_wait(&mpt->m_fw_diag_cv, &mpt->m_mutex);
	}

	if (cmd->cmd_flags & CFLAG_TIMEOUT) {
		status = DDI_FAILURE;
		mptsas_log(mpt, CE_WARN, "Post FW Diag command timeout");
		goto out;
	}

	if (pkt->pkt_reason != CMD_CMPLT) {
		mptsas_log(mpt, CE_WARN, "mptsas_post_fw_diag_buffer: Bad pkt "
		    "reason 0x%x(%s)", pkt->pkt_reason,
		    scsi_rname(pkt->pkt_reason));
		status = DDI_FAILURE;
		goto out;
	}

	/*
	 * cmd_rfm points to the reply message if a reply was given.  Check the
	 * IOCStatus to make sure everything went OK with the FW diag request
	 * and set buffer flags.
	 */
	if (cmd->cmd_rfm) {
		post_flags |= MPTSAS_ADDRESS_REPLY;
		(void) ddi_dma_sync(mpt->m_dma_reply_frame_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		reply = (pMpi2DiagBufferPostReply_t)(mpt->m_reply_frame +
		    (cmd->cmd_rfm -
		    (mpt->m_reply_frame_dma_addr&0xfffffffful)));

		/*
		 * Get the reply message data
		 */
		iocstatus = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCStatus);
		iocloginfo = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCLogInfo);
		transfer_length = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &reply->TransferLength);

		/*
		 * If post failed quit.
		 */
		if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
			status = DDI_FAILURE;
			NDBG13(("%d: post FW Diag Buffer failed: IOCStatus="
			    "0x%x, IOCLogInfo=0x%x, TransferLength=0x%x",
			    mpt->m_instance, iocstatus,
			    iocloginfo, transfer_length));
			goto out;
		}

		/*
		 * Post was successful.
		 */
		pBuffer->valid_data = TRUE;
		pBuffer->owned_by_firmware = TRUE;
		*return_code = MPTSAS_FW_DIAG_ERROR_SUCCESS;
		status = DDI_SUCCESS;
	}

out:
	/*
	 * Put the reply frame back on the free queue, increment the free
	 * index, and write the new index to the free index register.  But only
	 * if this reply is an ADDRESS reply.
	 */
	if (post_flags & MPTSAS_ADDRESS_REPLY) {
		mptsas_return_replyframe(mpt, cmd->cmd_rfm);
	}
	if (cmd && (cmd->cmd_flags & CFLAG_PREPARED)) {
		mptsas_deref_ioccmd(mpt, cmd);
	}
	if (post_flags & MPTSAS_REQUEST_POOL_CMD) {
		mptsas_return_to_pool(mpt, cmd);
	}

	return (status);
}

static int
mptsas_release_fw_diag_buffer(mptsas_t *mpt,
    mptsas_fw_diagnostic_buffer_t *pBuffer, uint32_t *return_code,
    uint32_t diag_type)
{
	mptsas_diag_request_t	diag;
	int			status, rel_flags = 0;
	mptsas_cmd_t		*cmd = NULL;
	struct scsi_pkt		*pkt;
	pMpi2DiagReleaseReply_t	reply;
	uint16_t		iocstatus;
	uint32_t		iocloginfo;

	/*
	 * If buffer is not enabled, just leave.
	 */
	*return_code = MPTSAS_FW_DIAG_ERROR_RELEASE_FAILED;
	if (!pBuffer->enabled) {
		mptsas_log(mpt, CE_NOTE, "This buffer type is not supported "
		    "by the IOC");
		status = DDI_FAILURE;
		goto out;
	}

	/*
	 * Clear some flags initially.
	 */
	pBuffer->force_release = FALSE;
	pBuffer->valid_data = FALSE;
	pBuffer->owned_by_firmware = FALSE;

	/*
	 * Get a cmd buffer from the cmd buffer pool
	 */
	mptsas_request_from_pool(mpt, &cmd, &pkt);
	rel_flags |= MPTSAS_REQUEST_POOL_CMD;

	bzero((caddr_t)cmd, sizeof (*cmd));
	bzero((caddr_t)pkt, scsi_pkt_size());

	diag.pBuffer = pBuffer;
	diag.function = MPI2_FUNCTION_DIAG_RELEASE;

	/*
	 * Form a blank cmd/pkt to store the acknowledgement message
	 */
	pkt->pkt_ha_private	= (opaque_t)&diag;
	pkt->pkt_flags		= FLAG_HEAD;
	pkt->pkt_time		= 60;
	cmd->cmd_pkt		= pkt;
	cmd->cmd_flags		= CFLAG_CMDIOC | CFLAG_FW_DIAG;

	/*
	 * Save the command in a slot
	 */
	if (mptsas_save_ioccmd(mpt, cmd) == TRUE) {
		/*
		 * Once passthru command get slot, set cmd_flags
		 * CFLAG_PREPARED.
		 */
		cmd->cmd_flags |= CFLAG_PREPARED;
		mptsas_start_diag(mpt, cmd);
	} else {
		mptsas_waitq_add(mpt, cmd);
	}

	while ((cmd->cmd_flags & CFLAG_FINISHED) == 0) {
		cv_wait(&mpt->m_fw_diag_cv, &mpt->m_mutex);
	}

	if (cmd->cmd_flags & CFLAG_TIMEOUT) {
		status = DDI_FAILURE;
		mptsas_log(mpt, CE_WARN, "Release FW Diag command timeout");
		goto out;
	}

	if (pkt->pkt_reason != CMD_CMPLT) {
		mptsas_log(mpt, CE_WARN, "mptsas_release_fw_diag_buffer: Bad "
		    "pkt reason 0x%x(%s)", pkt->pkt_reason,
		    scsi_rname(pkt->pkt_reason));
		status = DDI_FAILURE;
		goto out;
	}

	/*
	 * cmd_rfm points to the reply message if a reply was given.  Check the
	 * IOCStatus to make sure everything went OK with the FW diag request
	 * and set buffer flags.
	 */
	if (cmd->cmd_rfm) {
		rel_flags |= MPTSAS_ADDRESS_REPLY;
		(void) ddi_dma_sync(mpt->m_dma_reply_frame_hdl, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		reply = (pMpi2DiagReleaseReply_t)(mpt->m_reply_frame +
		    (cmd->cmd_rfm -
		    (mpt->m_reply_frame_dma_addr&0xfffffffful)));

		/*
		 * Get the reply message data
		 */
		iocstatus = ddi_get16(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCStatus);
		iocloginfo = ddi_get32(mpt->m_acc_reply_frame_hdl,
		    &reply->IOCLogInfo);

		/*
		 * If release failed quit.
		 */
		if ((iocstatus != MPI2_IOCSTATUS_SUCCESS) ||
		    pBuffer->owned_by_firmware) {
			status = DDI_FAILURE;
			NDBG13(("%d: release FW Diag Buffer failed: "
			    "IOCStatus=0x%x, IOCLogInfo=0x%x", mpt->m_instance,
			    iocstatus, iocloginfo));
			goto out;
		}

		/*
		 * Release was successful.
		 */
		*return_code = MPTSAS_FW_DIAG_ERROR_SUCCESS;
		status = DDI_SUCCESS;

		/*
		 * If this was for an UNREGISTER diag type command, clear the
		 * unique ID.
		 */
		if (diag_type == MPTSAS_FW_DIAG_TYPE_UNREGISTER) {
			pBuffer->unique_id = MPTSAS_FW_DIAG_INVALID_UID;
		}
	}

out:
	/*
	 * Put the reply frame back on the free queue, increment the free
	 * index, and write the new index to the free index register.  But only
	 * if this reply is an ADDRESS reply.
	 */
	if (rel_flags & MPTSAS_ADDRESS_REPLY) {
		mptsas_return_replyframe(mpt, cmd->cmd_rfm);
	}
	if (cmd && (cmd->cmd_flags & CFLAG_PREPARED)) {
		mptsas_deref_ioccmd(mpt, cmd);
	}
	if (rel_flags & MPTSAS_REQUEST_POOL_CMD) {
		mptsas_return_to_pool(mpt, cmd);
	}

	return (status);
}

static int
mptsas_diag_register(mptsas_t *mpt, mptsas_fw_diag_register_t *diag_register,
    uint32_t *return_code)
{
	mptsas_fw_diagnostic_buffer_t	*pBuffer;
	uint8_t				extended_type, buffer_type, i;
	uint32_t			buffer_size;
	uint32_t			unique_id;
	int				status;

	ASSERT(mutex_owned(&mpt->m_mutex));

	extended_type = diag_register->ExtendedType;
	buffer_type = diag_register->BufferType;
	buffer_size = diag_register->RequestedBufferSize;
	unique_id = diag_register->UniqueId;

	/*
	 * Check for valid buffer type
	 */
	if (buffer_type >= MPI2_DIAG_BUF_TYPE_COUNT) {
		*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER;
		return (DDI_FAILURE);
	}

	/*
	 * Get the current buffer and look up the unique ID.  The unique ID
	 * should not be found.  If it is, the ID is already in use.
	 */
	i = mptsas_get_fw_diag_buffer_number(mpt, unique_id);
	pBuffer = &mpt->m_fw_diag_buffer_list[buffer_type];
	if (i != MPTSAS_FW_DIAGNOSTIC_UID_NOT_FOUND) {
		*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_UID;
		return (DDI_FAILURE);
	}

	/*
	 * The buffer's unique ID should not be registered yet, and the given
	 * unique ID cannot be 0.
	 */
	if ((pBuffer->unique_id != MPTSAS_FW_DIAG_INVALID_UID) ||
	    (unique_id == MPTSAS_FW_DIAG_INVALID_UID)) {
		*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_UID;
		return (DDI_FAILURE);
	}

	/*
	 * If this buffer is already posted as immediate, just change owner.
	 */
	if (pBuffer->immediate && pBuffer->owned_by_firmware &&
	    (pBuffer->unique_id == MPTSAS_FW_DIAG_INVALID_UID)) {
		pBuffer->immediate = FALSE;
		pBuffer->unique_id = unique_id;
		return (DDI_SUCCESS);
	}

	/*
	 * Post a new buffer after checking if it's enabled.  The DMA buffer
	 * that is allocated will be contiguous (sgl_len = 1).
	 */
	if (!pBuffer->enabled) {
		*return_code = MPTSAS_FW_DIAG_ERROR_NO_BUFFER;
		return (DDI_FAILURE);
	}
	bzero(&pBuffer->buffer_data, sizeof (mptsas_dma_alloc_state_t));
	pBuffer->buffer_data.size = buffer_size;
	if (mptsas_dma_alloc(mpt, &pBuffer->buffer_data) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "failed to alloc DMA resource for "
		    "diag buffer: size = %d bytes", buffer_size);
		*return_code = MPTSAS_FW_DIAG_ERROR_NO_BUFFER;
		return (DDI_FAILURE);
	}

	/*
	 * Copy the given info to the diag buffer and post the buffer.
	 */
	pBuffer->buffer_type = buffer_type;
	pBuffer->immediate = FALSE;
	if (buffer_type == MPI2_DIAG_BUF_TYPE_TRACE) {
		for (i = 0; i < (sizeof (pBuffer->product_specific) / 4);
		    i++) {
			pBuffer->product_specific[i] =
			    diag_register->ProductSpecific[i];
		}
	}
	pBuffer->extended_type = extended_type;
	pBuffer->unique_id = unique_id;
	status = mptsas_post_fw_diag_buffer(mpt, pBuffer, return_code);

	if (mptsas_check_dma_handle(pBuffer->buffer_data.handle) !=
	    DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "Check of DMA handle failed in "
		    "mptsas_diag_register.");
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		status = DDI_FAILURE;
	}

	/*
	 * In case there was a failure, free the DMA buffer.
	 */
	if (status == DDI_FAILURE) {
		mptsas_dma_free(&pBuffer->buffer_data);
	}

	return (status);
}

static int
mptsas_diag_unregister(mptsas_t *mpt,
    mptsas_fw_diag_unregister_t *diag_unregister, uint32_t *return_code)
{
	mptsas_fw_diagnostic_buffer_t	*pBuffer;
	uint8_t				i;
	uint32_t			unique_id;
	int				status;

	ASSERT(mutex_owned(&mpt->m_mutex));

	unique_id = diag_unregister->UniqueId;

	/*
	 * Get the current buffer and look up the unique ID.  The unique ID
	 * should be there.
	 */
	i = mptsas_get_fw_diag_buffer_number(mpt, unique_id);
	if (i == MPTSAS_FW_DIAGNOSTIC_UID_NOT_FOUND) {
		*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_UID;
		return (DDI_FAILURE);
	}

	pBuffer = &mpt->m_fw_diag_buffer_list[i];

	/*
	 * Try to release the buffer from FW before freeing it.  If release
	 * fails, don't free the DMA buffer in case FW tries to access it
	 * later.  If buffer is not owned by firmware, can't release it.
	 */
	if (!pBuffer->owned_by_firmware) {
		status = DDI_SUCCESS;
	} else {
		status = mptsas_release_fw_diag_buffer(mpt, pBuffer,
		    return_code, MPTSAS_FW_DIAG_TYPE_UNREGISTER);
	}

	/*
	 * At this point, return the current status no matter what happens with
	 * the DMA buffer.
	 */
	pBuffer->unique_id = MPTSAS_FW_DIAG_INVALID_UID;
	if (status == DDI_SUCCESS) {
		if (mptsas_check_dma_handle(pBuffer->buffer_data.handle) !=
		    DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "Check of DMA handle failed "
			    "in mptsas_diag_unregister.");
			ddi_fm_service_impact(mpt->m_dip,
			    DDI_SERVICE_UNAFFECTED);
		}
		mptsas_dma_free(&pBuffer->buffer_data);
	}

	return (status);
}

static int
mptsas_diag_query(mptsas_t *mpt, mptsas_fw_diag_query_t *diag_query,
    uint32_t *return_code)
{
	mptsas_fw_diagnostic_buffer_t	*pBuffer;
	uint8_t				i;
	uint32_t			unique_id;

	ASSERT(mutex_owned(&mpt->m_mutex));

	unique_id = diag_query->UniqueId;

	/*
	 * If ID is valid, query on ID.
	 * If ID is invalid, query on buffer type.
	 */
	if (unique_id == MPTSAS_FW_DIAG_INVALID_UID) {
		i = diag_query->BufferType;
		if (i >= MPI2_DIAG_BUF_TYPE_COUNT) {
			*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_UID;
			return (DDI_FAILURE);
		}
	} else {
		i = mptsas_get_fw_diag_buffer_number(mpt, unique_id);
		if (i == MPTSAS_FW_DIAGNOSTIC_UID_NOT_FOUND) {
			*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_UID;
			return (DDI_FAILURE);
		}
	}

	/*
	 * Fill query structure with the diag buffer info.
	 */
	pBuffer = &mpt->m_fw_diag_buffer_list[i];
	diag_query->BufferType = pBuffer->buffer_type;
	diag_query->ExtendedType = pBuffer->extended_type;
	if (diag_query->BufferType == MPI2_DIAG_BUF_TYPE_TRACE) {
		for (i = 0; i < (sizeof (diag_query->ProductSpecific) / 4);
		    i++) {
			diag_query->ProductSpecific[i] =
			    pBuffer->product_specific[i];
		}
	}
	diag_query->TotalBufferSize = pBuffer->buffer_data.size;
	diag_query->DriverAddedBufferSize = 0;
	diag_query->UniqueId = pBuffer->unique_id;
	diag_query->ApplicationFlags = 0;
	diag_query->DiagnosticFlags = 0;

	/*
	 * Set/Clear application flags
	 */
	if (pBuffer->immediate) {
		diag_query->ApplicationFlags &= ~MPTSAS_FW_DIAG_FLAG_APP_OWNED;
	} else {
		diag_query->ApplicationFlags |= MPTSAS_FW_DIAG_FLAG_APP_OWNED;
	}
	if (pBuffer->valid_data || pBuffer->owned_by_firmware) {
		diag_query->ApplicationFlags |=
		    MPTSAS_FW_DIAG_FLAG_BUFFER_VALID;
	} else {
		diag_query->ApplicationFlags &=
		    ~MPTSAS_FW_DIAG_FLAG_BUFFER_VALID;
	}
	if (pBuffer->owned_by_firmware) {
		diag_query->ApplicationFlags |=
		    MPTSAS_FW_DIAG_FLAG_FW_BUFFER_ACCESS;
	} else {
		diag_query->ApplicationFlags &=
		    ~MPTSAS_FW_DIAG_FLAG_FW_BUFFER_ACCESS;
	}

	return (DDI_SUCCESS);
}

static int
mptsas_diag_read_buffer(mptsas_t *mpt,
    mptsas_diag_read_buffer_t *diag_read_buffer, uint8_t *ioctl_buf,
    uint32_t *return_code, int ioctl_mode)
{
	mptsas_fw_diagnostic_buffer_t	*pBuffer;
	uint8_t				i, *pData;
	uint32_t			unique_id, byte;
	int				status;

	ASSERT(mutex_owned(&mpt->m_mutex));

	unique_id = diag_read_buffer->UniqueId;

	/*
	 * Get the current buffer and look up the unique ID.  The unique ID
	 * should be there.
	 */
	i = mptsas_get_fw_diag_buffer_number(mpt, unique_id);
	if (i == MPTSAS_FW_DIAGNOSTIC_UID_NOT_FOUND) {
		*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_UID;
		return (DDI_FAILURE);
	}

	pBuffer = &mpt->m_fw_diag_buffer_list[i];

	/*
	 * Make sure requested read is within limits
	 */
	if (diag_read_buffer->StartingOffset + diag_read_buffer->BytesToRead >
	    pBuffer->buffer_data.size) {
		*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER;
		return (DDI_FAILURE);
	}

	/*
	 * Copy the requested data from DMA to the diag_read_buffer.  The DMA
	 * buffer that was allocated is one contiguous buffer.
	 */
	pData = (uint8_t *)(pBuffer->buffer_data.memp +
	    diag_read_buffer->StartingOffset);
	(void) ddi_dma_sync(pBuffer->buffer_data.handle, 0, 0,
	    DDI_DMA_SYNC_FORCPU);
	for (byte = 0; byte < diag_read_buffer->BytesToRead; byte++) {
		if (ddi_copyout(pData + byte, ioctl_buf + byte, 1, ioctl_mode)
		    != 0) {
			return (DDI_FAILURE);
		}
	}
	diag_read_buffer->Status = 0;

	/*
	 * Set or clear the Force Release flag.
	 */
	if (pBuffer->force_release) {
		diag_read_buffer->Flags |= MPTSAS_FW_DIAG_FLAG_FORCE_RELEASE;
	} else {
		diag_read_buffer->Flags &= ~MPTSAS_FW_DIAG_FLAG_FORCE_RELEASE;
	}

	/*
	 * If buffer is to be reregistered, make sure it's not already owned by
	 * firmware first.
	 */
	status = DDI_SUCCESS;
	if (!pBuffer->owned_by_firmware) {
		if (diag_read_buffer->Flags & MPTSAS_FW_DIAG_FLAG_REREGISTER) {
			status = mptsas_post_fw_diag_buffer(mpt, pBuffer,
			    return_code);
		}
	}

	return (status);
}

static int
mptsas_diag_release(mptsas_t *mpt, mptsas_fw_diag_release_t *diag_release,
    uint32_t *return_code)
{
	mptsas_fw_diagnostic_buffer_t	*pBuffer;
	uint8_t				i;
	uint32_t			unique_id;
	int				status;

	ASSERT(mutex_owned(&mpt->m_mutex));

	unique_id = diag_release->UniqueId;

	/*
	 * Get the current buffer and look up the unique ID.  The unique ID
	 * should be there.
	 */
	i = mptsas_get_fw_diag_buffer_number(mpt, unique_id);
	if (i == MPTSAS_FW_DIAGNOSTIC_UID_NOT_FOUND) {
		*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_UID;
		return (DDI_FAILURE);
	}

	pBuffer = &mpt->m_fw_diag_buffer_list[i];

	/*
	 * If buffer is not owned by firmware, it's already been released.
	 */
	if (!pBuffer->owned_by_firmware) {
		*return_code = MPTSAS_FW_DIAG_ERROR_ALREADY_RELEASED;
		return (DDI_FAILURE);
	}

	/*
	 * Release the buffer.
	 */
	status = mptsas_release_fw_diag_buffer(mpt, pBuffer, return_code,
	    MPTSAS_FW_DIAG_TYPE_RELEASE);
	return (status);
}

static int
mptsas_do_diag_action(mptsas_t *mpt, uint32_t action, uint8_t *diag_action,
    uint32_t length, uint32_t *return_code, int ioctl_mode)
{
	mptsas_fw_diag_register_t	diag_register;
	mptsas_fw_diag_unregister_t	diag_unregister;
	mptsas_fw_diag_query_t		diag_query;
	mptsas_diag_read_buffer_t	diag_read_buffer;
	mptsas_fw_diag_release_t	diag_release;
	int				status = DDI_SUCCESS;
	uint32_t			original_return_code, read_buf_len;

	ASSERT(mutex_owned(&mpt->m_mutex));

	original_return_code = *return_code;
	*return_code = MPTSAS_FW_DIAG_ERROR_SUCCESS;

	switch (action) {
		case MPTSAS_FW_DIAG_TYPE_REGISTER:
			if (!length) {
				*return_code =
				    MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER;
				status = DDI_FAILURE;
				break;
			}
			if (ddi_copyin(diag_action, &diag_register,
			    sizeof (diag_register), ioctl_mode) != 0) {
				return (DDI_FAILURE);
			}
			status = mptsas_diag_register(mpt, &diag_register,
			    return_code);
			break;

		case MPTSAS_FW_DIAG_TYPE_UNREGISTER:
			if (length < sizeof (diag_unregister)) {
				*return_code =
				    MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER;
				status = DDI_FAILURE;
				break;
			}
			if (ddi_copyin(diag_action, &diag_unregister,
			    sizeof (diag_unregister), ioctl_mode) != 0) {
				return (DDI_FAILURE);
			}
			status = mptsas_diag_unregister(mpt, &diag_unregister,
			    return_code);
			break;

		case MPTSAS_FW_DIAG_TYPE_QUERY:
			if (length < sizeof (diag_query)) {
				*return_code =
				    MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER;
				status = DDI_FAILURE;
				break;
			}
			if (ddi_copyin(diag_action, &diag_query,
			    sizeof (diag_query), ioctl_mode) != 0) {
				return (DDI_FAILURE);
			}
			status = mptsas_diag_query(mpt, &diag_query,
			    return_code);
			if (status == DDI_SUCCESS) {
				if (ddi_copyout(&diag_query, diag_action,
				    sizeof (diag_query), ioctl_mode) != 0) {
					return (DDI_FAILURE);
				}
			}
			break;

		case MPTSAS_FW_DIAG_TYPE_READ_BUFFER:
			if (ddi_copyin(diag_action, &diag_read_buffer,
			    sizeof (diag_read_buffer) - 4, ioctl_mode) != 0) {
				return (DDI_FAILURE);
			}
			read_buf_len = sizeof (diag_read_buffer) -
			    sizeof (diag_read_buffer.DataBuffer) +
			    diag_read_buffer.BytesToRead;
			if (length < read_buf_len) {
				*return_code =
				    MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER;
				status = DDI_FAILURE;
				break;
			}
			status = mptsas_diag_read_buffer(mpt,
			    &diag_read_buffer, diag_action +
			    sizeof (diag_read_buffer) - 4, return_code,
			    ioctl_mode);
			if (status == DDI_SUCCESS) {
				if (ddi_copyout(&diag_read_buffer, diag_action,
				    sizeof (diag_read_buffer) - 4, ioctl_mode)
				    != 0) {
					return (DDI_FAILURE);
				}
			}
			break;

		case MPTSAS_FW_DIAG_TYPE_RELEASE:
			if (length < sizeof (diag_release)) {
				*return_code =
				    MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER;
				status = DDI_FAILURE;
				break;
			}
			if (ddi_copyin(diag_action, &diag_release,
			    sizeof (diag_release), ioctl_mode) != 0) {
				return (DDI_FAILURE);
			}
			status = mptsas_diag_release(mpt, &diag_release,
			    return_code);
			break;

		default:
			*return_code = MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER;
			status = DDI_FAILURE;
			break;
	}

	if ((status == DDI_FAILURE) &&
	    (original_return_code == MPTSAS_FW_DIAG_NEW) &&
	    (*return_code != MPTSAS_FW_DIAG_ERROR_SUCCESS)) {
		status = DDI_SUCCESS;
	}

	return (status);
}

static int
mptsas_diag_action(mptsas_t *mpt, mptsas_diag_action_t *user_data, int mode)
{
	int			status;
	mptsas_diag_action_t	driver_data;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * Copy the user data to a driver data buffer.
	 */
	if (ddi_copyin(user_data, &driver_data, sizeof (mptsas_diag_action_t),
	    mode) == 0) {
		/*
		 * Send diag action request if Action is valid
		 */
		if (driver_data.Action == MPTSAS_FW_DIAG_TYPE_REGISTER ||
		    driver_data.Action == MPTSAS_FW_DIAG_TYPE_UNREGISTER ||
		    driver_data.Action == MPTSAS_FW_DIAG_TYPE_QUERY ||
		    driver_data.Action == MPTSAS_FW_DIAG_TYPE_READ_BUFFER ||
		    driver_data.Action == MPTSAS_FW_DIAG_TYPE_RELEASE) {
			status = mptsas_do_diag_action(mpt, driver_data.Action,
			    (void *)(uintptr_t)driver_data.PtrDiagAction,
			    driver_data.Length, &driver_data.ReturnCode,
			    mode);
			if (status == DDI_SUCCESS) {
				if (ddi_copyout(&driver_data.ReturnCode,
				    &user_data->ReturnCode,
				    sizeof (user_data->ReturnCode), mode)
				    != 0) {
					status = EFAULT;
				} else {
					status = 0;
				}
			} else {
				status = EIO;
			}
		} else {
			status = EINVAL;
		}
	} else {
		status = EFAULT;
	}

	return (status);
}

/*
 * This routine handles the "event query" ioctl.
 */
static int
mptsas_event_query(mptsas_t *mpt, mptsas_event_query_t *data, int mode,
    int *rval)
{
	int			status;
	mptsas_event_query_t	driverdata;
	uint8_t			i;

	driverdata.Entries = MPTSAS_EVENT_QUEUE_SIZE;

	mutex_enter(&mpt->m_mutex);
	for (i = 0; i < 4; i++) {
		driverdata.Types[i] = mpt->m_event_mask[i];
	}
	mutex_exit(&mpt->m_mutex);

	if (ddi_copyout(&driverdata, data, sizeof (driverdata), mode) != 0) {
		status = EFAULT;
	} else {
		*rval = MPTIOCTL_STATUS_GOOD;
		status = 0;
	}

	return (status);
}

/*
 * This routine handles the "event enable" ioctl.
 */
static int
mptsas_event_enable(mptsas_t *mpt, mptsas_event_enable_t *data, int mode,
    int *rval)
{
	int			status;
	mptsas_event_enable_t	driverdata;
	uint8_t			i;

	if (ddi_copyin(data, &driverdata, sizeof (driverdata), mode) == 0) {
		mutex_enter(&mpt->m_mutex);
		for (i = 0; i < 4; i++) {
			mpt->m_event_mask[i] = driverdata.Types[i];
		}
		mutex_exit(&mpt->m_mutex);

		*rval = MPTIOCTL_STATUS_GOOD;
		status = 0;
	} else {
		status = EFAULT;
	}
	return (status);
}

/*
 * This routine handles the "event report" ioctl.
 */
static int
mptsas_event_report(mptsas_t *mpt, mptsas_event_report_t *data, int mode,
    int *rval)
{
	int			status;
	mptsas_event_report_t	driverdata;

	mutex_enter(&mpt->m_mutex);

	if (ddi_copyin(&data->Size, &driverdata.Size, sizeof (driverdata.Size),
	    mode) == 0) {
		if (driverdata.Size >= sizeof (mpt->m_events)) {
			if (ddi_copyout(mpt->m_events, data->Events,
			    sizeof (mpt->m_events), mode) != 0) {
				status = EFAULT;
			} else {
				if (driverdata.Size > sizeof (mpt->m_events)) {
					driverdata.Size =
					    sizeof (mpt->m_events);
					if (ddi_copyout(&driverdata.Size,
					    &data->Size,
					    sizeof (driverdata.Size),
					    mode) != 0) {
						status = EFAULT;
					} else {
						*rval = MPTIOCTL_STATUS_GOOD;
						status = 0;
					}
				} else {
					*rval = MPTIOCTL_STATUS_GOOD;
					status = 0;
				}
			}
		} else {
			*rval = MPTIOCTL_STATUS_LEN_TOO_SHORT;
			status = 0;
		}
	} else {
		status = EFAULT;
	}

	mutex_exit(&mpt->m_mutex);
	return (status);
}

static void
mptsas_lookup_pci_data(mptsas_t *mpt, mptsas_adapter_data_t *adapter_data)
{
	int	*reg_data;
	uint_t	reglen;

	/*
	 * Lookup the 'reg' property and extract the other data
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, mpt->m_dip,
	    DDI_PROP_DONTPASS, "reg", &reg_data, &reglen) ==
	    DDI_PROP_SUCCESS) {
		/*
		 * Extract the PCI data from the 'reg' property first DWORD.
		 * The entry looks like the following:
		 * First DWORD:
		 * Bits 0 - 7 8-bit Register number
		 * Bits 8 - 10 3-bit Function number
		 * Bits 11 - 15 5-bit Device number
		 * Bits 16 - 23 8-bit Bus number
		 * Bits 24 - 25 2-bit Address Space type identifier
		 *
		 */
		adapter_data->PciInformation.u.bits.BusNumber =
		    (reg_data[0] & 0x00FF0000) >> 16;
		adapter_data->PciInformation.u.bits.DeviceNumber =
		    (reg_data[0] & 0x0000F800) >> 11;
		adapter_data->PciInformation.u.bits.FunctionNumber =
		    (reg_data[0] & 0x00000700) >> 8;
		ddi_prop_free((void *)reg_data);
	} else {
		/*
		 * If we can't determine the PCI data then we fill in FF's for
		 * the data to indicate this.
		 */
		adapter_data->PCIDeviceHwId = 0xFFFFFFFF;
		adapter_data->MpiPortNumber = 0xFFFFFFFF;
		adapter_data->PciInformation.u.AsDWORD = 0xFFFFFFFF;
	}

	/*
	 * Saved in the mpt->m_fwversion
	 */
	adapter_data->MpiFirmwareVersion = mpt->m_fwversion;
}

static void
mptsas_read_adapter_data(mptsas_t *mpt, mptsas_adapter_data_t *adapter_data)
{
	char	*driver_verstr = MPTSAS_MOD_STRING;

	mptsas_lookup_pci_data(mpt, adapter_data);
	adapter_data->AdapterType = MPTIOCTL_ADAPTER_TYPE_SAS3;
	adapter_data->PCIDeviceHwId = (uint32_t)mpt->m_devid;
	adapter_data->PCIDeviceHwRev = (uint32_t)mpt->m_revid;
	adapter_data->SubSystemId = (uint32_t)mpt->m_ssid;
	adapter_data->SubsystemVendorId = (uint32_t)mpt->m_svid;
	(void) strcpy((char *)&adapter_data->DriverVersion[0], driver_verstr);
	adapter_data->BiosVersion = 0;
	(void) mptsas_get_bios_page3(mpt, &adapter_data->BiosVersion);
}

static void
mptsas_read_pci_info(mptsas_t *mpt, mptsas_pci_info_t *pci_info)
{
	int	*reg_data, i;
	uint_t	reglen;

	/*
	 * Lookup the 'reg' property and extract the other data
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, mpt->m_dip,
	    DDI_PROP_DONTPASS, "reg", &reg_data, &reglen) ==
	    DDI_PROP_SUCCESS) {
		/*
		 * Extract the PCI data from the 'reg' property first DWORD.
		 * The entry looks like the following:
		 * First DWORD:
		 * Bits 8 - 10 3-bit Function number
		 * Bits 11 - 15 5-bit Device number
		 * Bits 16 - 23 8-bit Bus number
		 */
		pci_info->BusNumber = (reg_data[0] & 0x00FF0000) >> 16;
		pci_info->DeviceNumber = (reg_data[0] & 0x0000F800) >> 11;
		pci_info->FunctionNumber = (reg_data[0] & 0x00000700) >> 8;
		ddi_prop_free((void *)reg_data);
	} else {
		/*
		 * If we can't determine the PCI info then we fill in FF's for
		 * the data to indicate this.
		 */
		pci_info->BusNumber = 0xFFFFFFFF;
		pci_info->DeviceNumber = 0xFF;
		pci_info->FunctionNumber = 0xFF;
	}

	/*
	 * Now get the interrupt vector and the pci header.  The vector can
	 * only be 0 right now.  The header is the first 256 bytes of config
	 * space.
	 */
	pci_info->InterruptVector = 0;
	for (i = 0; i < sizeof (pci_info->PciHeader); i++) {
		pci_info->PciHeader[i] = pci_config_get8(mpt->m_config_handle,
		    i);
	}
}

static int
mptsas_reg_access(mptsas_t *mpt, mptsas_reg_access_t *data, int mode)
{
	int			status = 0;
	mptsas_reg_access_t	driverdata;

	mutex_enter(&mpt->m_mutex);
	if (ddi_copyin(data, &driverdata, sizeof (driverdata), mode) == 0) {
		switch (driverdata.Command) {
			/*
			 * IO access is not supported.
			 */
			case REG_IO_READ:
			case REG_IO_WRITE:
				mptsas_log(mpt, CE_WARN, "IO access is not "
				    "supported.  Use memory access.");
				status = EINVAL;
				break;

			case REG_MEM_READ:
				driverdata.RegData = ddi_get32(mpt->m_datap,
				    (uint32_t *)(void *)mpt->m_reg +
				    driverdata.RegOffset);
				if (ddi_copyout(&driverdata.RegData,
				    &data->RegData,
				    sizeof (driverdata.RegData), mode) != 0) {
					mptsas_log(mpt, CE_WARN, "Register "
					    "Read Failed");
					status = EFAULT;
				}
				break;

			case REG_MEM_WRITE:
				ddi_put32(mpt->m_datap,
				    (uint32_t *)(void *)mpt->m_reg +
				    driverdata.RegOffset,
				    driverdata.RegData);
				break;

			default:
				status = EINVAL;
				break;
		}
	} else {
		status = EFAULT;
	}

	mutex_exit(&mpt->m_mutex);
	return (status);
}

static int
led_control(mptsas_t *mpt, intptr_t data, int mode)
{
	int ret = 0;
	mptsas_led_control_t lc;
	mptsas_target_t *ptgt;

	if (ddi_copyin((void *)data, &lc, sizeof (lc), mode) != 0) {
		return (EFAULT);
	}

	if ((lc.Command != MPTSAS_LEDCTL_FLAG_SET &&
	    lc.Command != MPTSAS_LEDCTL_FLAG_GET) ||
	    lc.Led < MPTSAS_LEDCTL_LED_MIN ||
	    lc.Led > MPTSAS_LEDCTL_LED_MAX ||
	    (lc.Command == MPTSAS_LEDCTL_FLAG_SET && lc.LedStatus != 0 &&
	    lc.LedStatus != 1)) {
		return (EINVAL);
	}

	if ((lc.Command == MPTSAS_LEDCTL_FLAG_SET && (mode & FWRITE) == 0) ||
	    (lc.Command == MPTSAS_LEDCTL_FLAG_GET && (mode & FREAD) == 0))
		return (EACCES);

	/* Locate the target we're interrogating... */
	mutex_enter(&mpt->m_mutex);
	ptgt = refhash_linear_search(mpt->m_targets,
	    mptsas_target_eval_slot, &lc);
	if (ptgt == NULL) {
		/* We could not find a target for that enclosure/slot. */
		mutex_exit(&mpt->m_mutex);
		return (ENOENT);
	}

	if (lc.Command == MPTSAS_LEDCTL_FLAG_SET) {
		/* Update our internal LED state. */
		ptgt->m_led_status &= ~(1 << (lc.Led - 1));
		ptgt->m_led_status |= lc.LedStatus << (lc.Led - 1);

		/* Flush it to the controller. */
		ret = mptsas_flush_led_status(mpt, ptgt);
		mutex_exit(&mpt->m_mutex);
		return (ret);
	}

	/* Return our internal LED state. */
	lc.LedStatus = (ptgt->m_led_status >> (lc.Led - 1)) & 1;
	mutex_exit(&mpt->m_mutex);

	if (ddi_copyout(&lc, (void *)data, sizeof (lc), mode) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
get_disk_info(mptsas_t *mpt, intptr_t data, int mode)
{
	uint16_t i = 0;
	uint16_t count = 0;
	int ret = 0;
	mptsas_target_t *ptgt;
	mptsas_disk_info_t *di;
	STRUCT_DECL(mptsas_get_disk_info, gdi);

	if ((mode & FREAD) == 0)
		return (EACCES);

	STRUCT_INIT(gdi, get_udatamodel());

	if (ddi_copyin((void *)data, STRUCT_BUF(gdi), STRUCT_SIZE(gdi),
	    mode) != 0) {
		return (EFAULT);
	}

	/* Find out how many targets there are. */
	mutex_enter(&mpt->m_mutex);
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		count++;
	}
	mutex_exit(&mpt->m_mutex);

	/*
	 * If we haven't been asked to copy out information on each target,
	 * then just return the count.
	 */
	STRUCT_FSET(gdi, DiskCount, count);
	if (STRUCT_FGETP(gdi, PtrDiskInfoArray) == NULL)
		goto copy_out;

	/*
	 * If we haven't been given a large enough buffer to copy out into,
	 * let the caller know.
	 */
	if (STRUCT_FGET(gdi, DiskInfoArraySize) <
	    count * sizeof (mptsas_disk_info_t)) {
		ret = ENOSPC;
		goto copy_out;
	}

	di = kmem_zalloc(count * sizeof (mptsas_disk_info_t), KM_SLEEP);

	mutex_enter(&mpt->m_mutex);
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		if (i >= count) {
			/*
			 * The number of targets changed while we weren't
			 * looking, so give up.
			 */
			refhash_rele(mpt->m_targets, ptgt);
			mutex_exit(&mpt->m_mutex);
			kmem_free(di, count * sizeof (mptsas_disk_info_t));
			return (EAGAIN);
		}
		di[i].Instance = mpt->m_instance;
		di[i].Enclosure = ptgt->m_enclosure;
		di[i].Slot = ptgt->m_slot_num;
		di[i].SasAddress = ptgt->m_addr.mta_wwn;
		i++;
	}
	mutex_exit(&mpt->m_mutex);
	STRUCT_FSET(gdi, DiskCount, i);

	/* Copy out the disk information to the caller. */
	if (ddi_copyout((void *)di, STRUCT_FGETP(gdi, PtrDiskInfoArray),
	    i * sizeof (mptsas_disk_info_t), mode) != 0) {
		ret = EFAULT;
	}

	kmem_free(di, count * sizeof (mptsas_disk_info_t));

copy_out:
	if (ddi_copyout(STRUCT_BUF(gdi), (void *)data, STRUCT_SIZE(gdi),
	    mode) != 0) {
		ret = EFAULT;
	}

	return (ret);
}

static int
mptsas_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
    int *rval)
{
	int			status = 0;
	mptsas_t		*mpt;
	mptsas_update_flash_t	flashdata;
	mptsas_pass_thru_t	passthru_data;
	mptsas_adapter_data_t   adapter_data;
	mptsas_pci_info_t	pci_info;
	int			copylen;

	int			iport_flag = 0;
	dev_info_t		*dip = NULL;
	mptsas_phymask_t	phymask = 0;
	struct devctl_iocdata	*dcp = NULL;
	char			*addr = NULL;
	mptsas_target_t		*ptgt = NULL;

	*rval = MPTIOCTL_STATUS_GOOD;
	if (secpolicy_sys_config(credp, B_FALSE) != 0) {
		return (EPERM);
	}

	mpt = ddi_get_soft_state(mptsas3_state, MINOR2INST(getminor(dev)));
	if (mpt == NULL) {
		/*
		 * Called from iport node, get the states
		 */
		iport_flag = 1;
		dip = mptsas_get_dip_from_dev(dev, &phymask);
		if (dip == NULL) {
			return (ENXIO);
		}
		mpt = DIP2MPT(dip);
	}
	/* Make sure power level is D0 before accessing registers */
	mutex_enter(&mpt->m_mutex);
	if (mpt->m_options & MPTSAS_OPT_PM) {
		(void) pm_busy_component(mpt->m_dip, 0);
		if (mpt->m_power_level != PM_LEVEL_D0) {
			mutex_exit(&mpt->m_mutex);
			if (pm_raise_power(mpt->m_dip, 0, PM_LEVEL_D0) !=
			    DDI_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "mptsas3%d: mptsas_ioctl: Raise power "
				    "request failed.", mpt->m_instance);
				(void) pm_idle_component(mpt->m_dip, 0);
				return (ENXIO);
			}
		} else {
			mutex_exit(&mpt->m_mutex);
		}
	} else {
		mutex_exit(&mpt->m_mutex);
	}

	if (iport_flag) {
		status = scsi_hba_ioctl(dev, cmd, data, mode, credp, rval);
		if (status != 0) {
			goto out;
		}
		/*
		 * The following code control the OK2RM LED, it doesn't affect
		 * the ioctl return status.
		 */
		if ((cmd == DEVCTL_DEVICE_ONLINE) ||
		    (cmd == DEVCTL_DEVICE_OFFLINE)) {
			if (ndi_dc_allochdl((void *)data, &dcp) !=
			    NDI_SUCCESS) {
				goto out;
			}
			addr = ndi_dc_getaddr(dcp);
			mutex_enter(&mpt->m_mutex);
			ptgt = mptsas_addr_to_ptgt(mpt, addr, phymask,
			    NULL, NULL, NULL);
			if (ptgt == NULL) {
				NDBG14(("%d: ioctl led control: tgt %s "
				    "not found", mpt->m_instance, addr));
				ndi_dc_freehdl(dcp);
				mutex_exit(&mpt->m_mutex);
				goto out;
			}
			mutex_exit(&ptgt->m_t_mutex);
			if (cmd == DEVCTL_DEVICE_ONLINE) {
				ptgt->m_tgt_unconfigured = 0;
			} else if (cmd == DEVCTL_DEVICE_OFFLINE) {
				ptgt->m_tgt_unconfigured = 1;
			}
			if (cmd == DEVCTL_DEVICE_OFFLINE) {
				ptgt->m_led_status |=
				    (1 << (MPTSAS_LEDCTL_LED_OK2RM - 1));
			} else {
				ptgt->m_led_status &=
				    ~(1 << (MPTSAS_LEDCTL_LED_OK2RM - 1));
			}
			(void) mptsas_flush_led_status(mpt, ptgt);
			mutex_exit(&mpt->m_mutex);
			ndi_dc_freehdl(dcp);
		}
		goto out;
	}
	switch (cmd) {
		case MPTIOCTL_GET_DISK_INFO:
			status = get_disk_info(mpt, data, mode);
			break;
		case MPTIOCTL_LED_CONTROL:
			status = led_control(mpt, data, mode);
			break;
		case MPTIOCTL_UPDATE_FLASH:
			if (ddi_copyin((void *)data, &flashdata,
				sizeof (struct mptsas_update_flash), mode)) {
				status = EFAULT;
				break;
			}

			mutex_enter(&mpt->m_mutex);
			if (mptsas_update_flash(mpt,
			    (caddr_t)(long)flashdata.PtrBuffer,
			    flashdata.ImageSize, flashdata.ImageType, mode)) {
				status = EFAULT;
			}

			/*
			 * Reset the chip to start using the new
			 * firmware.  Reset if failed also.
			 */
			mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
			if (mptsas_restart_ioc(mpt, "MPTIOCTL_UPDATE_FLASH") ==
			    DDI_FAILURE) {
				status = EFAULT;
			}
			mutex_exit(&mpt->m_mutex);
			break;
		case MPTIOCTL_PASS_THRU:
			/*
			 * The user has requested to pass through a command to
			 * be executed by the MPT firmware.  Call our routine
			 * which does this.  Only allow one passthru IOCTL at
			 * one time. Other threads will block on
			 * m_passthru_mutex, which is of adaptive variant.
			 */
			if (ddi_copyin((void *)data, &passthru_data,
			    sizeof (mptsas_pass_thru_t), mode)) {
				status = EFAULT;
				break;
			}
			mutex_enter(&mpt->m_passthru_mutex);
			mutex_enter(&mpt->m_mutex);
			status = mptsas_pass_thru(mpt, &passthru_data, mode);
			mutex_exit(&mpt->m_mutex);
			mutex_exit(&mpt->m_passthru_mutex);

			break;
		case MPTIOCTL_GET_ADAPTER_DATA:
			/*
			 * The user has requested to read adapter data.  Call
			 * our routine which does this.
			 */
			bzero(&adapter_data, sizeof (mptsas_adapter_data_t));
			if (ddi_copyin((void *)data, (void *)&adapter_data,
			    sizeof (mptsas_adapter_data_t), mode)) {
				status = EFAULT;
				break;
			}
			if (adapter_data.StructureLength >=
			    sizeof (mptsas_adapter_data_t)) {
				adapter_data.StructureLength = (uint32_t)
				    sizeof (mptsas_adapter_data_t);
				copylen = sizeof (mptsas_adapter_data_t);
				mutex_enter(&mpt->m_mutex);
				mptsas_read_adapter_data(mpt, &adapter_data);
				mutex_exit(&mpt->m_mutex);
			} else {
				adapter_data.StructureLength = (uint32_t)
				    sizeof (mptsas_adapter_data_t);
				copylen = sizeof (adapter_data.StructureLength);
				*rval = MPTIOCTL_STATUS_LEN_TOO_SHORT;
			}
			if (ddi_copyout((void *)(&adapter_data), (void *)data,
			    copylen, mode) != 0) {
				status = EFAULT;
			}
			break;
		case MPTIOCTL_GET_PCI_INFO:
			/*
			 * The user has requested to read pci info.  Call
			 * our routine which does this.
			 */
			bzero(&pci_info, sizeof (mptsas_pci_info_t));
			mutex_enter(&mpt->m_mutex);
			mptsas_read_pci_info(mpt, &pci_info);
			mutex_exit(&mpt->m_mutex);
			if (ddi_copyout((void *)(&pci_info), (void *)data,
			    sizeof (mptsas_pci_info_t), mode) != 0) {
				status = EFAULT;
			}
			break;
		case MPTIOCTL_RESET_ADAPTER:
			mutex_enter(&mpt->m_mutex);
			mpt->m_softstate &= ~MPTSAS_SS_MSG_UNIT_RESET;
			if ((mptsas_restart_ioc(mpt,
			    "MPTIOCTL_RESET_ADAPTER")) == DDI_FAILURE) {
				mptsas_log(mpt, CE_WARN, "reset adapter IOCTL "
				    "failed");
				status = EFAULT;
			}
			mutex_exit(&mpt->m_mutex);
			break;
		case MPTIOCTL_DIAG_ACTION:
			/*
			 * The user has done a diag buffer action.  Call our
			 * routine which does this.  Only allow one diag action
			 * at one time.
			 */
			mutex_enter(&mpt->m_mutex);
			if (mpt->m_diag_action_in_progress) {
				mutex_exit(&mpt->m_mutex);
				return (EBUSY);
			}
			mpt->m_diag_action_in_progress = 1;
			status = mptsas_diag_action(mpt,
			    (mptsas_diag_action_t *)data, mode);
			mpt->m_diag_action_in_progress = 0;
			mutex_exit(&mpt->m_mutex);
			break;
		case MPTIOCTL_EVENT_QUERY:
			/*
			 * The user has done an event query. Call our routine
			 * which does this.
			 */
			status = mptsas_event_query(mpt,
			    (mptsas_event_query_t *)data, mode, rval);
			break;
		case MPTIOCTL_EVENT_ENABLE:
			/*
			 * The user has done an event enable. Call our routine
			 * which does this.
			 */
			status = mptsas_event_enable(mpt,
			    (mptsas_event_enable_t *)data, mode, rval);
			break;
		case MPTIOCTL_EVENT_REPORT:
			/*
			 * The user has done an event report. Call our routine
			 * which does this.
			 */
			status = mptsas_event_report(mpt,
			    (mptsas_event_report_t *)data, mode, rval);
			break;
		case MPTIOCTL_REG_ACCESS:
			/*
			 * The user has requested register access.  Call our
			 * routine which does this.
			 */
			status = mptsas_reg_access(mpt,
			    (mptsas_reg_access_t *)data, mode);
			break;
		default:
			status = scsi_hba_ioctl(dev, cmd, data, mode, credp,
			    rval);
			break;
	}

out:
	return (status);
}

/*
 * This function grabs all the reply q locks and then releases them.
 * If m_in_reset is set this ensures the interrupt routine has cleared
 * the reply q processing. Further interrupts will see the flag and
 * exit without processing anyway.
 */
static void
mptsas_rpqlock_chkpoint(mptsas_t *mpt)
{
	mptsas_reply_pqueue_t	*rpqp;
	int			i;

	rpqp = mpt->m_rep_post_queues;
	for (i = 0; i < mpt->m_post_reply_qcount; i++) {
		mutex_enter(&rpqp->rpq_mutex);
		mutex_exit(&rpqp->rpq_mutex);
		rpqp++;
	}
}

int
mptsas_restart_ioc(mptsas_t *mpt, char *reason)
{
	mptsas_target_t	*ptgt = NULL;
	hrtime_t	bcwto;

	ASSERT(mutex_owned(&mpt->m_mutex));

	mptsas_log(mpt, CE_NOTE, "?Restart HBA - %s\n", reason);

	/*
	 * Set a flag telling I/O path that we're processing a reset.  This is
	 * needed because after the reset is complete, the hash table still
	 * needs to be rebuilt.  If I/Os are started before the hash table is
	 * rebuilt, I/O errors will occur.  This flag allows I/Os to be marked
	 * so that they can be retried.
	 */
	mpt->m_in_reset = TRUE;

	/*
	 * Set all throttles to HOLD. Any commands that can get in
	 * while we temporarily drop the mutex then get put on
	 * the waitq.
	 */
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mptsas_set_throttle_mtx(mpt, ptgt, HOLD_THROTTLE);
	}

	/*
	 * Disable interrupts and ensure all interrupt processing has ceased.
	 * The m_in_reset flag has been set so future interrupts will just
	 * return. Doing the checkpoint ensures current processing has
	 * completed. However there is the possibility of an interrupt
	 * routine having stalled waiting for the m_mutex. So we have to
	 * drop that and finally remove the interrupts to ensure that the
	 * interrupt functions have exited.
	 * Then we can flush the HBA and wait for any outstanding task q
	 * processing to complete, without further interrupts we will not
	 * get any more.
	 */
	MPTSAS_DISABLE_INTR(mpt);
	mutex_exit(&mpt->m_mutex);
	mptsas_rpqlock_chkpoint(mpt);
	mptsas_rem_intrs(mpt);
	mutex_enter(&mpt->m_mutex);

	/*
	 * Abort all outstanding commands on the HBA.
	 */
	mptsas_flush_hba(mpt);
	mptsas_flush_waitq(mpt, B_TRUE);

	/*
	 * Abort IOPB and NOQUEUE commands on the waitq for targets in the
	 * middle of config_luns operations, leave others.
	 * This should correspond to the behavior in mptsas_accept_pkt().
	 * If the target is not present after the reset all it's commands
	 * will be flushed anyway.
	 * Commands left in those waitq will be restarted afterwards provided
	 * the reset works.
	 */
	mptsas_flush_alltarg_waitqs(mpt, B_TRUE, B_FALSE, CFLAG_CMDIOPB,
	    CFLAG_CMDIOPB, STAT_BUS_RESET, CMD_RESET);
	mptsas_flush_alltarg_waitqs(mpt, B_TRUE, B_TRUE,
	    (FLAG_NOQUEUE|FLAG_SILENT), (FLAG_NOQUEUE|FLAG_SILENT),
	    STAT_BUS_RESET, CMD_RESET);

	/*
	 * The theory is that we should have errored all the commands that
	 * would be issued during configuration.
	 * Wait for any outstanding dr tasks to complete.
	 */
	mutex_exit(&mpt->m_mutex);
	ddi_taskq_wait(mpt->m_event_taskq);
	ddi_taskq_wait(mpt->m_dr_taskq);
	mutex_enter(&mpt->m_mutex);

	/*
	 * New bus_config calls will stall while we have the m_in_reset
	 * flag set. But it's quite possible we are here in the middle
	 * of one. Any commands should have been aborted by the previous
	 * flush, try waiting for a while!
	 */
	bcwto = gethrtime() + 5000000000ll;
	while (mpt->m_bcfgs != 0 && gethrtime() < bcwto) {
		mutex_exit(&mpt->m_mutex);
		delay(1);
		mutex_enter(&mpt->m_mutex);
	}
	if (mpt->m_bcfgs != 0)
		mptsas_log(mpt, CE_WARN, "Restart IOC failed to wait for "
		    "all _bus_config() calls (%d)", mpt->m_bcfgs);

	/*
	 * Reinitialize the chip.
	 */
	if (mptsas_init_chip(mpt, FALSE) == DDI_FAILURE) {
		/*
		 * There is a potential case to offline all targets and smp
		 * devices here. However, the fm call and the fact that we
		 * will fail _bus_config() calls from now on results in
		 * all paths through this device failing. At the moment there
		 * is no way back from this, you will have to reboot and clear
		 * the fm faulty event.
		 */
		mptsas_flush_alltarg_waitqs(mpt, B_FALSE, B_FALSE, 0, 0,
		    STAT_ABORTED, CMD_DEV_GONE);
		mptsas_flush_waitq(mpt, B_FALSE);
		mptsas_doneq_empty(mpt);
		mptsas_fm_ereport(mpt, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_LOST);
		cv_broadcast(&mpt->m_cv);
		return (DDI_FAILURE);
	}

	/*
	 * Clear the in reset flag and enable interrupts again.
	 */
	mpt->m_in_reset = FALSE;
	cv_broadcast(&mpt->m_cv);
	MPTSAS_ENABLE_INTR(mpt);

	/*
	 * If mptsas_init_chip was successful, update the driver data.
	 * Must do this after resetting m_in_reset or config commands
	 * would get queued.
	 */
	mptsas_update_driver_data(mpt);

	/*
	 * Check that we didn't lose some targets.
	 * If not revert the throttle.
	 */
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		mutex_enter(&ptgt->m_t_mutex);
		if (ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL)
			mptsas_set_throttle(mpt, ptgt, MAX_THROTTLE);
		else if (ptgt->m_shdwhdl != MPTSAS_INVALID_DEVHDL) {
			/*
			 * Target does not seem to be present after the
			 * reset. Re-instate the devhdl so we can try to
			 * offline it manually.
			 */
			ptgt->m_devhdl = ptgt->m_shdwhdl;
			mptsas_dispatch_offline_tgt(mpt, ptgt, B_FALSE);
		}
		mutex_exit(&ptgt->m_t_mutex);
	}

	/*
	 * Restart everything.
	 */
	mptsas_restart_hba(mpt);

	return (DDI_SUCCESS);
}

static void
mptsas_restart_ioc_task(void *args)
{
	mptsas_t *mpt = (mptsas_t *)args;
	mutex_enter(&mpt->m_mutex);
	(void) mptsas_restart_ioc(mpt, "restart taskq triggered from watch");
	mutex_exit(&mpt->m_mutex);
}


static int
mptsas_init_chip(mptsas_t *mpt, int first_time)
{
	ddi_dma_cookie_t	cookie;
	mptsas_reply_pqueue_t	*rpqp;
	uint32_t		i, j;
	int			rval;

	/*
	 * Check to see if the firmware image is valid
	 */
	if (ddi_get32(mpt->m_datap, &mpt->m_reg->HostDiagnostic) &
	    MPI2_DIAG_FLASH_BAD_SIG) {
		mptsas_log(mpt, CE_WARN, "mptsas bad flash signature!");
		goto fail;
	}

	/*
	 * Reset the chip
	 */
	rval = mptsas_ioc_reset(mpt, first_time);
	NDBG19(("%d: init_chip: %sioc_reset() returned 0x%x",
	    mpt->m_instance, first_time?"FirstTime ":"", rval));
	if (rval == MPTSAS_RESET_FAIL) {
		mptsas_log(mpt, CE_WARN, "hard reset failed!");
		goto fail;
	}

	/*
	 * Free any reply args allocation before we call get_fact
	 * because that can change the max_replies number.
	 */
	if (mpt->m_replyh_args != NULL) {
		kmem_free(mpt->m_replyh_args, sizeof (m_replyh_arg_t)
		    * mpt->m_max_replies);
		mpt->m_replyh_args = NULL;
	}

#ifdef MPTSAS_TEST
	if (mptsas_fail_next_initchip) {
		mptsas_fail_next_initchip = 0;
		goto fail;
	}
#endif
	ASSERT(mpt->m_intr_cnt == 0);
	if ((rval == MPTSAS_SUCCESS_MUR) && (!first_time)) {
		/*
		 * Always have to re-register the interrupts, but that's
		 * all in this case.
		 */
		if (mptsas_register_intrs(mpt) == FALSE)
			goto fail;
		goto mur;
	}

	/*
	 * Setup configuration space
	 */
	if (mptsas_config_space_init(mpt) == FALSE) {
		mptsas_log(mpt, CE_WARN, "mptsas_config_space_init "
		    "failed!");
		goto fail;
	}

	/*
	 * IOC facts can change after a diag reset so all buffers that are
	 * based on these numbers must be de-allocated and re-allocated.  Get
	 * new IOC facts each time chip is initialized.
	 */
	if (mptsas_ioc_get_facts(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "mptsas_ioc_get_facts failed");
		goto fail;
	}

	/*
	 * Now we know chip MSIX capabilitites and it's not been done
	 * previously register interrupts accordingly. Need to know this
	 * information before allocating the reply frames below.
	 */
	if (mptsas_register_intrs(mpt) == FALSE)
		goto fail;

	if (mpt->m_targets == NULL) {
		mpt->m_targets = refhash_create(MPTSAS_TARGET_BUCKET_COUNT,
		    mptsas_target_addr_hash, mptsas_target_addr_cmp,
		    mptsas_target_free, sizeof (mptsas_target_t),
		    offsetof(mptsas_target_t, m_link),
		    offsetof(mptsas_target_t, m_addr), KM_SLEEP);
	}

	if (mptsas_alloc_active_slots(mpt, KM_SLEEP)) {
		goto fail;
	}

	/*
	 * Allocate request message frames, reply free queue, reply descriptor
	 * post queue, and reply message frames using latest IOC facts.
	 */
	if (mptsas_alloc_request_frames(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "mptsas_alloc_request_frames failed");
		goto fail;
	}
	if (mptsas_alloc_sense_bufs(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "mptsas_alloc_sense_bufs failed");
		goto fail;
	}
	if (mptsas_alloc_free_queue(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "mptsas_alloc_free_queue failed!");
		goto fail;
	}
	if (mptsas_alloc_post_queue(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "mptsas_alloc_post_queue failed!");
		goto fail;
	}
	if (mptsas_alloc_reply_frames(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "mptsas_alloc_reply_frames failed!");
		goto fail;
	}

mur:
	/*
	 * Re-Initialize ioc to operational state
	 */
	if (mptsas_ioc_init(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "mptsas_ioc_init failed");
		goto fail;
	}

	mptsas_alloc_reply_args(mpt);

	/*
	 * Initialize the Reply Free Queue with the physical addresses of our
	 * reply frames.
	 */
	cookie.dmac_address = mpt->m_reply_frame_dma_addr&0xfffffffful;
	for (i = 0; i < mpt->m_max_replies; i++) {
		ddi_put32(mpt->m_acc_free_queue_hdl,
		    &((uint32_t *)(void *)mpt->m_free_queue)[i],
		    cookie.dmac_address);
		cookie.dmac_address += mpt->m_reply_frame_size;
	}
	(void) ddi_dma_sync(mpt->m_dma_free_queue_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Initialize the reply free index to one past the last frame on the
	 * queue.  This will signify that the queue is empty to start with.
	 */
	mpt->m_free_index = i;
	ddi_put32(mpt->m_datap, &mpt->m_reg->ReplyFreeHostIndex, i);

	/*
	 * Initialize the reply post queue to 0xFFFFFFFF,0xFFFFFFFF's
	 * and the indexes to 0.
	 */
	rpqp = mpt->m_rep_post_queues;
	for (j = 0; j < mpt->m_post_reply_qcount; j++) {
		for (i = 0; i < mpt->m_post_queue_depth; i++) {
			ddi_put64(mpt->m_acc_post_queue_hdl,
			    &((uint64_t *)(void *)rpqp->rpq_queue)[i],
			    0xFFFFFFFFFFFFFFFF);
		}
		rpqp->rpq_index = 0;
		rpqp++;
	}
	(void) ddi_dma_sync(mpt->m_dma_post_queue_hdl, 0, 0,
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Initialise all the reply post queue indexes.
	 */
	for (j = 0; j < mpt->m_post_reply_qcount; j++) {
		ddi_put32(mpt->m_datap, &mpt->m_reg->ReplyPostHostIndex,
		    j << MPI2_RPHI_MSIX_INDEX_SHIFT);
	}

	/*
	 * Enable ports
	 */
	if (mptsas_ioc_enable_port(mpt) == DDI_FAILURE) {
		mptsas_log(mpt, CE_WARN, "mptsas_ioc_enable_port failed");
		goto fail;
	}

	/*
	 * enable events
	 */
	if (mptsas_ioc_enable_event_notification(mpt)) {
		mptsas_log(mpt, CE_WARN,
		    "mptsas_ioc_enable_event_notification failed");
		goto fail;
	}

	/*
	 * We need checks in attach and these.
	 * chip_init is called in mult. places
	 */

	if ((mptsas_check_dma_handle(mpt->m_dma_req_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_req_sense_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_reply_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_free_queue_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_dma_post_queue_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_dma_handle(mpt->m_hshk_dma_hdl) !=
	    DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		goto fail;
	}

	/* Check all acc handles */
	if ((mptsas_check_acc_handle(mpt->m_datap) != DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_req_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_req_sense_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_reply_frame_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_free_queue_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_acc_post_queue_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_hshk_acc_hdl) !=
	    DDI_SUCCESS) ||
	    (mptsas_check_acc_handle(mpt->m_config_handle) !=
	    DDI_SUCCESS)) {
		ddi_fm_service_impact(mpt->m_dip, DDI_SERVICE_UNAFFECTED);
		goto fail;
	}
	mpt->m_softstate &= ~MPTSAS_SS_INIT_FAILED;
	return (DDI_SUCCESS);

fail:
	mpt->m_softstate |= MPTSAS_SS_INIT_FAILED;
	return (DDI_FAILURE);
}

static int
mptsas_get_pci_cap(mptsas_t *mpt)
{
	ushort_t caps_ptr, cap, cap_count;

	if (mpt->m_config_handle == NULL)
		return (FALSE);
	/*
	 * Check if capabilities list is supported and if so,
	 * get initial capabilities pointer and clear bits 0,1.
	 */
	if (pci_config_get16(mpt->m_config_handle, PCI_CONF_STAT)
	    & PCI_STAT_CAP) {
		caps_ptr = P2ALIGN(pci_config_get8(mpt->m_config_handle,
		    PCI_CONF_CAP_PTR), 4);
	} else {
		caps_ptr = PCI_CAP_NEXT_PTR_NULL;
	}

	/*
	 * Walk capabilities if supported.
	 */
	for (cap_count = 0; caps_ptr != PCI_CAP_NEXT_PTR_NULL; ) {

		/*
		 * Check that we haven't exceeded the maximum number of
		 * capabilities and that the pointer is in a valid range.
		 */
		if (++cap_count > 48) {
			mptsas_log(mpt, CE_WARN,
			    "too many device capabilities.\n");
			break;
		}
		if (caps_ptr < 64) {
			mptsas_log(mpt, CE_WARN,
			    "capabilities pointer 0x%x out of range.\n",
			    caps_ptr);
			break;
		}

		/*
		 * Get next capability and check that it is valid.
		 * For now, we only support power management.
		 */
		cap = pci_config_get8(mpt->m_config_handle, caps_ptr);
		switch (cap) {
			case PCI_CAP_ID_PM:
				mptsas_log(mpt, CE_NOTE,
				    "?mptsas3%d supports power management.\n",
				    mpt->m_instance);
				mpt->m_options |= MPTSAS_OPT_PM;

				/* Save PMCSR offset */
				mpt->m_pmcsr_offset = caps_ptr + PCI_PMCSR;
				break;
			case PCI_CAP_ID_MSI:
				mptsas_log(mpt, CE_NOTE,
				    "?mptsas3%d supports MSI.\n",
				    mpt->m_instance);
				mpt->m_options |= MPTSAS_OPT_MSI;
				break;
			case PCI_CAP_ID_MSI_X:
				mptsas_log(mpt, CE_NOTE,
				    "?mptsas3%d supports MSI-X.\n",
				    mpt->m_instance);
				mpt->m_options |= MPTSAS_OPT_MSI_X;
				break;
			/*
			 * The following capabilities are valid.  Any others
			 * will cause a message to be logged.
			 */
			case PCI_CAP_ID_VPD:
			case PCI_CAP_ID_PCIX:
			case PCI_CAP_ID_PCI_E:
				break;
			default:
				mptsas_log(mpt, CE_NOTE,
				    "?mptsas3%d unrecognized capability "
				    "0x%x.\n", mpt->m_instance, cap);
				break;
		}

		/*
		 * Get next capabilities pointer and clear bits 0,1.
		 */
		caps_ptr = P2ALIGN(pci_config_get8(mpt->m_config_handle,
		    (caps_ptr + PCI_CAP_NEXT_PTR)), 4);
	}
	return (TRUE);
}

static int
mptsas_init_pm(mptsas_t *mpt)
{
	char		pmc_name[16];
	char		*pmc[] = {
				NULL,
				"0=Off (PCI D3 State)",
				"3=On (PCI D0 State)",
				NULL
			};
	uint16_t	pmcsr_stat;

	/*
	 * If PCI's capability does not support PM, then don't need
	 * to registe the pm-components
	 */
	if (!(mpt->m_options & MPTSAS_OPT_PM))
		return (DDI_SUCCESS);
	/*
	 * If power management is supported by this chip, create
	 * pm-components property for the power management framework
	 */
	(void) sprintf(pmc_name, "NAME=mptsas3%d", mpt->m_instance);
	pmc[0] = pmc_name;
	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, mpt->m_dip,
	    "pm-components", pmc, 3) != DDI_PROP_SUCCESS) {
		mpt->m_options &= ~MPTSAS_OPT_PM;
		mptsas_log(mpt, CE_WARN,
		    "mptsas3%d: pm-component property creation failed.",
		    mpt->m_instance);
		return (DDI_FAILURE);
	}

	/*
	 * Power on device.
	 */
	(void) pm_busy_component(mpt->m_dip, 0);
	pmcsr_stat = pci_config_get16(mpt->m_config_handle,
	    mpt->m_pmcsr_offset);
	if ((pmcsr_stat & PCI_PMCSR_STATE_MASK) != PCI_PMCSR_D0) {
		mptsas_log(mpt, CE_WARN, "mptsas3%d: Power up the device",
		    mpt->m_instance);
		pci_config_put16(mpt->m_config_handle, mpt->m_pmcsr_offset,
		    PCI_PMCSR_D0);
	}
	if (pm_power_has_changed(mpt->m_dip, 0, PM_LEVEL_D0) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "pm_power_has_changed failed");
		return (DDI_FAILURE);
	}
	mpt->m_power_level = PM_LEVEL_D0;
	/*
	 * Set pm idle delay.
	 */
	mpt->m_pm_idle_delay = ddi_prop_get_int(DDI_DEV_T_ANY,
	    mpt->m_dip, 0, "mptsas-pm-idle-delay", MPTSAS_PM_IDLE_TIMEOUT);

	return (DDI_SUCCESS);
}

static int
mptsas_register_intrs(mptsas_t *mpt)
{
	dev_info_t *dip;
	int intr_types;

	dip = mpt->m_dip;

	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(dip, &intr_types) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "ddi_intr_get_supported_types "
		    "failed\n");
		return (FALSE);
	}

	NDBG6(("%d: ddi_intr_get_supported_types() returned: 0x%x",
	    mpt->m_instance, intr_types));

	/*
	 * Try MSIX first.
	 */
	if (mptsas_enable_msix && (intr_types & DDI_INTR_TYPE_MSIX)) {
		if (mptsas_add_intrs(mpt, DDI_INTR_TYPE_MSIX) == DDI_SUCCESS) {
			NDBG6(("%d: Using MSI-X interrupt type",
			    mpt->m_instance));
			mpt->m_intr_type = DDI_INTR_TYPE_MSIX;
			return (TRUE);
		}
	}

	/*
	 * Try MSI, but fall back to FIXED
	 */
	if (mptsas_enable_msi && (intr_types & DDI_INTR_TYPE_MSI)) {
		if (mptsas_add_intrs(mpt, DDI_INTR_TYPE_MSI) == DDI_SUCCESS) {
			NDBG6(("%d: Using MSI interrupt type",
			    mpt->m_instance));
			mpt->m_intr_type = DDI_INTR_TYPE_MSI;
			return (TRUE);
		}
	}
	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (mptsas_add_intrs(mpt, DDI_INTR_TYPE_FIXED) == DDI_SUCCESS) {
			NDBG6(("%d: Using FIXED interrupt type",
			    mpt->m_instance));
			mpt->m_intr_type = DDI_INTR_TYPE_FIXED;
			return (TRUE);
		} else {
			NDBG6(("%d: FIXED interrupt registration failed",
			    mpt->m_instance));
			return (FALSE);
		}
	}

	return (FALSE);
}

static void
mptsas_unregister_intrs(mptsas_t *mpt)
{
	if (mpt->m_intr_cnt != 0) {
		mptsas_rem_intrs(mpt);
	}
}

/*
 * mptsas_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 * The mptsas_ignore_mptmsixmax_ondevid variable identifies a device ids
 * for which we should ignore the values returned from the IOC
 * Facts inquiry and just go on the ddi_intr() framework info.
 */
int mptsas_ignore_mptmsixmax_ondevid[3] = {
	MPI2_MFGPAGE_DEVID_SAS2308_1,
	MPI2_MFGPAGE_DEVID_SAS2308_2, 0
};

static int
mptsas_add_intrs(mptsas_t *mpt, int intr_type)
{
	dev_info_t	*dip = mpt->m_dip;
	int		avail, actual, count = 0;
	int		i, flag, ret;

	NDBG6(("%d: add_intrs:interrupt type 0x%x",
	    mpt->m_instance, intr_type));

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count <= 0)) {
		mptsas_log(mpt, CE_WARN, "ddi_intr_get_nintrs() failed, "
		    "ret %d count %d\n", ret, count);

		return (DDI_FAILURE);
	}

	/* Get number of interrupts available to this device */
	ret = ddi_intr_get_navail(dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		mptsas_log(mpt, CE_WARN, "ddi_intr_get_navail() failed, "
		    "ret %d avail %d\n", ret, avail);

		return (DDI_FAILURE);
	}

	if (count < avail) {
		mptsas_log(mpt, CE_NOTE, "ddi_intr_get_nvail returned %d, "
		    "navail() returned %d", count, avail);
	}

	NDBG6(("%d: add_intrs:count %d, avail %d", mpt->m_instance,
	    count, avail));

	if (intr_type == DDI_INTR_TYPE_MSIX) {
		if (!mptsas3_max_msix_intrs) {
			return (DDI_FAILURE);
		}

		/*
		 * Restrict the number of interrupts, firstly by
		 * the number returned from the IOCInfo, then by
		 * overall restriction.
		 */
		flag = 0;
		for (i = 0; i < sizeof (mptsas_ignore_mptmsixmax_ondevid)/
		    sizeof (mptsas_ignore_mptmsixmax_ondevid[0]); i++) {
			if (mptsas_ignore_mptmsixmax_ondevid[i] == mpt->m_devid)
				flag = 1;
		}
		if ((flag == 0) && (avail > mpt->m_max_msix_vectors)) {
			avail = mpt->m_max_msix_vectors?
			    mpt->m_max_msix_vectors:1;
			NDBG6(("%d: add_intrs: mmmv avail %d",
			    mpt->m_instance, avail));
		}
		if (avail > mptsas3_max_msix_intrs) {
			avail = mptsas3_max_msix_intrs;
			NDBG6(("%d: add_intrs: m3mmi avail %d",
			    mpt->m_instance, avail));
		}

		/*
		 * Reset the cpu to replyq map.
		 * Note that if you want to turn this optimization off
		 * set all the values in the array to -2.
		 */
		for (i = 0; i < NCPUS; i++) {
			if (mpt->m_cpu_to_repq[i] >= 0)
				mpt->m_cpu_to_repq[i] = -1;
		}
	}
	if (intr_type == DDI_INTR_TYPE_MSI) {
		NDBG6(("%d: add_intrs: MSI avail %d", mpt->m_instance,
		    avail));
		avail = 1;
	}

	/* Allocate an array of interrupt handles */
	mpt->m_intr_size = avail * sizeof (ddi_intr_handle_t);
	mpt->m_htable = kmem_alloc(mpt->m_intr_size, KM_SLEEP);

	flag = DDI_INTR_ALLOC_NORMAL;

	/* call ddi_intr_alloc() */
	ret = ddi_intr_alloc(dip, mpt->m_htable, intr_type, 0,
	    avail, &actual, flag);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		mptsas_log(mpt, CE_WARN, "ddi_intr_alloc() failed, ret %d\n",
		    ret);
		kmem_free(mpt->m_htable, mpt->m_intr_size);
		return (DDI_FAILURE);
	}

	NDBG6(("%d: add_intrs: actual %d, avail %d", mpt->m_instance,
	    actual, avail));
	/* use interrupt count returned or abort? */
	if (actual < avail) {
		mptsas_log(mpt, CE_NOTE,
		    "Interrupts requested: %d, received: %d\n",
		    avail, actual);
	}

	/*
	 * Get priority for first msi, assume remaining are all the same
	 */
	if ((ret = ddi_intr_get_pri(mpt->m_htable[0],
	    &mpt->m_intr_pri)) != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "ddi_intr_get_pri() failed %d\n", ret);

		/* Free already allocated intr */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(mpt->m_htable[i]);
		}

		kmem_free(mpt->m_htable, mpt->m_intr_size);
		return (DDI_FAILURE);
	}

	/* Test for high level mutex */
	if (mpt->m_intr_pri >= ddi_intr_get_hilevel_pri()) {
		mptsas_log(mpt, CE_WARN, "mptsas_add_intrs: "
		    "Hi level interrupt not supported\n");

		/* Free already allocated intr */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(mpt->m_htable[i]);
		}

		kmem_free(mpt->m_htable, mpt->m_intr_size);
		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(mpt->m_htable[i], mptsas_intr,
		    (caddr_t)mpt, (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "ddi_intr_add_handler() "
			    "failed %d\n", ret);

			/* Free already allocated intr */
			for (i = 0; i < actual; i++) {
				(void) ddi_intr_free(mpt->m_htable[i]);
			}

			kmem_free(mpt->m_htable, mpt->m_intr_size);
			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(mpt->m_htable[0], &mpt->m_intr_cap))
	    != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "ddi_intr_get_cap() failed %d\n", ret);

		/* Free already allocated intr */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(mpt->m_htable[i]);
		}

		kmem_free(mpt->m_htable, mpt->m_intr_size);
		return (DDI_FAILURE);
	}

	mpt->m_intr_cnt = actual;

	/*
	 * Enable interrupts
	 */
	if (mpt->m_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		(void) ddi_intr_block_enable(mpt->m_htable, mpt->m_intr_cnt);
	} else {
		/* Call ddi_intr_enable for MSI or FIXED interrupts */
		for (i = 0; i < mpt->m_intr_cnt; i++) {
			(void) ddi_intr_enable(mpt->m_htable[i]);
		}
	}

	switch (intr_type) {
	case DDI_INTR_TYPE_MSIX:
		mptsas_log(mpt, CE_NOTE, "?Using %d MSI-X interrupt(s) "
		    "(Available sys %d, mpt %d, Requested %d)\n",
		    actual, count, mpt->m_max_msix_vectors, avail);
		break;
	case DDI_INTR_TYPE_MSI:
		mptsas_log(mpt, CE_NOTE, "Using single MSI interrupt\n");
		break;
	case DDI_INTR_TYPE_FIXED:
	default:
		mptsas_log(mpt, CE_NOTE, "Using single fixed interrupt\n");
		break;
	}

	return (DDI_SUCCESS);
}

/*
 * mptsas_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
static void
mptsas_rem_intrs(mptsas_t *mpt)
{
	int	i;

	NDBG6(("%d: rem_intrs", mpt->m_instance));

	/* Disable all interrupts */
	if (mpt->m_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_disable() */
		(void) ddi_intr_block_disable(mpt->m_htable, mpt->m_intr_cnt);
	} else {
		for (i = 0; i < mpt->m_intr_cnt; i++) {
			(void) ddi_intr_disable(mpt->m_htable[i]);
		}
	}

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < mpt->m_intr_cnt; i++) {
		(void) ddi_intr_remove_handler(mpt->m_htable[i]);
		(void) ddi_intr_free(mpt->m_htable[i]);
	}
	kmem_free(mpt->m_htable, mpt->m_intr_size);
	mpt->m_intr_cnt = 0;
}

/*
 * The IO fault service error handling callback function
 */
/*ARGSUSED*/
static int
mptsas_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

/*
 * mptsas_fm_init - initialize fma capabilities and register with IO
 *               fault services.
 */
static void
mptsas_fm_init(mptsas_t *mpt)
{
	/*
	 * Need to change iblock to priority for new MSI intr
	 */
	ddi_iblock_cookie_t	fm_ibc;

	/* Only register with IO Fault Services if we have some capability */
	if (mpt->m_fm_capabilities) {
		/* Adjust access and dma attributes for FMA */
		mpt->m_reg_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
		mpt->m_msg_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		mpt->m_io_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;

		/*
		 * Register capabilities with IO Fault Services.
		 * mpt->m_fm_capabilities will be updated to indicate
		 * capabilities actually supported (not requested.)
		 */
		ddi_fm_init(mpt->m_dip, &mpt->m_fm_capabilities, &fm_ibc);

		/*
		 * Initialize pci ereport capabilities if ereport
		 * capable (should always be.)
		 */
		if (DDI_FM_EREPORT_CAP(mpt->m_fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(mpt->m_fm_capabilities)) {
			pci_ereport_setup(mpt->m_dip);
		}

		/*
		 * Register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(mpt->m_fm_capabilities)) {
			ddi_fm_handler_register(mpt->m_dip,
			    mptsas_fm_error_cb, (void *) mpt);
		}
	}
}

/*
 * mptsas_fm_fini - Releases fma capabilities and un-registers with IO
 *               fault services.
 *
 */
static void
mptsas_fm_fini(mptsas_t *mpt)
{
	/* Only unregister FMA capabilities if registered */
	if (mpt->m_fm_capabilities) {

		/*
		 * Un-register error callback if error callback capable.
		 */

		if (DDI_FM_ERRCB_CAP(mpt->m_fm_capabilities)) {
			ddi_fm_handler_unregister(mpt->m_dip);
		}

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */

		if (DDI_FM_EREPORT_CAP(mpt->m_fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(mpt->m_fm_capabilities)) {
			pci_ereport_teardown(mpt->m_dip);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(mpt->m_dip);

		/* Adjust access and dma attributes for FMA */
		mpt->m_reg_acc_attr.devacc_attr_access = DDI_DEFAULT_ACC;
		mpt->m_msg_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		mpt->m_io_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;

	}
}

int
mptsas_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t	de;

	if (handle == NULL)
		return (DDI_FAILURE);
	ddi_fm_acc_err_get(handle, &de, DDI_FME_VER0);
	return (de.fme_status);
}

int
mptsas_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t	de;

	if (handle == NULL)
		return (DDI_FAILURE);
	ddi_fm_dma_err_get(handle, &de, DDI_FME_VER0);
	return (de.fme_status);
}

void
mptsas_fm_ereport(mptsas_t *mpt, char *detail)
{
	uint64_t	ena;
	char		buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(mpt->m_fm_capabilities)) {
		ddi_fm_ereport_post(mpt->m_dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
}

static int
mptsas_get_target_device_info(mptsas_t *mpt, uint32_t page_address,
    uint16_t *dev_handle, mptsas_target_t **pptgt)
{
	uint32_t	dev_info;
	uint64_t	sas_wwn;
	mptsas_phymask_t phymask;
	uint8_t		physport, phynum, config, disk;
	uint64_t	devicename;
	uint16_t	pdev_hdl;
	mptsas_target_t	*tmp_tgt = NULL;
	uint16_t	bay_num, enclosure, io_flags;

	ASSERT(*pptgt == NULL);

	if (mptsas_get_sas_device_page0(mpt, page_address, dev_handle,
	    &sas_wwn, &dev_info, &physport, &phynum, &pdev_hdl,
	    &bay_num, &enclosure, &io_flags) != DDI_SUCCESS) {
		return (DEV_INFO_FAIL_PAGE0);
	}

	if ((dev_info & (MPI2_SAS_DEVICE_INFO_SSP_TARGET |
	    MPI2_SAS_DEVICE_INFO_SATA_DEVICE |
	    MPI2_SAS_DEVICE_INFO_ATAPI_DEVICE)) == 0) {
		return (DEV_INFO_WRONG_DEVICE_TYPE);
	}
	if (dev_info == MPI2_SAS_DEVICE_INFO_VIRTSES &&
	    phynum >= mpt->m_num_phys) {
		mptsas_log(mpt, CE_CONT,
		    "!mptsas_get_target_device_info(): Omit "
		    "dev_handle 0x%x, phynum 0x%x, enclosure 0x%x, "
		    "physport 0x%x, dev_info 0x%x, wwn w%016"PRIx64"\n",
		    *dev_handle, phynum, enclosure, physport, dev_info,
		    sas_wwn);
		return (DEV_INFO_WRONG_DEVICE_TYPE);
	}

	/*
	 * Check if the dev handle is for a Phys Disk. If so, set return value
	 * and exit.  Don't add Phys Disks to hash.
	 */
	for (config = 0; config < mpt->m_num_raid_configs; config++) {
		for (disk = 0; disk < MPTSAS_MAX_DISKS_IN_CONFIG; disk++) {
			if (*dev_handle == mpt->m_raidconfig[config].
			    m_physdisk_devhdl[disk]) {
				return (DEV_INFO_PHYS_DISK);
			}
		}
	}

	/*
	 * Get SATA Device Name from SAS device page0 for
	 * sata device, if device name doesn't exist, set mta_wwn to
	 * 0 for direct attached SATA. For the device behind the expander
	 * we still can use STP address assigned by expander.
	 */
	if (dev_info & (MPI2_SAS_DEVICE_INFO_SATA_DEVICE |
	    MPI2_SAS_DEVICE_INFO_ATAPI_DEVICE)) {
		mutex_exit(&mpt->m_mutex);
		/* alloc a tmp_tgt to send the cmd */
		tmp_tgt = kmem_zalloc(sizeof (struct mptsas_target),
		    KM_SLEEP);
		tmp_tgt->m_devhdl = *dev_handle;
		tmp_tgt->m_deviceinfo = dev_info;
		tmp_tgt->m_qfull_retries = QFULL_RETRIES;
		tmp_tgt->m_qfull_retry_interval =
		    drv_usectohz(QFULL_RETRY_INTERVAL * 1000);
		tmp_tgt->m_t_throttle = tmp_tgt->m_t_maxthrottle =
		    (int16_t)mptsas_max_throttle;
		mutex_init(&tmp_tgt->m_t_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&tmp_tgt->m_t_cv, NULL, CV_DRIVER, NULL);
		TAILQ_INIT(&tmp_tgt->m_active_cmdq);
		STAILQ_INIT(&tmp_tgt->m_t_wait.cl_q);
		devicename = mptsas_get_sata_guid(mpt, tmp_tgt);
		cv_destroy(&tmp_tgt->m_t_cv);
		mutex_destroy(&tmp_tgt->m_t_mutex);
		kmem_free(tmp_tgt, sizeof (struct mptsas_target));
		mutex_enter(&mpt->m_mutex);
		if (devicename != 0 && (((devicename >> 56) & 0xf0) == 0x50)) {
			sas_wwn = devicename;
		} else if (dev_info & MPI2_SAS_DEVICE_INFO_DIRECT_ATTACH) {
			sas_wwn = 0;
		}
	}

	phymask = mptsas_physport_to_phymask(mpt, physport);
	*pptgt = mptsas_tgt_alloc(mpt, *dev_handle, sas_wwn, dev_info,
	    phymask, phynum);
	(*pptgt)->m_io_flags = io_flags;
	(*pptgt)->m_enclosure = enclosure;
	(*pptgt)->m_slot_num = bay_num;
	return (DEV_INFO_SUCCESS);
}

static uint64_t
mptsas_get_sata_guid(mptsas_t *mpt, mptsas_target_t *ptgt)
{
	uint64_t	sata_guid = 0, *pwwn = NULL;
	int		target = ptgt->m_devhdl;
	uchar_t		*inq83 = NULL;
	int		inq83_len = 0xFF;
	uchar_t		*dblk = NULL;
	int		inq83_retry = 3;
	int		rval = DDI_FAILURE;

	inq83	= kmem_zalloc(inq83_len, KM_SLEEP);

inq83_retry:
	rval = mptsas_inquiry(mpt, ptgt, 0, 0x83, inq83,
	    inq83_len, NULL, 1);
	if (rval != DDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "!mptsas request inquiry page "
		    "0x83 for target:%d, lun:0 failed!", target);
		goto out;
	}
	/* According to SAT2, the first descriptor is logic unit name */
	dblk = &inq83[4];
	if ((dblk[1] & 0x30) != 0) {
		mptsas_log(mpt, CE_WARN, "!Descriptor is not lun associated.");
		goto out;
	}
	pwwn = (uint64_t *)(void *)(&dblk[4]);
	if ((dblk[4] & 0xf0) == 0x50) {
		sata_guid = BE_64(*pwwn);
		goto out;
	} else if (dblk[4] == 'A') {
		NDBG20(("SATA drive has no NAA format GUID."));
		goto out;
	} else {
		/* The data is not ready, wait and retry */
		inq83_retry--;
		if (inq83_retry <= 0) {
			goto out;
		}
		NDBG20(("The GUID is not ready, retry..."));
		delay(1 * drv_usectohz(1000000));
		goto inq83_retry;
	}
out:
	kmem_free(inq83, inq83_len);
	return (sata_guid);
}

static int
mptsas_inquiry(mptsas_t *mpt, mptsas_target_t *ptgt, int lun, uchar_t page,
    unsigned char *buf, int len, int *reallen, uchar_t evpd)
{
	uchar_t			cdb[CDB_GROUP0];
	struct scsi_address	ap;
	struct buf		*data_bp = NULL;
	int			resid = 0;
	int			ret = DDI_FAILURE;

	ASSERT(len <= 0xffff);

	ap.a_target = MPTSAS_INVALID_DEVHDL;
	ap.a_lun = (uchar_t)(lun);
	ap.a_hba_tran = mpt->m_tran;

	data_bp = scsi_alloc_consistent_buf(&ap,
	    (struct buf *)NULL, len, B_READ, NULL_FUNC, NULL);
	if (data_bp == NULL) {
		return (ret);
	}
	bzero(cdb, CDB_GROUP0);
	cdb[0] = SCMD_INQUIRY;
	cdb[1] = evpd;
	cdb[2] = page;
	cdb[3] = (len & 0xff00) >> 8;
	cdb[4] = (len & 0x00ff);
	cdb[5] = 0;

	ret = mptsas_send_scsi_cmd(mpt, &ap, ptgt, &cdb[0], CDB_GROUP0, data_bp,
	    &resid);
	if (ret == DDI_SUCCESS) {
		if (reallen) {
			*reallen = len - resid;
		}
		bcopy((caddr_t)data_bp->b_un.b_addr, buf, len);
	}
	if (data_bp) {
		scsi_free_consistent_buf(data_bp);
	}
	return (ret);
}

static int
mptsas_send_scsi_cmd(mptsas_t *mpt, struct scsi_address *ap,
    mptsas_target_t *ptgt, uchar_t *cdb, int cdblen, struct buf *data_bp,
    int *resid)
{
	struct scsi_pkt		*pktp = NULL;
	scsi_hba_tran_t		*tran_clone = NULL;
	mptsas_tgt_private_t	*tgt_private = NULL;
	int			ret = DDI_FAILURE;

	/*
	 * scsi_hba_tran_t->tran_tgt_private is used to pass the address
	 * information to scsi_init_pkt, allocate a scsi_hba_tran structure
	 * to simulate the cmds from sd
	 */
	tran_clone = kmem_alloc(
	    sizeof (scsi_hba_tran_t), KM_SLEEP);
	if (tran_clone == NULL) {
		goto out;
	}
	bcopy((caddr_t)mpt->m_tran,
	    (caddr_t)tran_clone, sizeof (scsi_hba_tran_t));
	tgt_private = kmem_alloc(
	    sizeof (mptsas_tgt_private_t), KM_SLEEP);
	if (tgt_private == NULL) {
		goto out;
	}
	tgt_private->t_lun = ap->a_lun;
	tgt_private->t_private = ptgt;
	tran_clone->tran_tgt_private = tgt_private;
	ap->a_hba_tran = tran_clone;

	pktp = scsi_init_pkt(ap, (struct scsi_pkt *)NULL,
	    data_bp, cdblen, sizeof (struct scsi_arq_status),
	    0, PKT_CONSISTENT, NULL, NULL);
	if (pktp == NULL) {
		goto out;
	}
	bcopy(cdb, pktp->pkt_cdbp, cdblen);
	pktp->pkt_flags = FLAG_NOPARITY | FLAG_HEAD;
	pktp->pkt_time = mptsas_scsi_pkt_time;
	if (scsi_poll(pktp) < 0) {
		goto out;
	}
	if (((struct scsi_status *)pktp->pkt_scbp)->sts_chk) {
		goto out;
	}
	if (resid != NULL) {
		*resid = pktp->pkt_resid;
	}

	ret = DDI_SUCCESS;
out:
	if (pktp) {
		scsi_destroy_pkt(pktp);
	}
	if (tran_clone) {
		kmem_free(tran_clone, sizeof (scsi_hba_tran_t));
	}
	if (tgt_private) {
		kmem_free(tgt_private, sizeof (mptsas_tgt_private_t));
	}
	return (ret);
}

static int
mptsas_parse_address(char *name, uint64_t *wwid, uint8_t *phy, int *lun)
{
	char	*cp = NULL;
	char	*ptr = NULL;
	size_t	s = 0;
	char	*wwid_str = NULL;
	char	*lun_str = NULL;
	long	lunnum;
	long	phyid = -1;
	int	rc = DDI_FAILURE;

	ptr = name;
	ASSERT(ptr[0] == 'w' || ptr[0] == 'p');
	ptr++;
	if ((cp = strchr(ptr, ',')) == NULL) {
		return (DDI_FAILURE);
	}

	wwid_str = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	s = (uintptr_t)cp - (uintptr_t)ptr;

	bcopy(ptr, wwid_str, s);
	wwid_str[s] = '\0';

	ptr = ++cp;

	if ((cp = strchr(ptr, '\0')) == NULL) {
		goto out;
	}
	lun_str =  kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	s = (uintptr_t)cp - (uintptr_t)ptr;

	bcopy(ptr, lun_str, s);
	lun_str[s] = '\0';

	if (name[0] == 'p') {
		rc = ddi_strtol(wwid_str, NULL, 0x10, &phyid);
	} else {
		rc = scsi_wwnstr_to_wwn(wwid_str, wwid);
	}
	if (rc != DDI_SUCCESS)
		goto out;

	if (phyid != -1) {
		ASSERT(phyid < MPTSAS_MAX_PHYS);
		*phy = (uint8_t)phyid;
	}
	rc = ddi_strtol(lun_str, NULL, 0x10, &lunnum);
	if (rc != 0)
		goto out;

	*lun = (int)lunnum;
	rc = DDI_SUCCESS;
out:
	if (wwid_str)
		kmem_free(wwid_str, SCSI_MAXNAMELEN);
	if (lun_str)
		kmem_free(lun_str, SCSI_MAXNAMELEN);

	return (rc);
}

/*
 * mptsas_parse_smp_name() is to parse sas wwn string
 * which format is "wWWN"
 */
static int
mptsas_parse_smp_name(char *name, uint64_t *wwn)
{
	char	*ptr = name;

	if (*ptr != 'w') {
		return (DDI_FAILURE);
	}

	ptr++;
	if (scsi_wwnstr_to_wwn(ptr, wwn)) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Initiate the config state machine to a probe state (tinit).
 * config_wait is called with both the mpt and target mutex held.
 * Ensure the config active flag is set, multiple threads can get here
 * so we also need to keep count.
 * If there is another thread configuring this target set the waiting
 * flag and sleep for completion.
 * If we do need to wait don't want to keep the mpt mutex but have to preserve
 * mutex hierarchy, yuck!
 */
static void
mptsas_config_wait(mptsas_t *mpt, mptsas_target_t *ptgt, uint8_t tinit)
{
	ASSERT(ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL);
	ASSERT(tinit > TINIT_CFGBUSY);
	ASSERT(ptgt->m_t_init != TINIT_UPDATE);

	if (ptgt->m_ncfgluns++ == 0) {
		ASSERT(ptgt->m_cnfg_luns == 0);
		ptgt->m_cnfg_luns = TFGL_ACTIVE;
	} else {
		ASSERT(ptgt->m_cnfg_luns & TFGL_ACTIVE);
	}
	if (ptgt->m_t_init > TINIT_CFGBUSY) {
		mutex_exit(&ptgt->m_t_mutex);
		mutex_exit(&mpt->m_mutex);
		mutex_enter(&ptgt->m_t_mutex);
		while (ptgt->m_t_init > TINIT_CFGBUSY) {
			ptgt->m_cnfg_luns |= TFGL_WAITING;
			DTRACE_PROBE2(have__to__wait, mptsas_target_t *, ptgt,
			    uint8_t, tinit);
			cv_wait(&ptgt->m_t_cv, &ptgt->m_t_mutex);
		}
		ptgt->m_t_init = tinit;
		mutex_exit(&ptgt->m_t_mutex);
		mutex_enter(&mpt->m_mutex);
		mutex_enter(&ptgt->m_t_mutex);
		ASSERT(ptgt->m_cnfg_luns & TFGL_ACTIVE);
	} else {
		ptgt->m_t_init = tinit;
	}
}

static int
mptsas_bus_config(dev_info_t *pdip, uint_t flag,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	int		ret = NDI_FAILURE;
	int		circ = 0;
	int		circ1 = 0;
	mptsas_t	*mpt;
	char		*ptr = NULL;
	char		*devnm = NULL;
	uint64_t	wwid = 0;
	uint8_t		phy = 0xFF;
	int		lun = 0;
	uint_t		mflags = flag;
	int		bconfig = TRUE;
	boolean_t	ndi_held = B_FALSE;
	mptsas_target_t	*ptgt = NULL;

	if (scsi_hba_iport_unit_address(pdip) == 0) {
		return (DDI_FAILURE);
	}

	mpt = DIP2MPT(pdip);
	if (mpt == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&mpt->m_mutex);

	/*
	 * Wait for any chip reset operation to complete.
	 */
	while (mpt->m_in_reset == TRUE &&
	    (mpt->m_softstate & MPTSAS_SS_INIT_FAILED) == 0) {
		cv_wait(&mpt->m_cv, &mpt->m_mutex);
	}
	if (mpt->m_softstate & MPTSAS_SS_INIT_FAILED) {
		mutex_exit(&mpt->m_mutex);
		NDBG10(("%d: bus_config, %d, Fail due to un-initialized IOC",
		    mpt->m_instance, op));
		return (DDI_FAILURE);
	}
	mpt->m_bcfgs++;
	mutex_exit(&mpt->m_mutex);

	/*
	 * Hold the nexus across the bus_config
	 */
	switch (op) {
	case BUS_CONFIG_ONE:
		NDBG10(("%d: bus_config, ONE \"%s\"", mpt->m_instance,
		    (char *)arg));
		/* parse wwid/target name out of name given */
		if ((ptr = strchr((char *)arg, '@')) == NULL) {
			ret = NDI_FAILURE;
			break;
		}
		ptr++;
		if (strncmp((char *)arg, "smp", 3) == 0) {
			/*
			 * This is a SMP target device
			 */
			ret = mptsas_parse_smp_name(ptr, &wwid);
			if (ret != DDI_SUCCESS) {
				ret = NDI_FAILURE;
				break;
			}

			ndi_devi_enter(scsi_vhci_dip, &circ);
			ndi_devi_enter(pdip, &circ1);
			ndi_held = B_TRUE;
			ret = mptsas_config_smp(pdip, wwid, childp);
		} else if ((ptr[0] == 'w') || (ptr[0] == 'p')) {
			mptsas_phymask_t phymask;

			/*
			 * OBP could pass down a non-canonical form
			 * bootpath without LUN part when LUN is 0.
			 * So driver need adjust the string.
			 */
			if (strchr(ptr, ',') == NULL) {
				devnm = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
				(void) sprintf(devnm, "%s,0", (char *)arg);
				ptr = strchr(devnm, '@');
				ptr++;
			}

			/*
			 * The device path is wWWID format and the device
			 * is not SMP target device.
			 */
			phymask = ddi_prop_get_int(DDI_DEV_T_ANY, pdip,
			    0, "phymask", 0);
			mutex_enter(&mpt->m_mutex);
			ptgt = mptsas_addr_to_ptgt(mpt, ptr, phymask,
			    &phy, &wwid, &lun);
			/* If found target is returned with m_t_mutex held */
			if (ptgt == NULL) {
				NDBG10(("%d: bus_config, couldn't find target"
				    " for %s", mpt->m_instance, ptr));
				/*
				 * didn't match any device by searching
				 */
				mutex_exit(&mpt->m_mutex);
				ret = NDI_FAILURE;
				break;
			}
			mptsas_config_wait(mpt, ptgt, TINIT_PROBEONE);
			mutex_exit(&ptgt->m_t_mutex);
			mutex_exit(&mpt->m_mutex);
			ret = mptsas_probe_target(pdip, ptgt);
			if (ret == DDI_SUCCESS) {
				ndi_devi_enter(scsi_vhci_dip, &circ);
				ndi_devi_enter(pdip, &circ1);
				ndi_held = B_TRUE;
				mutex_enter(&ptgt->m_t_mutex);
				ASSERT(ptgt->m_t_init == TINIT_PROBEONE);
				ptgt->m_t_init = TINIT_CONFONE;
				mutex_exit(&ptgt->m_t_mutex);

				*childp = NULL;
				if (ptr[0] == 'w') {
					ret = mptsas_config_one_addr(
					    pdip, ptgt, wwid, lun,
					    childp);
				} else if (ptr[0] == 'p') {
					ret = mptsas_config_one_phy(
					    pdip, ptgt, phy, lun,
					    childp);
				}

				/*
				 * If this is CD/DVD device in OBP
				 * path, the ndi_busop_bus_config can
				 * be skipped as config one
				 * operation is done above.
				 */
				if ((ret == NDI_SUCCESS) && (*childp != NULL) &&
				    (strcmp(ddi_node_name(*childp),
				    "cdrom") == 0) && (strncmp((char *)arg,
				    "disk", 4) == 0)) {
					bconfig = FALSE;
					ndi_hold_devi(*childp);
				}
			} else {
				NDBG10(("%d: bus_config: failed probe_target"
				    "for %d", mpt->m_instance, ptgt->m_devhdl));
				ret = NDI_FAILURE;
			}
		} else {
			NDBG10(("%d: bus_config: Unknown config %s",
			    mpt->m_instance, (char *)arg));
			ret = NDI_FAILURE;
			break;
		}

		/*
		 * DDI group instructed us to use this flag.
		 */
		mflags |= NDI_MDI_FALLBACK;
		break;
	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:
		NDBG10(("%d: bus_config, %s", mpt->m_instance,
		    op == BUS_CONFIG_DRIVER ? "DRIVER" : "ALL"));
		mptsas_probe_all(pdip);
		ndi_devi_enter(scsi_vhci_dip, &circ);
		ndi_devi_enter(pdip, &circ1);
		ndi_held = B_TRUE;
		mptsas_config_all(pdip);
		ret = NDI_SUCCESS;
		break;
	default:
		ret = NDI_FAILURE;
		break;
	}

	if ((ret == NDI_SUCCESS) && bconfig) {
		ret = ndi_busop_bus_config(pdip, mflags, op,
		    (devnm == NULL) ? arg : devnm, childp, 0);
	}

	if (ptgt != NULL) {
		mutex_enter(&ptgt->m_t_mutex);
		if (ptgt->m_t_init == TINIT_CONFONE ||
		    ptgt->m_t_init == TINIT_PROBEONE) {
			mptsas_clr_tgtcl(mpt, ptgt);
		}
		mutex_exit(&ptgt->m_t_mutex);
	}
	if (ndi_held) {
		ndi_devi_exit(pdip, circ1);
		ndi_devi_exit(scsi_vhci_dip, circ);
	}
	if (devnm != NULL)
		kmem_free(devnm, SCSI_MAXNAMELEN);
	mutex_enter(&mpt->m_mutex);
	ASSERT(mpt->m_bcfgs != 0);
	mpt->m_bcfgs--;
	mutex_exit(&mpt->m_mutex);
	NDBG10(("%d: bus_config, %d, %s", mpt->m_instance, op,
	    ret == NDI_SUCCESS ? "SUCCESS" : "FAIL"));
	return (ret);
}

static int
mptsas_inq83(mptsas_t *mpt, int lunidx, mptsas_target_t *ptgt)
{
	int			rval = DDI_FAILURE;
	uchar_t			*inq83 = NULL;
	int			i, inq83_len = 0;
	uint16_t		lun;
	struct scsi_inquiry	*sd_inq = &ptgt->m_t_luns[lunidx].l_inqp0;
	ddi_devid_t		devid;
	char			*guid = NULL;

	/*
	 * For DVD/CD ROM and tape devices and optical
	 * devices, we won't try to enumerate them under
	 * scsi_vhci, so no need to try page83
	 */
	if (sd_inq->inq_dtype == DTYPE_RODIRECT ||
	    sd_inq->inq_dtype == DTYPE_OPTICAL ||
	    sd_inq->inq_dtype == DTYPE_ESI) {
		return (DDI_SUCCESS);
	}

	lun = ptgt->m_t_luns[lunidx].l_num;
	inq83 = ptgt->m_t_luns[lunidx].l_inqp83;

	for (i = 0; i < mptsas_inq83_retry_timeout; i++) {
		rval = mptsas_inquiry(mpt, ptgt, lun, 0x83,
		    inq83, INQ83_LEN, &inq83_len, 1);
		if (rval != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN,
			    "!mptsas request inquiry page "
			    "0x83 for target:%d, lun:%d "
			    "failed!", ptgt->m_devhdl, lun);
			if (mptsas_physical_bind_failed_page_83 != B_FALSE)
				return (DDI_SUCCESS);
			else
				return (rval);
		}

		/*
		 * create DEVID from inquiry data
		 */
		rval = ddi_devid_scsi_encode(DEVID_SCSI_ENCODE_VERSION_LATEST,
		    NULL, (uchar_t *)sd_inq, sizeof (struct scsi_inquiry),
		    NULL, 0, inq83, (size_t)inq83_len, &devid);

		if (rval == DDI_SUCCESS) {
			/*
			 * extract GUID from DEVID
			 */
			guid = ddi_devid_to_guid(devid);

			/*
			 * Do not enable MPXIO if the strlen(guid) is greater
			 * than MPTSAS_MAX_GUID_LEN, this constraint would be
			 * handled by framework later.
			 */
			if (guid && (strlen(guid) > MPTSAS_MAX_GUID_LEN)) {
				ddi_devid_free_guid(guid);
				guid = NULL;
				if (mpt->m_mpxio_enable == TRUE) {
					mptsas_log(mpt, CE_NOTE, "!Target:%x, "
					    "lun:%x doesn't have a valid GUID, "
					    "multipathing for this drive is "
					    "not enabled", ptgt->m_devhdl, lun);
				}
			}

			/*
			 * devid no longer needed
			 */
			ddi_devid_free(devid);
			break;
		} else if (rval == DDI_NOT_WELL_FORMED) {
			/*
			 * A return value from ddi_devid_scsi_encode equal to
			 * DDI_NOT_WELL_FORMED means DEVID_RETRY, it's
			 * worthwhile retrying page 0x83 and get GUID.
			 */
			NDBG20(("%d: Not well formed devid, retry...",
			    mpt->m_instance));
			delay(1 * drv_usectohz(1000000));
			continue;
		} else {
			mptsas_log(mpt, CE_WARN, "!Encode devid failed for "
			    "path target:%d, lun:%d", ptgt->m_devhdl, lun);
			break;
		}
	}

	if (i == mptsas_inq83_retry_timeout) {
		mptsas_log(mpt, CE_WARN, "!Repeated page83 requests timeout "
		    "for path target:%d, lun:%d", ptgt->m_devhdl, lun);
	}
	ptgt->m_t_luns[lunidx].l_guid = guid;
	return (DDI_SUCCESS);
}

static int
mptsas_probe_lunidx(mptsas_t *mpt, int lunidx, mptsas_target_t *ptgt)
{
	int		rval = DDI_FAILURE;
	uint16_t	lun;

	ASSERT(ptgt->m_t_nluns > lunidx);
	ASSERT(ptgt->m_t_luns != NULL);

	lun = ptgt->m_t_luns[lunidx].l_num;
	NDBG12(("%d: probe_lun: %d, target %d, dr %d", mpt->m_instance,
	    lun, ptgt->m_devhdl, ptgt->m_dr_flag));

	if (ptgt->m_dr_flag != MPTSAS_DR_INTRANSITION) {
		struct scsi_inquiry	*sd_inq;

		sd_inq = &ptgt->m_t_luns[lunidx].l_inqp0;
		rval = mptsas_inquiry(mpt, ptgt, lun, 0, (uchar_t *)sd_inq,
		    SUN_INQSIZE, NULL, (uchar_t)0);

		if (rval == DDI_SUCCESS) {
			rval = mptsas_inq83(mpt, lunidx, ptgt);

			if (lun == 0 && ptgt->m_deviceinfo &
			    (MPI2_SAS_DEVICE_INFO_SATA_DEVICE |
			    MPI2_SAS_DEVICE_INFO_ATAPI_DEVICE)) {

				(void) mptsas_inquiry(mpt, ptgt, 0, 0x89,
				    ptgt->m_t_luns[lunidx].l_inqp89,
				    INQ89_LEN, NULL, 1);
			}
		}
	}
	NDBG12(("%d: probe_lun: %d target %d - %s", mpt->m_instance,
	    lun, ptgt->m_devhdl, rval == DDI_SUCCESS?"SUCCESS":"FAIL"));
	return (rval);
}

static int
mptsas_config_lunidx(dev_info_t *pdip, int lunidx, dev_info_t **dip,
    mptsas_target_t *ptgt)
{
	int		rval = DDI_FAILURE;
	mptsas_t	*mpt = DIP2MPT(pdip);
	mptsas_lun_t	*plun = &ptgt->m_t_luns[lunidx];

	NDBG12(("%d: config_lun: %d, target %d, dr %d", mpt->m_instance,
	    plun->l_num, ptgt->m_devhdl, ptgt->m_dr_flag));

	if (ptgt->m_dr_flag != MPTSAS_DR_INTRANSITION) {
		if (MPTSAS_VALID_LUN(&plun->l_inqp0)) {
			rval = mptsas_create_lun(pdip, dip, ptgt, plun);
		} else {
			rval = DDI_FAILURE;
		}
	}
	NDBG12(("%d: config_lun: %d target %d ret %s", mpt->m_instance,
	    plun->l_num, ptgt->m_devhdl,
	    rval == DDI_SUCCESS ? "SUCCESS" : "FAIL"));
	return (rval);
}

static int
mptsas_config_lun(dev_info_t *pdip, int lun, dev_info_t **dip,
    mptsas_target_t *ptgt)
{
	int	lidx;

	if (ptgt->m_t_luns != NULL) {
		for (lidx = 0; lidx < ptgt->m_t_nluns; lidx++)
			if (ptgt->m_t_luns[lidx].l_num == lun)
				return (mptsas_config_lunidx(pdip, lidx,
				    dip, ptgt));
	}
	return (DDI_FAILURE);
}

/*
 * Release all the flags and check if there was an offline event.
 * If there was dispatch an event to do it now.
 */
static void
mptsas_clr_tgtcl(mptsas_t *mpt, mptsas_target_t *ptgt)
{
	uint8_t		cfl_hist = ptgt->m_cnfg_luns;
	
	ASSERT(ptgt->m_t_init != TINIT_UPDATE);

	ptgt->m_ncfgluns--;
	if (ptgt->m_cnfg_luns & TFGL_WAITING) {
		ptgt->m_cnfg_luns &= ~TFGL_WAITING;
		cv_broadcast(&ptgt->m_t_cv);
	}

	/*
	 * Have to wait until all threads attempting config have finished going
	 * through the state machine before actually dispatching the offline.
	 */
	if (ptgt->m_ncfgluns == 0) {
		ptgt->m_t_init = TINIT_DONE;
		if (ptgt->m_cnfg_luns & TFGL_OFFLINE) {
			mptsas_dispatch_offline_tgt(mpt, ptgt,
			    (ptgt->m_cnfg_luns & TFGL_FREEHDL) != 0);
		}
		ptgt->m_cfl_hist = cfl_hist;
		ptgt->m_cnfg_luns = 0;
	} else {
		ptgt->m_t_init = TINIT_CFGBUSY;
	}
}

static int
mptsas_config_one_addr(dev_info_t *pdip, mptsas_target_t *ptgt,
    uint64_t sasaddr, int lun, dev_info_t **lundip)
{
	int		phymask_prop;

	/*
	 * Get the physical port associated to the iport
	 */
	phymask_prop = ddi_prop_get_int(DDI_DEV_T_ANY, pdip, 0, "phymask", 0);

	/*
	 * If the LUN already exists and the status is online,
	 * we just return the pointer to dev_info_t directly.
	 * For the mdi_pathinfo node, we'll handle it in
	 * mptsas_create_virt_lun()
	 * TODO should be also in mptsas_handle_dr
	 */

	*lundip = mptsas_find_child_addr(pdip, sasaddr, lun);
	if (*lundip != NULL) {
		/*
		 * TODO Another senario is, we hotplug the same disk
		 * on the same slot, the devhdl changed, is this
		 * possible?
		 * tgt_private->t_private != ptgt
		 */
		if (sasaddr != ptgt->m_addr.mta_wwn) {
			/*
			 * The device has changed although the devhdl is the
			 * same (Enclosure mapping mode, change drive on the
			 * same slot)
			 */
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	}

	if (phymask_prop == 0) {
		/*
		 * Configure IR volume
		 */
		return (mptsas_config_raid(pdip, ptgt->m_devhdl, lundip));
	}
	return (mptsas_config_lun(pdip, lun, lundip, ptgt));
}

static int
mptsas_config_one_phy(dev_info_t *pdip, mptsas_target_t *ptgt, uint8_t phy,
    int lun, dev_info_t **lundip)
{
	/*
	 * If the LUN already exists and the status is online,
	 * we just return the pointer to dev_info_t directly.
	 * For the mdi_pathinfo node, we'll handle it in
	 * mptsas_create_virt_lun().
	 */

	*lundip = mptsas_find_child_phy(pdip, phy);
	if (*lundip != NULL) {
		return (DDI_SUCCESS);
	}

	return (mptsas_config_lun(pdip, lun, lundip, ptgt));
}

static int
mptsas_retrieve_lundata(int lun_cnt, uint8_t *buf, uint16_t *lun_num,
    uint8_t *lun_addr_type)
{
	uint32_t	lun_idx = 0;

	ASSERT(lun_num != NULL);
	ASSERT(lun_addr_type != NULL);

	lun_idx = (lun_cnt + 1) * MPTSAS_SCSI_REPORTLUNS_ADDRESS_SIZE;
	/* determine report luns addressing type */
	switch (buf[lun_idx] & MPTSAS_SCSI_REPORTLUNS_ADDRESS_MASK) {
		/*
		 * Vendors in the field have been found to be concatenating
		 * bus/target/lun to equal the complete lun value instead
		 * of switching to flat space addressing
		 */
		/* 00b - peripheral device addressing method */
	case MPTSAS_SCSI_REPORTLUNS_ADDRESS_PERIPHERAL:
		/* FALLTHRU */
		/* 10b - logical unit addressing method */
	case MPTSAS_SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT:
		/* FALLTHRU */
		/* 01b - flat space addressing method */
	case MPTSAS_SCSI_REPORTLUNS_ADDRESS_FLAT_SPACE:
		/* byte0 bit0-5=msb lun byte1 bit0-7=lsb lun */
		*lun_addr_type = (buf[lun_idx] &
		    MPTSAS_SCSI_REPORTLUNS_ADDRESS_MASK) >> 6;
		*lun_num = (buf[lun_idx] & 0x3F) << 8;
		*lun_num |= buf[lun_idx + 1];
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
mptsas_probe_luns(dev_info_t *pdip, mptsas_target_t *ptgt)
{
	struct buf		*repluns_bp = NULL;
	struct scsi_address	ap;
	uchar_t			cdb[CDB_GROUP5];
	int			ret = DDI_SUCCESS;
	int			retry = 0;
	int			lun_list_len = 0;
	uint16_t		lun_num = 0;
	uint8_t			lun_addr_type = 0;
	uint16_t		lun_cnt = 0;
	uint16_t		lun_total = 0;
	char			*buffer = NULL;
	int			buf_len = 128;
	mptsas_t		*mpt = DIP2MPT(pdip);
	uint64_t		sas_wwn;
	uint8_t			dr_flag;
	uint32_t		dev_info;

	/*
	 * This target has only just been created, need to figure out if
	 * it's possible it might have luns and if so, how many.
	 */
	sas_wwn = ptgt->m_addr.mta_wwn;
	dev_info = ptgt->m_deviceinfo;
	dr_flag = ptgt->m_dr_flag;

	NDBG12(("%d: probe_luns: target %d, dr %d", mpt->m_instance,
	    ptgt->m_devhdl, dr_flag));

	if (dr_flag == MPTSAS_DR_INTRANSITION) {
		ret = DDI_FAILURE;
		goto out;
	}

	ASSERT(ptgt->m_t_luns == NULL);

	if (sas_wwn == 0 || (dev_info & (MPI2_SAS_DEVICE_INFO_SATA_DEVICE |
	    MPI2_SAS_DEVICE_INFO_ATAPI_DEVICE |
	    MPI2_SAS_DEVICE_INFO_SEP)) != 0) {
		/*
		 * It's a SATA without Device Name (sas_wwn == 0) or
		 * it's a device type that does not do Multi-LUN.
		 * So don't try multi-LUNs.
		 */
		ret = DDI_FAILURE;
		goto out;
	}

	do {
		ap.a_target = MPTSAS_INVALID_DEVHDL;
		ap.a_lun = 0;
		ap.a_hba_tran = mpt->m_tran;
		repluns_bp = scsi_alloc_consistent_buf(&ap,
		    (struct buf *)NULL, buf_len, B_READ, NULL_FUNC, NULL);
		if (repluns_bp == NULL) {
			retry++;
			continue;
		}
		bzero(cdb, CDB_GROUP5);
		cdb[0] = SCMD_REPORT_LUNS;
		cdb[6] = (buf_len & 0xff000000) >> 24;
		cdb[7] = (buf_len & 0x00ff0000) >> 16;
		cdb[8] = (buf_len & 0x0000ff00) >> 8;
		cdb[9] = (buf_len & 0x000000ff);

		ret = mptsas_send_scsi_cmd(mpt, &ap, ptgt, &cdb[0], CDB_GROUP5,
		    repluns_bp, NULL);
		if (ret != DDI_SUCCESS) {
			scsi_free_consistent_buf(repluns_bp);
			if (ptgt->m_dr_flag == MPTSAS_DR_INTRANSITION) {
				break;
			}

			retry++;
			continue;
		}
		lun_list_len = BE_32(*(int *)((void *)(
		    repluns_bp->b_un.b_addr)));
		if (buf_len >= lun_list_len + 8) {
			ret = DDI_SUCCESS;
			break;
		}
		scsi_free_consistent_buf(repluns_bp);
		buf_len = lun_list_len + 8;

	} while (retry < 3);

	if (ret != DDI_SUCCESS)
		goto out;

	buffer = (char *)repluns_bp->b_un.b_addr;

	/*
	 * find out the number of luns returned by the SCSI ReportLun call
	 * and allocate buffer space
	 */
	lun_total = (uint16_t)(lun_list_len /
	    MPTSAS_SCSI_REPORTLUNS_ADDRESS_SIZE);
	NDBG12(("%d: probe_luns:  target %d has %d luns",
	    mpt->m_instance, ptgt->m_devhdl, lun_total));
	if (lun_total == 0) {
		ret = DDI_FAILURE;
		scsi_free_consistent_buf(repluns_bp);
		goto out;
	}
	mutex_enter(&ptgt->m_t_mutex);
	mptsas_alloc_target_luninfo(ptgt, lun_total);
	mutex_exit(&ptgt->m_t_mutex);

	for (lun_cnt = 0; lun_cnt < lun_total; lun_cnt++) {
		if (mptsas_retrieve_lundata(lun_cnt, (uint8_t *)(buffer),
		    &lun_num, &lun_addr_type) != DDI_SUCCESS) {
			ptgt->m_t_luns[lun_cnt].l_num = INVALID_LUN;
			continue;
		}
		ptgt->m_t_luns[lun_cnt].l_num = lun_num;
		ret = mptsas_probe_lunidx(mpt, lun_cnt, ptgt);
	}
	ret = DDI_SUCCESS;
	scsi_free_consistent_buf(repluns_bp);
out:
	mutex_enter(&ptgt->m_t_mutex);
	if (ret != DDI_SUCCESS) {
		mptsas_free_target_luninfo(ptgt);
	}
	mutex_exit(&ptgt->m_t_mutex);
	NDBG12(("%d: probe_luns: target %d, %d luns, ret %s",
	    mpt->m_instance, ptgt->m_devhdl, lun_total,
	    ret == DDI_SUCCESS ? "SUCCESS" : "FAIL"));
	return (ret);
}

static int
mptsas_config_luns(dev_info_t *pdip, mptsas_target_t *ptgt)
{
	int			ret = DDI_SUCCESS;
	uint32_t		lun_cnt = 0;
	uint32_t		lun_total = 0;
	dev_info_t		*cdip;
	mptsas_t		*mpt = DIP2MPT(pdip);
	uint64_t		sas_wwn;
	uint8_t			dr_flag;

	sas_wwn = ptgt->m_addr.mta_wwn;
	dr_flag = ptgt->m_dr_flag;

	NDBG12(("%d: config_luns: target %d, dr %d, %d luns",
	    mpt->m_instance, ptgt->m_devhdl, dr_flag, ptgt->m_t_nluns));

	if (dr_flag == MPTSAS_DR_INTRANSITION) {
		ret = DDI_FAILURE;
		goto out;
	}

	/*
	 * Try to configure all the luns.
	 */
	lun_total = ptgt->m_t_nluns;
	if (lun_total == 0) {
		mptsas_log(mpt, CE_WARN, "mptsas3%d: config_luns:  target %d "
		    "- NO LUNS!", mpt->m_instance, ptgt->m_devhdl);
		ret = DDI_FAILURE;
		goto out;
	}

	if (sas_wwn == 0) {
		/*
		 * It's a SATA without Device Name
		 * Must be just one LUN.
		 */
		ASSERT(lun_total == 1);
	}

	for (lun_cnt = 0; lun_cnt < lun_total; lun_cnt++) {
		if (ptgt->m_t_luns[lun_cnt].l_num == INVALID_LUN) {
			continue;
		}

		if (sas_wwn == 0) {
			cdip = mptsas_find_child_phy(pdip, ptgt->m_phynum);
		} else {
			cdip = mptsas_find_child_addr(pdip, sas_wwn,
			    ptgt->m_t_luns[lun_cnt].l_num);
		}
		if (cdip != NULL)
			ret = DDI_SUCCESS;
		else
			ret = mptsas_config_lunidx(pdip, lun_cnt, &cdip, ptgt);
		if ((ret == DDI_SUCCESS) && (cdip != NULL)) {
			(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip,
			    MPTSAS_DEV_GONE);
		}
	}
	ret = DDI_SUCCESS;
	mptsas_offline_missed_luns(pdip, lun_total, ptgt);
out:
	NDBG12(("%d: config_luns: target %d, ret %s", mpt->m_instance,
	    ptgt->m_devhdl, ret == DDI_SUCCESS?"SUCCESS":"FAIL"));
	return (ret);
}

static int
mptsas_probe_raid(dev_info_t *pdip, uint16_t target)
{
	int			rval = DDI_FAILURE;
	mptsas_t		*mpt = DIP2MPT(pdip);
	mptsas_target_t		*ptgt = NULL;

	mutex_enter(&mpt->m_mutex);
	ptgt = refhash_linear_search(mpt->m_targets,
	    mptsas_target_eval_devhdl, &target);
	mutex_exit(&mpt->m_mutex);
	if (ptgt == NULL) {
		mptsas_log(mpt, CE_WARN, "Volume with VolDevHandle of 0x%x "
		    "not found.", target);
		return (rval);
	}

	ASSERT(ptgt->m_t_luns == NULL);
	mutex_enter(&ptgt->m_t_mutex);
	mptsas_alloc_target_luninfo(ptgt, 1);
	mutex_exit(&ptgt->m_t_mutex);
	rval = mptsas_inquiry(mpt, ptgt, 0, 0,
	    (uchar_t *)&ptgt->m_t_luns[0].l_inqp0, SUN_INQSIZE, 0, (uchar_t)0);

	if (rval != DDI_SUCCESS) {
		mutex_enter(&ptgt->m_t_mutex);
		mptsas_free_target_luninfo(ptgt);
		mutex_exit(&ptgt->m_t_mutex);
	}

	return (rval);
}

static int
mptsas_config_raid(dev_info_t *pdip, uint16_t target, dev_info_t **dip)
{
	int			rval = DDI_FAILURE;
	mptsas_t		*mpt = DIP2MPT(pdip);
	mptsas_target_t		*ptgt = NULL;

	mutex_enter(&mpt->m_mutex);
	ptgt = refhash_linear_search(mpt->m_targets,
	    mptsas_target_eval_devhdl, &target);
	mutex_exit(&mpt->m_mutex);
	if (ptgt == NULL) {
		mptsas_log(mpt, CE_WARN, "Volume with VolDevHandle of 0x%x "
		    "not found.", target);
		return (rval);
	}

	if (MPTSAS_VALID_LUN(&ptgt->m_t_luns[0].l_inqp0)) {
		rval = mptsas_create_phys_lun(pdip, dip, ptgt, ptgt->m_t_luns);
	} else {
		rval = DDI_FAILURE;
	}

	return (rval);
}

/*
 * Probe and configure all RAID volumes for virtual iport
 */
static void
mptsas_probe_all_viport(dev_info_t *pdip)
{
	mptsas_t	*mpt = DIP2MPT(pdip);
	int		config, vol;
	int		target;

	/*
	 * Get latest RAID info and search for any Volume DevHandles.  If any
	 * are found, probe the volume.
	 */
	mutex_enter(&mpt->m_mutex);
	for (config = 0; config < mpt->m_num_raid_configs; config++) {
		for (vol = 0; vol < MPTSAS_MAX_RAIDVOLS; vol++) {
			if (mpt->m_raidconfig[config].m_raidvol[vol].m_israid
			    == 1) {
				target = mpt->m_raidconfig[config].
				    m_raidvol[vol].m_raidhandle;
				mutex_exit(&mpt->m_mutex);
				(void) mptsas_probe_raid(pdip, target);
				mutex_enter(&mpt->m_mutex);
			}
		}
	}
	mutex_exit(&mpt->m_mutex);
}

static void
mptsas_config_all_viport(dev_info_t *pdip)
{
	mptsas_t	*mpt = DIP2MPT(pdip);
	int		config, vol;
	int		target;
	dev_info_t	*lundip = NULL;

	/*
	 * Get latest RAID info and search for any Volume DevHandles.  If any
	 * are found, configure the volume.
	 */
	mutex_enter(&mpt->m_mutex);
	for (config = 0; config < mpt->m_num_raid_configs; config++) {
		for (vol = 0; vol < MPTSAS_MAX_RAIDVOLS; vol++) {
			if (mpt->m_raidconfig[config].m_raidvol[vol].m_israid
			    == 1) {
				target = mpt->m_raidconfig[config].
				    m_raidvol[vol].m_raidhandle;
				mutex_exit(&mpt->m_mutex);
				(void) mptsas_config_raid(pdip, target,
				    &lundip);
				mutex_enter(&mpt->m_mutex);
			}
		}
	}
	mutex_exit(&mpt->m_mutex);
}

static void
mptsas_offline_missed_luns(dev_info_t *pdip, int lun_cnt, mptsas_target_t *ptgt)
{
	dev_info_t	*child = NULL, *savechild = NULL;
	mdi_pathinfo_t	*pip = NULL, *savepip = NULL;
	uint64_t	sas_wwn, wwid;
	uint8_t		phy;
	int		lun;
	int		i;
	int		find;
	char		*addr;
	char		*nodename;
	mptsas_t	*mpt = DIP2MPT(pdip);

	mutex_enter(&mpt->m_mutex);
	wwid = ptgt->m_addr.mta_wwn;
	mutex_exit(&mpt->m_mutex);

	child = ddi_get_child(pdip);
	while (child) {
		find = 0;
		savechild = child;
		child = ddi_get_next_sibling(child);

		nodename = ddi_node_name(savechild);
		if (strcmp(nodename, "smp") == 0) {
			continue;
		}

		addr = ddi_get_name_addr(savechild);
		if (addr == NULL) {
			continue;
		}

		if (mptsas_parse_address(addr, &sas_wwn, &phy, &lun) !=
		    DDI_SUCCESS) {
			continue;
		}

		if (wwid == sas_wwn) {
			for (i = 0; i < lun_cnt; i++) {
				if (ptgt->m_t_luns[i].l_num == lun) {
					find = 1;
					break;
				}
			}
		} else {
			continue;
		}
		if (find == 0) {
			/*
			 * The lun has not been there already
			 */
			(void) mptsas_offline_lun(pdip, savechild, NULL,
			    NDI_DEVI_REMOVE);
		}
	}

	pip = mdi_get_next_client_path(pdip, NULL);
	while (pip) {
		find = 0;
		savepip = pip;
		addr = MDI_PI(pip)->pi_addr;

		pip = mdi_get_next_client_path(pdip, pip);

		if (addr == NULL) {
			continue;
		}

		if (mptsas_parse_address(addr, &sas_wwn, &phy,
		    &lun) != DDI_SUCCESS) {
			continue;
		}

		if (sas_wwn == wwid) {
			for (i = 0; i < lun_cnt; i++) {
				if (ptgt->m_t_luns[i].l_num == lun) {
					find = 1;
					break;
				}
			}
		} else {
			continue;
		}

		if (find == 0) {
			/*
			 * The lun has not been there already
			 */
			(void) mptsas_offline_lun(pdip, NULL, savepip,
			    NDI_DEVI_REMOVE);
		}
	}
}

static void
mptsas_update_hashtab(struct mptsas *mpt)
{
	uint32_t	page_address;
	int		rval = 0;
	uint16_t	dev_handle;
	mptsas_target_t	*ptgt = NULL;
	mptsas_smp_t	smp_node;

	/*
	 * Get latest RAID info.
	 */
	(void) mptsas_get_raid_info(mpt);

	dev_handle = mpt->m_smp_devhdl;
	for (; mpt->m_done_traverse_smp == 0; ) {
		page_address = (MPI2_SAS_EXPAND_PGAD_FORM_GET_NEXT_HNDL &
		    MPI2_SAS_EXPAND_PGAD_FORM_MASK) | (uint32_t)dev_handle;
		if (mptsas_get_sas_expander_page0(mpt, page_address, &smp_node)
		    != DDI_SUCCESS) {
			break;
		}
		mpt->m_smp_devhdl = dev_handle = smp_node.m_devhdl;
		(void) mptsas_smp_alloc(mpt, &smp_node);
	}

	/*
	 * Config target devices
	 */
	dev_handle = mpt->m_dev_handle;

	/*
	 * Do loop to get sas device page 0 by GetNextHandle till the
	 * the last handle. If the sas device is a SATA/SSP target,
	 * we try to config it.
	 */
	for (; mpt->m_done_traverse_dev == 0; ) {
		ptgt = NULL;
		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_GET_NEXT_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) | (uint32_t)dev_handle;
		rval = mptsas_get_target_device_info(mpt, page_address,
		    &dev_handle, &ptgt);
		if (rval == DEV_INFO_FAIL_PAGE0) {
			break;
		}
		if (rval == DEV_INFO_SUCCESS) {
			mutex_exit(&ptgt->m_t_mutex);
		}

		mpt->m_dev_handle = dev_handle;
	}

}

static void
mptsas_update_driver_data(struct mptsas *mpt)
{
	mptsas_target_t *tp;
	mptsas_smp_t *sp;

	ASSERT(MUTEX_HELD(&mpt->m_mutex));

	/*
	 * TODO after hard reset, update the driver data structures
	 * 1. update port/phymask mapping table mpt->m_phy_info
	 * 2. invalid all the entries in hash table
	 *    m_devhdl = 0xffff and m_deviceinfo = 0
	 * 3. call sas_device_page/expander_page to update hash table
	 */
	mptsas_update_phymask(mpt);

	/*
	 * Invalidate the existing entries. A reset may have caused the
	 * handles to change. During an ongoing reset commands are still
	 * allowed to queue to the target waitq.
	 */
	NDBG28(("%d: mptsas_update_driver_data: set all dr_flags to "
	    "inactive.", mpt->m_instance));
	for (tp = refhash_first(mpt->m_targets); tp != NULL;
	    tp = refhash_next(mpt->m_targets, tp)) {
		mutex_enter(&tp->m_t_mutex);
		mptsas_free_target_luninfo(tp);
		if (tp->m_devhdl != MPTSAS_INVALID_DEVHDL)
			tp->m_shdwhdl = tp->m_devhdl;
		tp->m_devhdl = MPTSAS_INVALID_DEVHDL;
		tp->m_deviceinfo = 0;
		tp->m_dr_flag = MPTSAS_DR_INACTIVE;
		tp->m_reset_delay = 0;
#ifdef AUTO_OFFLINE_TARGETS
		tp->m_timeout_ncmd = 0;
#endif
		/*
		 * This ASSERT() should be true because we are only called
		 * at initialization or after an IOC reset without letting
		 * go of the m_mutex.
		 */
		ASSERT(tp->m_t_init < TINIT_CFGBUSY);
		tp->m_t_init = TINIT_UPDATE;
		mutex_exit(&tp->m_t_mutex);
	}
	for (sp = refhash_first(mpt->m_smp_targets); sp != NULL;
	    sp = refhash_next(mpt->m_smp_targets, sp)) {
		sp->m_devhdl = MPTSAS_INVALID_DEVHDL;
		sp->m_deviceinfo = 0;
	}
	mpt->m_done_traverse_dev = 0;
	mpt->m_done_traverse_smp = 0;
	mpt->m_dev_handle = mpt->m_smp_devhdl = MPTSAS_INVALID_DEVHDL;
	mptsas_update_hashtab(mpt);
}

static void
mptsas_probe_all(dev_info_t *pdip)
{
	mptsas_t	*mpt = DIP2MPT(pdip);
	int		phymask_prop = 0, rval;
	mptsas_phymask_t phy_mask;
	mptsas_target_t	*ptgt = NULL;

	/*
	 * Get the phymask associated to the iport
	 */
	phymask_prop = ddi_prop_get_int(DDI_DEV_T_ANY, pdip, 0, "phymask", 0);

	/*
	 * Enumerate RAID volumes here (phymask_prop == 0).
	 */
	if (phymask_prop == 0) {
		mptsas_probe_all_viport(pdip);
		return;
	}

	mutex_enter(&mpt->m_mutex);

	if (!mpt->m_done_traverse_dev || !mpt->m_done_traverse_smp) {
		mptsas_update_hashtab(mpt);
	}

	/*
	 * Loop looking for all relevant targets and set the state to
	 * probe all. This will serialize config requests to the specific
	 * targets.
	 * Once through mptsas_config_wait() we cannot lose the target from
	 * the refhash list, it's safe to keep the reference to it without
	 * either mutex.
	 * Have to guard against this because we can get an offline target
	 * event at any point, these states block the final processing that
	 * can free the mptsas_target_t structure.
	 */
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		phy_mask = ptgt->m_addr.mta_phymask;
		if (phy_mask == phymask_prop) {
			mutex_enter(&ptgt->m_t_mutex);
			if (ptgt->m_devhdl == MPTSAS_INVALID_DEVHDL) {
				mutex_exit(&ptgt->m_t_mutex);
				continue;
			}
			mptsas_config_wait(mpt, ptgt, TINIT_PROBEALL);
			mutex_exit(&ptgt->m_t_mutex);
			mutex_exit(&mpt->m_mutex);
			rval = mptsas_probe_target(pdip, ptgt);
			mutex_enter(&mpt->m_mutex);
			/*
			 * If we fail probe_target should reset state.
			 */
			if (rval != DDI_SUCCESS) {
				mutex_enter(&ptgt->m_t_mutex);
				ASSERT(ptgt->m_t_init == TINIT_PROBEALL);
				mptsas_clr_tgtcl(mpt, ptgt);
				mutex_exit(&ptgt->m_t_mutex);
			}
		}
	}
	mutex_exit(&mpt->m_mutex);
}

static void
mptsas_config_all(dev_info_t *pdip)
{
	dev_info_t	*smpdip = NULL;
	mptsas_t	*mpt = DIP2MPT(pdip);
	int		phymask_prop = 0;
	mptsas_phymask_t phy_mask;
	mptsas_target_t	*ptgt = NULL;
	mptsas_smp_t	*psmp;

	/*
	 * Get the phymask associated to the iport
	 */
	phymask_prop = ddi_prop_get_int(DDI_DEV_T_ANY, pdip, 0, "phymask", 0);

	/*
	 * Enumerate RAID volumes here (phymask == 0).
	 */
	if (phymask_prop == 0) {
		mptsas_config_all_viport(pdip);
		return;
	}

	mutex_enter(&mpt->m_mutex);

	for (psmp = refhash_first(mpt->m_smp_targets); psmp != NULL;
	    psmp = refhash_next(mpt->m_smp_targets, psmp)) {
		phy_mask = psmp->m_addr.mta_phymask;
		if (phy_mask == phymask_prop) {
			smpdip = NULL;
			mutex_exit(&mpt->m_mutex);
			(void) mptsas_online_smp(pdip, psmp, &smpdip);
			mutex_enter(&mpt->m_mutex);
		}
	}

	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		phy_mask = ptgt->m_addr.mta_phymask;
		if (phy_mask == phymask_prop) {
			mutex_enter(&ptgt->m_t_mutex);
			if (ptgt->m_t_init != TINIT_PROBEALL) {
				mutex_exit(&ptgt->m_t_mutex);
			} else {
				ptgt->m_t_init = TINIT_CONFALL;
				mutex_exit(&ptgt->m_t_mutex);
				mutex_exit(&mpt->m_mutex);
				(void) mptsas_config_target(pdip, ptgt);
				mutex_enter(&mpt->m_mutex);
			}
		}
	}

	/*
	 * Finally reset state for all the targets we tried to configure.
	 */
	for (ptgt = refhash_first(mpt->m_targets); ptgt != NULL;
	    ptgt = refhash_next(mpt->m_targets, ptgt)) {
		phy_mask = ptgt->m_addr.mta_phymask;
		if (phy_mask == phymask_prop) {
			mutex_enter(&ptgt->m_t_mutex);
			if (ptgt->m_t_init == TINIT_CONFALL) {
				mptsas_clr_tgtcl(mpt, ptgt);
			}
			mutex_exit(&ptgt->m_t_mutex);
		}
	}
	mutex_exit(&mpt->m_mutex);
}

/*
 * Fetch all information required by config_target().
 * Called prior to taking the ndi locks that are needed for config
 * so that we don't need to issue inquiry commands while we have those
 * locks. If probe information is valid then m_t_luns will point to
 * the structures containing the information and we don't need to re-issue
 * those inquiry commands.
 * This effectively initiates a state machine based on the m_t_init
 * target variable (See mptsas3_var.h).
 */
static int
mptsas_probe_target(dev_info_t *pdip, mptsas_target_t *ptgt)
{
	int	rval = DDI_FAILURE;

	NDBG12(("%d: probe_target: target %d, dr %d",
	    ddi_get_instance(pdip), ptgt->m_devhdl, ptgt->m_dr_flag));

	ASSERT(ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL);

	/*
	 * If there is an offline event pending fail this probe.
	 */
	if (ptgt->m_cnfg_luns & TFGL_OFFLINE ||
	    ptgt->m_pcfail > mptsas_max_pcfail)
		return (DDI_FAILURE);

	if (ptgt->m_t_luns != NULL)
		return (DDI_SUCCESS);

#ifdef MPTSAS_TEST
	if (mptsas_test_fail_probe & (1<<DIP2MPT(pdip)->m_instance) &&
	    ptgt->m_devhdl == (uint16_t)(mptsas_test_fail_probe>>16)) {
		mutex_enter(&ptgt->m_t_mutex);
		goto failed_probe;
	}
#endif
	rval = mptsas_probe_luns(pdip, ptgt);
	if (rval != DDI_SUCCESS) {
		/*
		 * The return value means the SCMD_REPORT_LUNS did not execute
		 * successfully. The target maybe doesn't support such a
		 * command.
		 * _probe_luns() will also de-allocate any lun structures if
		 * it fails. We are effectively going to probe just lun zero in
		 * a different way so allocate a single structure for that.
		 */
		mutex_enter(&ptgt->m_t_mutex);
		mptsas_alloc_target_luninfo(ptgt, 1);
		mutex_exit(&ptgt->m_t_mutex);
		rval = mptsas_probe_lunidx(DIP2MPT(pdip), 0, ptgt);
		if (rval != DDI_SUCCESS) {
			mutex_enter(&ptgt->m_t_mutex);
			mptsas_free_target_luninfo(ptgt);
#ifdef MPTSAS_TEST
		failed_probe:
#endif
			ASSERT(ptgt->m_cnfg_luns & TFGL_ACTIVE);
			ptgt->m_cnfg_luns |= TFGL_PFAIL;
			if (++(ptgt->m_pcfail) > mptsas_max_pcfail) {
				ptgt->m_cnfg_luns |= TFGL_OFFLINE;
			}
			NDBG12(("%d: probe_target: FAILED, target %d%s",
			    ddi_get_instance(pdip), ptgt->m_devhdl,
			    ptgt->m_cnfg_luns & TFGL_OFFLINE ?
			    " try to offline" : ""));
			mutex_exit(&ptgt->m_t_mutex);
		}
	}
	return (rval);
}

static int
mptsas_config_target(dev_info_t *pdip, mptsas_target_t *ptgt)
{
	int		rval = DDI_FAILURE;

	/*
	 * There is no point trying to configure luns on a target that
	 * does not have a handle. Can certainly get this when looping all
	 * targets, not sure if it's possible in other circumstances.
	 */
	if (ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL) {
		rval = mptsas_config_luns(pdip, ptgt);
	}
	return (rval);
}

/*
 * Return fail if not all the childs/paths are freed.
 * if there is any path under the HBA, the return value will be always fail
 * because we didn't call mdi_pi_free for path
 */
static int
mptsas_offline_targetdev(dev_info_t *pdip, char *name)
{
	dev_info_t		*child = NULL, *prechild = NULL;
	mdi_pathinfo_t		*pip = NULL, *savepip = NULL;
	int			tmp_rval, rval = DDI_SUCCESS;
	char			*addr, *cp;
	size_t			s;
	mptsas_t		*mpt = DIP2MPT(pdip);

	child = ddi_get_child(pdip);
	while (child) {
		addr = ddi_get_name_addr(child);
		prechild = child;
		child = ddi_get_next_sibling(child);

		if (addr == NULL) {
			continue;
		}
		if ((cp = strchr(addr, ',')) == NULL) {
			continue;
		}

		s = (uintptr_t)cp - (uintptr_t)addr;

		if (strncmp(addr, name, s) != 0) {
			continue;
		}

		tmp_rval = mptsas_offline_lun(pdip, prechild, NULL,
		    NDI_DEVI_REMOVE);
		if (tmp_rval != DDI_SUCCESS) {
			rval = DDI_FAILURE;
			if (ndi_prop_create_boolean(DDI_DEV_T_NONE,
			    prechild, MPTSAS_DEV_GONE) !=
			    DDI_PROP_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "unable to create property for "
				    "SAS %s (MPTSAS_DEV_GONE)", addr);
			}
		}
	}

	pip = mdi_get_next_client_path(pdip, NULL);
	while (pip) {
		addr = MDI_PI(pip)->pi_addr;
		savepip = pip;
		pip = mdi_get_next_client_path(pdip, pip);
		if (addr == NULL) {
			continue;
		}

		if ((cp = strchr(addr, ',')) == NULL) {
			continue;
		}

		s = (uintptr_t)cp - (uintptr_t)addr;

		if (strncmp(addr, name, s) != 0) {
			continue;
		}

		(void) mptsas_offline_lun(pdip, NULL, savepip,
		    NDI_DEVI_REMOVE);
		/*
		 * driver will not invoke mdi_pi_free, so path will not
		 * be freed forever, return DDI_FAILURE.
		 */
		rval = DDI_FAILURE;
	}
	return (rval);
}

static int
mptsas_offline_lun(dev_info_t *pdip, dev_info_t *rdip,
    mdi_pathinfo_t *rpip, uint_t flags)
{
	int		rval = DDI_FAILURE;
	char		*devname;
	dev_info_t	*cdip, *parent;

	if (rpip != NULL) {
		parent = scsi_vhci_dip;
		cdip = mdi_pi_get_client(rpip);
	} else if (rdip != NULL) {
		parent = pdip;
		cdip = rdip;
	} else {
		return (DDI_FAILURE);
	}

	/*
	 * Make sure node is attached otherwise
	 * it won't have related cache nodes to
	 * clean up.  i_ddi_devi_attached is
	 * similiar to i_ddi_node_state(cdip) >=
	 * DS_ATTACHED.
	 */
	if (i_ddi_devi_attached(cdip)) {

		/* Get full devname */
		devname = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
		(void) ddi_deviname(cdip, devname);
		/* Clean cache */
		(void) devfs_clean(parent, devname + 1,
		    DV_CLEAN_FORCE);
		kmem_free(devname, MAXNAMELEN + 1);
	}
	if (rpip != NULL) {
		if (MDI_PI_IS_OFFLINE(rpip)) {
			rval = DDI_SUCCESS;
		} else {
			rval = mdi_pi_offline(rpip, 0);
		}
	} else {
		rval = ndi_devi_offline(cdip, flags);
	}

	return (rval);
}

static dev_info_t *
mptsas_find_smp_child(dev_info_t *parent, char *str_wwn)
{
	dev_info_t	*child = NULL;
	char		*smp_wwn = NULL;

	child = ddi_get_child(parent);
	while (child) {
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, SMP_WWN, &smp_wwn)
		    != DDI_SUCCESS) {
			child = ddi_get_next_sibling(child);
			continue;
		}

		if (strcmp(smp_wwn, str_wwn) == 0) {
			ddi_prop_free(smp_wwn);
			break;
		}
		child = ddi_get_next_sibling(child);
		ddi_prop_free(smp_wwn);
	}
	return (child);
}

static int
mptsas_offline_smp(dev_info_t *pdip, mptsas_smp_t *smp_node, uint_t flags)
{
	int		rval = DDI_FAILURE;
	char		*devname;
	char		wwn_str[MPTSAS_WWN_STRLEN];
	dev_info_t	*cdip;

	(void) sprintf(wwn_str, "%"PRIx64, smp_node->m_addr.mta_wwn);

	cdip = mptsas_find_smp_child(pdip, wwn_str);

	if (cdip == NULL)
		return (DDI_SUCCESS);

	/*
	 * Make sure node is attached otherwise
	 * it won't have related cache nodes to
	 * clean up.  i_ddi_devi_attached is
	 * similiar to i_ddi_node_state(cdip) >=
	 * DS_ATTACHED.
	 */
	if (i_ddi_devi_attached(cdip)) {

		/* Get full devname */
		devname = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
		(void) ddi_deviname(cdip, devname);
		/* Clean cache */
		(void) devfs_clean(pdip, devname + 1,
		    DV_CLEAN_FORCE);
		kmem_free(devname, MAXNAMELEN + 1);
	}

	rval = ndi_devi_offline(cdip, flags);

	return (rval);
}

static dev_info_t *
mptsas_find_child(dev_info_t *pdip, char *name)
{
	dev_info_t	*child = NULL;
	char		*rname = NULL;
	int		rval = DDI_FAILURE;

	rname = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);

	child = ddi_get_child(pdip);
	while (child) {
		rval = mptsas_name_child(child, rname, SCSI_MAXNAMELEN);
		if (rval != DDI_SUCCESS) {
			child = ddi_get_next_sibling(child);
			bzero(rname, SCSI_MAXNAMELEN);
			continue;
		}

		if (strcmp(rname, name) == 0) {
			break;
		}
		child = ddi_get_next_sibling(child);
		bzero(rname, SCSI_MAXNAMELEN);
	}

	kmem_free(rname, SCSI_MAXNAMELEN);

	return (child);
}


static dev_info_t *
mptsas_find_child_addr(dev_info_t *pdip, uint64_t sasaddr, int lun)
{
	dev_info_t	*child = NULL;
	char		*name = NULL;
	char		*addr = NULL;

	name = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	addr = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	(void) sprintf(name, "%016"PRIx64, sasaddr);
	(void) sprintf(addr, "w%s,%x", name, lun);
	child = mptsas_find_child(pdip, addr);
	kmem_free(name, SCSI_MAXNAMELEN);
	kmem_free(addr, SCSI_MAXNAMELEN);
	return (child);
}

static dev_info_t *
mptsas_find_child_phy(dev_info_t *pdip, uint8_t phy)
{
	dev_info_t	*child;
	char		*addr;

	addr = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	(void) sprintf(addr, "p%x,0", phy);
	child = mptsas_find_child(pdip, addr);
	kmem_free(addr, SCSI_MAXNAMELEN);
	return (child);
}

static mdi_pathinfo_t *
mptsas_find_path_phy(dev_info_t *pdip, uint8_t phy)
{
	mdi_pathinfo_t	*path;
	char		*addr = NULL;

	addr = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	(void) sprintf(addr, "p%x,0", phy);
	path = mdi_pi_find(pdip, NULL, addr);
	kmem_free(addr, SCSI_MAXNAMELEN);
	return (path);
}

static mdi_pathinfo_t *
mptsas_find_path_addr(dev_info_t *parent, uint64_t sasaddr, uint16_t lun)
{
	mdi_pathinfo_t	*path;
	char		*name = NULL;
	char		*addr = NULL;

	name = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	addr = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	(void) sprintf(name, "%016"PRIx64, sasaddr);
	(void) sprintf(addr, "w%s,%x", name, lun);
	path = mdi_pi_find(parent, NULL, addr);
	kmem_free(name, SCSI_MAXNAMELEN);
	kmem_free(addr, SCSI_MAXNAMELEN);

	return (path);
}

static int
mptsas_create_lun(dev_info_t *pdip, dev_info_t **lun_dip, mptsas_target_t *ptgt,
    mptsas_lun_t *plun)
{
	int			rval = DDI_FAILURE;
	mdi_pathinfo_t		*pip = NULL;
	mptsas_t		*mpt = DIP2MPT(pdip);

	if ((plun->l_guid != NULL) && (mpt->m_mpxio_enable == TRUE)) {
		rval = mptsas_create_virt_lun(pdip, lun_dip, &pip, ptgt, plun);
	}

	/*
	 * If pip is not NULL _create_virt_lun() found a pre-existing path
	 * that corresponds to this lun but failed to online it. This is the
	 * only case we do not try to create a physical lun.
	 */
	if (rval != DDI_SUCCESS && pip == NULL) {
		rval = mptsas_create_phys_lun(pdip, lun_dip, ptgt, plun);

	}
	if (rval != DDI_SUCCESS) {
		mutex_enter(&ptgt->m_t_mutex);
		ASSERT(ptgt->m_cnfg_luns & TFGL_ACTIVE);
		ptgt->m_cnfg_luns |= TFGL_CFAIL;
		if (++(ptgt->m_pcfail) > mptsas_max_pcfail) {
			ptgt->m_cnfg_luns |= TFGL_OFFLINE;
		}
		NDBG12(("%d: create_lun: FAILED, target,lun %d,%d%s",
			ddi_get_instance(pdip), ptgt->m_devhdl, plun->l_num,
			ptgt->m_cnfg_luns & TFGL_OFFLINE ? " try to offline": ""));
		mutex_exit(&ptgt->m_t_mutex);
	}
	return (rval);
}

static int
mptsas_create_virt_lun(dev_info_t *pdip, dev_info_t **lun_dip,
    mdi_pathinfo_t **pip, mptsas_target_t *ptgt, mptsas_lun_t *plun)
{
	int			target;
	char			*nodename = NULL, *guid;
	struct scsi_inquiry	*inq;
	char			**compatible = NULL;
	int			ncompatible = 0;
	int			mdi_rtn = MDI_FAILURE;
	int			rval = DDI_FAILURE;
	char			*old_guid = NULL;
	mptsas_t		*mpt = DIP2MPT(pdip);
	char			*lun_addr = NULL;
	char			wwn_str[MPTSAS_WWN_STRLEN];
	char			*component = NULL;
	uint8_t			phy = 0xFF;
	uint64_t		sas_wwn;
	char			ses_sa_str[MPTSAS_WWN_STRLEN];
	int64_t			lun64 = 0;
	uint32_t		devinfo;
	uint16_t		dev_hdl;
	uint16_t		pdev_hdl;
	uint64_t		dev_sas_wwn;
	uint64_t		pdev_sas_wwn;
	uint32_t		pdev_info;
	uint8_t			physport;
	uint8_t			phy_id;
	uint32_t		page_address;
	uint16_t		bay_num, enclosure, io_flags, lun;
	char			pdev_wwn_str[MPTSAS_WWN_STRLEN];
	uint32_t		dev_info;

	mutex_enter(&mpt->m_mutex);
	target = ptgt->m_devhdl;
	sas_wwn = ptgt->m_addr.mta_wwn;
	devinfo = ptgt->m_deviceinfo;
	phy = ptgt->m_phynum;
	inq = &plun->l_inqp0;
	guid = plun->l_guid;
	lun = plun->l_num;
	mutex_exit(&mpt->m_mutex);

	if (sas_wwn) {
		*pip = mptsas_find_path_addr(pdip, sas_wwn, lun);
	} else {
		*pip = mptsas_find_path_phy(pdip, phy);
	}

	(void) sprintf(ses_sa_str, "%016"PRIx64, ptgt->m_addr.mta_wwn);

	if (*pip != NULL) {
		*lun_dip = MDI_PI(*pip)->pi_client->ct_dip;
		ASSERT(*lun_dip != NULL);
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, *lun_dip,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    MDI_CLIENT_GUID_PROP, &old_guid) == DDI_SUCCESS) {
			if (strncmp(guid, old_guid, strlen(guid)) == 0) {
				/*
				 * Same path back online again.
				 */
				(void) ddi_prop_free(old_guid);
				if ((!MDI_PI_IS_ONLINE(*pip)) &&
				    (!MDI_PI_IS_STANDBY(*pip)) &&
				    (ptgt->m_tgt_unconfigured == 0)) {
					NDBG20(("%d: onlining old "
					    "vlun path:%s", mpt->m_instance,
					    MDI_PI(*pip)->pi_addr));
					rval = mdi_pi_online(*pip, 0);
					if (rval != MDI_SUCCESS) {
						mptsas_log(mpt, CE_WARN,
						    "vlun mdi_pi_online:failed "
						    "targ %d, lun:%d!", target,
						    lun);
					}
					mutex_enter(&mpt->m_mutex);
					ptgt->m_led_status = 0;
					(void) mptsas_flush_led_status(mpt,
					    ptgt);
					mutex_exit(&mpt->m_mutex);
				} else {
					/*
					 * Update ses info.
					 */
					if (mdi_prop_update_string(*pip,
					    SCSI_ADDR_PROP_SES_SA,
					    ses_sa_str) != DDI_PROP_SUCCESS) {
						mptsas_log(mpt, CE_WARN,
						    "mptsas3%d: unable "
						    "to create prop for target"
						    " %d lun %d (target-port)",
						    mpt->m_instance, target,
						    lun);
						rval = DDI_FAILURE;
					} else {
						rval = DDI_SUCCESS;
					}
				}
				if (rval != DDI_SUCCESS) {
					mptsas_log(mpt, CE_WARN, "path:target: "
					    "%d, lun:%x online failed!", target,
					    lun);
					/*
					 * We found an existing path but
					 * something else went wrong. Indicate
					 * this by not clearing the pip pointer.
					 * *pip = NULL;
					 */
					*lun_dip = NULL;
				}
				return (rval);
			} else {
				/*
				 * The GUID of the LUN has changed which maybe
				 * because customer mapped another volume to the
				 * same LUN.
				 */
				mptsas_log(mpt, CE_WARN, "The GUID of the "
				    "target:%d, lun:%d was changed, maybe "
				    "because someone mapped another volume "
				    "to the same LUN", target, lun);
				(void) ddi_prop_free(old_guid);
				if (!MDI_PI_IS_OFFLINE(*pip)) {
					rval = mdi_pi_offline(*pip, 0);
					if (rval != MDI_SUCCESS) {
						mptsas_log(mpt, CE_WARN, "path:"
						    "target:%d, lun:%d offline "
						    "failed!", target, lun);
						*lun_dip = NULL;
						return (DDI_FAILURE);
					}
				}
				if (mdi_pi_free(*pip, 0) != MDI_SUCCESS) {
					mptsas_log(mpt, CE_WARN, "path:target:"
					    "%d, lun:%x free failed!", target,
					    lun);
					*lun_dip = NULL;
					return (DDI_FAILURE);
				}
			}
		} else {
			mptsas_log(mpt, CE_WARN, "Can't get client-guid "
			    "property for path:target:%d, lun:%d", target, lun);
			*lun_dip = NULL;
			return (DDI_FAILURE);
		}
	}
	scsi_hba_nodename_compatible_get(inq, NULL,
	    inq->inq_dtype, NULL, &nodename, &compatible, &ncompatible);

	/*
	 * if nodename can't be determined then print a message and skip it
	 */
	if (nodename == NULL) {
		mptsas_log(mpt, CE_WARN, "found no compatible "
		    "driver for target %d lun %d dtype:0x%02x", target, lun,
		    inq->inq_dtype);
		return (DDI_FAILURE);
	}

	/* The property is needed by MPAPI */
	(void) sprintf(wwn_str, "%016"PRIx64, sas_wwn);

	lun_addr = kmem_zalloc(SCSI_MAXNAMELEN, KM_SLEEP);
	if (guid) {
		(void) sprintf(lun_addr, "w%s,%x", wwn_str, lun);
		(void) sprintf(wwn_str, "w%016"PRIx64, sas_wwn);
	} else {
		(void) sprintf(lun_addr, "p%x,%x", phy, lun);
		(void) sprintf(wwn_str, "p%x", phy);
	}

	mdi_rtn = mdi_pi_alloc_compatible(pdip, nodename, guid, lun_addr,
	    compatible, ncompatible, 0, pip);

	if (mdi_rtn != MDI_SUCCESS) {
		mptsas_log(mpt, CE_WARN, "mdi_pi_alloc_compatible() failed "
		    "driver for target %d lun %d dtype:0x%02x", target, lun,
		    inq->inq_dtype);
	}
	if (mdi_rtn == MDI_SUCCESS) {

		if (mdi_prop_update_string(*pip, MDI_GUID,
		    guid) != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "unable to "
			    "create prop for target %d lun %d (MDI_GUID)",
			    target, lun);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		if (mdi_prop_update_int(*pip, LUN_PROP,
		    lun) != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "unable to "
			    "create prop for target %d lun %d (LUN_PROP)",
			    target, lun);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}
		lun64 = (int64_t)lun;
		if (mdi_prop_update_int64(*pip, LUN64_PROP,
		    lun64) != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "unable to "
			    "create prop for target %d (LUN64_PROP)",
			    target);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}
		if (mdi_prop_update_string_array(*pip, "compatible",
		    compatible, ncompatible) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "unable to "
			    "create prop for target %d lun %d (COMPATIBLE)",
			    target, lun);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		if (mdi_prop_update_string(*pip,
		    SCSI_ADDR_PROP_SES_SA, ses_sa_str) != DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas3%d: unable to "
			    "create prop for target %d lun %d "
			    "(target-port)", mpt->m_instance, target, lun);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		if (sas_wwn && (mdi_prop_update_string(*pip,
		    SCSI_ADDR_PROP_TARGET_PORT, wwn_str) != DDI_PROP_SUCCESS)) {
			mptsas_log(mpt, CE_WARN, "unable to "
			    "create prop for target %d lun %d "
			    "(target-port)", target, lun);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		} else if ((sas_wwn == 0) && (mdi_prop_update_int(*pip,
		    "sata-phy", phy) != DDI_PROP_SUCCESS)) {
			/*
			 * Direct attached SATA device without DeviceName
			 */
			mptsas_log(mpt, CE_WARN, "unable to "
			    "create prop for SAS target %d lun %d "
			    "(sata-phy)", target, lun);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}
		mutex_enter(&mpt->m_mutex);

		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) |
		    (uint32_t)ptgt->m_devhdl;
		rval = mptsas_get_sas_device_page0(mpt, page_address,
		    &dev_hdl, &dev_sas_wwn, &dev_info, &physport,
		    &phy_id, &pdev_hdl, &bay_num, &enclosure, &io_flags);
		if (rval != DDI_SUCCESS) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "mptsas unable to get "
			    "parent device for handle %d", page_address);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) | (uint32_t)pdev_hdl;
		rval = mptsas_get_sas_device_page0(mpt, page_address,
		    &dev_hdl, &pdev_sas_wwn, &pdev_info, &physport,
		    &phy_id, &pdev_hdl, &bay_num, &enclosure, &io_flags);
		if (rval != DDI_SUCCESS) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "mptsas unable to get"
			    "device info for handle %d", page_address);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}

		mutex_exit(&mpt->m_mutex);

		/*
		 * If this device direct attached to the controller
		 * set the attached-port to the base wwid
		 */
		if ((ptgt->m_deviceinfo & DEVINFO_DIRECT_ATTACHED)
		    != DEVINFO_DIRECT_ATTACHED) {
			(void) sprintf(pdev_wwn_str, "w%016"PRIx64,
			    pdev_sas_wwn);
		} else {
			/*
			 * Update the iport's attached-port to guid
			 */
			if (sas_wwn == 0) {
				(void) sprintf(wwn_str, "p%x", phy);
			} else {
				(void) sprintf(wwn_str, "w%016"PRIx64, sas_wwn);
			}
			if (ddi_prop_update_string(DDI_DEV_T_NONE,
			    pdip, SCSI_ADDR_PROP_ATTACHED_PORT, wwn_str) !=
			    DDI_PROP_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "mptsas unable to create "
				    "property for iport target-port"
				    " %s (sas_wwn)",
				    wwn_str);
				mdi_rtn = MDI_FAILURE;
				goto virt_create_done;
			}

			(void) sprintf(pdev_wwn_str, "w%016"PRIx64,
			    mpt->un.m_base_wwid);
		}

		if (mdi_prop_update_string(*pip,
		    SCSI_ADDR_PROP_ATTACHED_PORT, pdev_wwn_str) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "unable to create "
			    "property for iport attached-port %s (sas_wwn)",
			    pdev_wwn_str);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}


		if (inq->inq_dtype == 0) {
			component = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
			/*
			 * set obp path for pathinfo
			 */
			(void) snprintf(component, MAXPATHLEN,
			    "disk@%s", lun_addr);

			if (mdi_pi_pathname_obp_set(*pip, component) !=
			    DDI_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "unable to set obp-path for object %s",
				    component);
				mdi_rtn = MDI_FAILURE;
				goto virt_create_done;
			}
		}

		*lun_dip = MDI_PI(*pip)->pi_client->ct_dip;
		if (devinfo & (MPI2_SAS_DEVICE_INFO_SATA_DEVICE |
		    MPI2_SAS_DEVICE_INFO_ATAPI_DEVICE)) {
			if ((ndi_prop_update_int(DDI_DEV_T_NONE, *lun_dip,
			    "pm-capable", 1)) !=
			    DDI_PROP_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "failed to create pm-capable "
				    "property, target %d", target);
				mdi_rtn = MDI_FAILURE;
				goto virt_create_done;
			}
		}
		/*
		 * Create the phy-num property
		 */
		if (mdi_prop_update_int(*pip, "phy-num",
		    ptgt->m_phynum) != DDI_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "unable to "
			    "create phy-num property for target %d lun %d",
			    target, lun);
			mdi_rtn = MDI_FAILURE;
			goto virt_create_done;
		}
		NDBG20(("%d: onlining new vlun path:%s", mpt->m_instance,
		    MDI_PI(*pip)->pi_addr));
		mdi_rtn = mdi_pi_online(*pip, 0);
		if (mdi_rtn == MDI_SUCCESS) {
			mutex_enter(&mpt->m_mutex);
			ptgt->m_led_status = 0;
			(void) mptsas_flush_led_status(mpt, ptgt);
			mutex_exit(&mpt->m_mutex);
		} else {
			NDBG20(("%d: failed to online new vlun path:%s, "
			    "ecode %d", mpt->m_instance, MDI_PI(*pip)->pi_addr,
			    mdi_rtn));
		}
		if (mdi_rtn == MDI_NOT_SUPPORTED) {
			mdi_rtn = MDI_FAILURE;
			(void) mdi_pi_free(*pip, 0);
			/*
			 * Specific error code indicating this drive is not
			 * supported by vhci. Clear *pip to allow
			 * mptsas_create_lun() to attempt to create a physical
			 * lun.
			 */
			*pip = NULL;
			*lun_dip = NULL;
		}
virt_create_done:
		if (*pip && mdi_rtn != MDI_SUCCESS) {
			(void) mdi_pi_free(*pip, 0);
			*lun_dip = NULL;
		}
	}

	scsi_hba_nodename_compatible_free(nodename, compatible);
	if (lun_addr != NULL) {
		kmem_free(lun_addr, SCSI_MAXNAMELEN);
	}
	if (component != NULL) {
		kmem_free(component, MAXPATHLEN);
	}

	return ((mdi_rtn == MDI_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

static int
mptsas_create_phys_lun(dev_info_t *pdip, dev_info_t **lun_dip,
    mptsas_target_t *ptgt, mptsas_lun_t *plun)
{
	int			target;
	int			rval;
	int			ndi_rtn = NDI_FAILURE;
	uint64_t		be_sas_wwn;
	char			*nodename = NULL, *guid;
	char			**compatible = NULL;
	struct scsi_inquiry	*inq;
	int			ncompatible = 0;
	int			instance = 0;
	mptsas_t		*mpt = DIP2MPT(pdip);
	char			wwn_str[MPTSAS_WWN_STRLEN];
	char			ses_sa_str[MPTSAS_WWN_STRLEN];
	char			component[MAXPATHLEN];
	uint8_t			phy = 0xFF;
	uint64_t		sas_wwn;
	uint32_t		devinfo;
	uint16_t		dev_hdl;
	uint16_t		pdev_hdl;
	uint64_t		pdev_sas_wwn;
	uint64_t		dev_sas_wwn;
	uint32_t		pdev_info;
	uint8_t			physport;
	uint8_t			phy_id;
	uint32_t		page_address;
	uint16_t		bay_num, enclosure, io_flags, lun;
	char			pdev_wwn_str[MPTSAS_WWN_STRLEN];
	uint32_t		dev_info;
	int64_t			lun64 = 0;

	mutex_enter(&mpt->m_mutex);
	target = ptgt->m_devhdl;
	sas_wwn = ptgt->m_addr.mta_wwn;
	devinfo = ptgt->m_deviceinfo;
	phy = ptgt->m_phynum;
	inq = &plun->l_inqp0;
	guid = plun->l_guid;
	lun = plun->l_num;
	mutex_exit(&mpt->m_mutex);

	/*
	 * generate compatible property with binding-set "mpt"
	 */
	scsi_hba_nodename_compatible_get(inq, NULL, inq->inq_dtype, NULL,
	    &nodename, &compatible, &ncompatible);

	/*
	 * if nodename can't be determined then print a message and skip it
	 */
	if (nodename == NULL) {
		mptsas_log(mpt, CE_WARN, "mptsas found no compatible driver "
		    "for target %d lun %d", target, lun);
		return (DDI_FAILURE);
	}

	ndi_rtn = ndi_devi_alloc(pdip, nodename,
	    DEVI_SID_NODEID, lun_dip);

	/*
	 * if lun alloc success, set props
	 */
	if (ndi_rtn == NDI_SUCCESS) {

		if (ndi_prop_update_int(DDI_DEV_T_NONE,
		    *lun_dip, LUN_PROP, lun) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to create "
			    "property for target %d lun %d (LUN_PROP)",
			    target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		lun64 = (int64_t)lun;
		if (ndi_prop_update_int64(DDI_DEV_T_NONE,
		    *lun_dip, LUN64_PROP, lun64) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to create "
			    "property for target %d lun64 %d (LUN64_PROP)",
			    target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}
		if (ndi_prop_update_string_array(DDI_DEV_T_NONE,
		    *lun_dip, "compatible", compatible, ncompatible)
		    != DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to create "
			    "property for target %d lun %d (COMPATIBLE)",
			    target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		(void) sprintf(ses_sa_str, "w%016"PRIx64, ptgt->m_addr.mta_wwn);
		if (ndi_prop_update_string(DDI_DEV_T_NONE,
		    *lun_dip, SCSI_ADDR_PROP_SES_SA, ses_sa_str)
		    != DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas3%d: unable to "
			    "create property for SAS target %d lun %d "
			    "(target-port)", mpt->m_instance, target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		/*
		 * We need the SAS WWN for non-multipath devices, so
		 * we'll use the same property as that multipathing
		 * devices need to present for MPAPI. If we don't have
		 * a WWN (e.g. parallel SCSI), don't create the prop.
		 */
		(void) sprintf(wwn_str, "w%016"PRIx64, sas_wwn);
		if (sas_wwn && ndi_prop_update_string(DDI_DEV_T_NONE,
		    *lun_dip, SCSI_ADDR_PROP_TARGET_PORT, wwn_str)
		    != DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to "
			    "create property for SAS target %d lun %d "
			    "(target-port)", target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		be_sas_wwn = BE_64(sas_wwn);
		if (sas_wwn && ndi_prop_update_byte_array(
		    DDI_DEV_T_NONE, *lun_dip, "port-wwn",
		    (uchar_t *)&be_sas_wwn, 8) != DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to "
			    "create property for SAS target %d lun %d "
			    "(port-wwn)", target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		} else if ((sas_wwn == 0) && (ndi_prop_update_int(
		    DDI_DEV_T_NONE, *lun_dip, "sata-phy", phy) !=
		    DDI_PROP_SUCCESS)) {
			/*
			 * Direct attached SATA device without DeviceName
			 */
			mptsas_log(mpt, CE_WARN, "mptsas unable to "
			    "create property for SAS target %d lun %d "
			    "(sata-phy)", target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		if (ndi_prop_create_boolean(DDI_DEV_T_NONE,
		    *lun_dip, SAS_PROP) != DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to"
			    "create property for SAS target %d lun %d"
			    " (SAS_PROP)", target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}
		if (guid && (ndi_prop_update_string(DDI_DEV_T_NONE,
		    *lun_dip, NDI_GUID, guid) != DDI_SUCCESS)) {
			mptsas_log(mpt, CE_WARN, "mptsas unable "
			    "to create guid property for target %d "
			    "lun %d", target, lun);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		/*
		 * The following code is to set properties for SM-HBA support,
		 * it doesn't apply to RAID volumes
		 */
		if (ptgt->m_addr.mta_phymask == 0)
			goto phys_raid_lun;

		mutex_enter(&mpt->m_mutex);

		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) |
		    (uint32_t)ptgt->m_devhdl;
		rval = mptsas_get_sas_device_page0(mpt, page_address,
		    &dev_hdl, &dev_sas_wwn, &dev_info,
		    &physport, &phy_id, &pdev_hdl,
		    &bay_num, &enclosure, &io_flags);
		if (rval != DDI_SUCCESS) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "mptsas unable to get"
			    "parent device for handle %d.", page_address);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) | (uint32_t)pdev_hdl;
		rval = mptsas_get_sas_device_page0(mpt, page_address,
		    &dev_hdl, &pdev_sas_wwn, &pdev_info, &physport,
		    &phy_id, &pdev_hdl, &bay_num, &enclosure, &io_flags);
		if (rval != DDI_SUCCESS) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "mptsas unable to create "
			    "device for handle %d.", page_address);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		mutex_exit(&mpt->m_mutex);

		/*
		 * If this device direct attached to the controller
		 * set the attached-port to the base wwid
		 */
		if ((ptgt->m_deviceinfo & DEVINFO_DIRECT_ATTACHED)
		    != DEVINFO_DIRECT_ATTACHED) {
			(void) sprintf(pdev_wwn_str, "w%016"PRIx64,
			    pdev_sas_wwn);
		} else {
			/*
			 * Update the iport's attached-port to guid
			 */
			if (sas_wwn == 0) {
				(void) sprintf(wwn_str, "p%x", phy);
			} else {
				(void) sprintf(wwn_str, "w%016"PRIx64, sas_wwn);
			}
			if (ddi_prop_update_string(DDI_DEV_T_NONE,
			    pdip, SCSI_ADDR_PROP_ATTACHED_PORT, wwn_str) !=
			    DDI_PROP_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "mptsas unable to create "
				    "property for iport target-port"
				    " %s (sas_wwn)",
				    wwn_str);
				ndi_rtn = NDI_FAILURE;
				goto phys_create_done;
			}

			(void) sprintf(pdev_wwn_str, "w%016"PRIx64,
			    mpt->un.m_base_wwid);
		}

		if (ndi_prop_update_string(DDI_DEV_T_NONE,
		    *lun_dip, SCSI_ADDR_PROP_ATTACHED_PORT, pdev_wwn_str) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN,
			    "mptsas unable to create "
			    "property for iport attached-port %s (sas_wwn)",
			    pdev_wwn_str);
			ndi_rtn = NDI_FAILURE;
			goto phys_create_done;
		}

		if (IS_SATA_DEVICE(dev_info)) {
			if (ndi_prop_update_string(DDI_DEV_T_NONE,
			    *lun_dip, MPTSAS_VARIANT, "sata") !=
			    DDI_PROP_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "mptsas unable to create "
				    "property for device variant ");
				ndi_rtn = NDI_FAILURE;
				goto phys_create_done;
			}
		}

		if (IS_ATAPI_DEVICE(dev_info)) {
			if (ndi_prop_update_string(DDI_DEV_T_NONE,
			    *lun_dip, MPTSAS_VARIANT, "atapi") !=
			    DDI_PROP_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "mptsas unable to create "
				    "property for device variant ");
				ndi_rtn = NDI_FAILURE;
				goto phys_create_done;
			}
		}

phys_raid_lun:
		/*
		 * if this is a SAS controller, and the target is a SATA
		 * drive, set the 'pm-capable' property for sd and if on
		 * an OPL platform, also check if this is an ATAPI
		 * device.
		 */
		instance = ddi_get_instance(mpt->m_dip);
		if (devinfo & (MPI2_SAS_DEVICE_INFO_SATA_DEVICE |
		    MPI2_SAS_DEVICE_INFO_ATAPI_DEVICE)) {
			NDBG2(("%d: creating pm-capable property, "
			    "target %d", instance, target));

			if ((ndi_prop_update_int(DDI_DEV_T_NONE,
			    *lun_dip, "pm-capable", 1)) !=
			    DDI_PROP_SUCCESS) {
				mptsas_log(mpt, CE_WARN, "mptsas "
				    "failed to create pm-capable "
				    "property, target %d", target);
				ndi_rtn = NDI_FAILURE;
				goto phys_create_done;
			}

		}

		if ((inq->inq_dtype == 0) || (inq->inq_dtype == 5)) {
			/*
			 * add 'obp-path' properties for devinfo
			 */
			bzero(wwn_str, sizeof (wwn_str));
			(void) sprintf(wwn_str, "%016"PRIx64, sas_wwn);
			if (guid) {
				(void) snprintf(component, MAXPATHLEN,
				    "disk@w%s,%x", wwn_str, lun);
			} else {
				(void) snprintf(component, MAXPATHLEN,
				    "disk@p%x,%x", phy, lun);
			}
			if (ddi_pathname_obp_set(*lun_dip, component)
			    != DDI_SUCCESS) {
				mptsas_log(mpt, CE_WARN, "mpt_sas driver "
				    "unable to set obp-path for SAS "
				    "object %s", component);
				ndi_rtn = NDI_FAILURE;
				goto phys_create_done;
			}
		}
		/*
		 * Create the phy-num property for non-raid disk
		 */
		if (ptgt->m_addr.mta_phymask != 0) {
			if (ndi_prop_update_int(DDI_DEV_T_NONE,
			    *lun_dip, "phy-num", ptgt->m_phynum) !=
			    DDI_PROP_SUCCESS) {
				mptsas_log(mpt, CE_WARN,
				    "failed to create phy-num property for "
				    "target %d", target);
				ndi_rtn = NDI_FAILURE;
				goto phys_create_done;
			}
		}
phys_create_done:
		/*
		 * If props were setup ok, online the lun
		 */
		if (ndi_rtn == NDI_SUCCESS) {
			/*
			 * Try to online the new node
			 */
			ndi_rtn = ndi_devi_online(*lun_dip, NDI_ONLINE_ATTACH);
		}
		if (ndi_rtn == NDI_SUCCESS) {
			mutex_enter(&mpt->m_mutex);
			ptgt->m_led_status = 0;
			(void) mptsas_flush_led_status(mpt, ptgt);
			mutex_exit(&mpt->m_mutex);
		}

		/*
		 * If success set rtn flag, else unwire alloc'd lun
		 */
		if (ndi_rtn != NDI_SUCCESS) {
			NDBG12(("%d: unable to online phys target %d "
			    "lun %d", mpt->m_instance, target, lun));
			ndi_prop_remove_all(*lun_dip);
			(void) ndi_devi_free(*lun_dip);
			*lun_dip = NULL;
		}
	}

	scsi_hba_nodename_compatible_free(nodename, compatible);

	return ((ndi_rtn == NDI_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

static int
mptsas_probe_smp(dev_info_t *pdip, uint64_t wwn)
{
	mptsas_t	*mpt = DIP2MPT(pdip);
	struct smp_device smp_sd;

	/* XXX An HBA driver should not be allocating an smp_device. */
	bzero(&smp_sd, sizeof (struct smp_device));
	smp_sd.smp_sd_address.smp_a_hba_tran = mpt->m_smptran;
	bcopy(&wwn, smp_sd.smp_sd_address.smp_a_wwn, SAS_WWN_BYTE_SIZE);

	if (smp_probe(&smp_sd) != DDI_PROBE_SUCCESS)
		return (NDI_FAILURE);
	return (NDI_SUCCESS);
}

static int
mptsas_config_smp(dev_info_t *pdip, uint64_t sas_wwn, dev_info_t **smp_dip)
{
	mptsas_t	*mpt = DIP2MPT(pdip);
	mptsas_smp_t	*psmp = NULL;
	int		rval;
	int		phymask_prop;

	/*
	 * Get the physical port associated to the iport
	 * PHYMASK TODO
	 */
	phymask_prop = ddi_prop_get_int(DDI_DEV_T_ANY, pdip, 0, "phymask", 0);

	/*
	 * Find the smp node in hash table with specified sas address and
	 * physical port
	 */
	psmp = mptsas_wwid_to_psmp(mpt, phymask_prop, sas_wwn);
	if (psmp == NULL) {
		return (DDI_FAILURE);
	}

	rval = mptsas_online_smp(pdip, psmp, smp_dip);

	return (rval);
}

static int
mptsas_online_smp(dev_info_t *pdip, mptsas_smp_t *smp_node,
    dev_info_t **smp_dip)
{
	char		wwn_str[MPTSAS_WWN_STRLEN];
	char		attached_wwn_str[MPTSAS_WWN_STRLEN];
	int		ndi_rtn = NDI_FAILURE;
	int		rval = 0;
	mptsas_smp_t	dev_info;
	uint32_t	page_address;
	mptsas_t	*mpt = DIP2MPT(pdip);
	uint16_t	dev_hdl;
	uint64_t	sas_wwn;
	uint64_t	smp_sas_wwn;
	uint8_t		physport;
	uint8_t		phy_id;
	uint16_t	pdev_hdl;
	uint8_t		numphys = 0;
	uint16_t	i = 0;
	char		phymask[MPTSAS_MAX_PHYS];
	char		*iport = NULL;
	mptsas_phymask_t	phy_mask = 0;
	uint16_t	attached_devhdl;
	uint16_t	bay_num, enclosure, io_flags;

	(void) sprintf(wwn_str, "%"PRIx64, smp_node->m_addr.mta_wwn);

	/*
	 * Probe smp device, prevent the node of removed device from being
	 * configured succesfully
	 */
	if (mptsas_probe_smp(pdip, smp_node->m_addr.mta_wwn) != NDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if ((*smp_dip = mptsas_find_smp_child(pdip, wwn_str)) != NULL) {
		return (DDI_SUCCESS);
	}

	ndi_rtn = ndi_devi_alloc(pdip, "smp", DEVI_SID_NODEID, smp_dip);

	/*
	 * if lun alloc success, set props
	 */
	if (ndi_rtn == NDI_SUCCESS) {
		/*
		 * Set the flavor of the child to be SMP flavored
		 */
		ndi_flavor_set(*smp_dip, SCSA_FLAVOR_SMP);

		if (ndi_prop_update_string(DDI_DEV_T_NONE,
		    *smp_dip, SMP_WWN, wwn_str) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to create "
			    "property for smp device %s (sas_wwn)",
			    wwn_str);
			ndi_rtn = NDI_FAILURE;
			goto smp_create_done;
		}

		(void) sprintf(wwn_str, "w%"PRIx64, smp_node->m_addr.mta_wwn);
		if (ndi_prop_update_string(DDI_DEV_T_NONE,
		    *smp_dip, SCSI_ADDR_PROP_TARGET_PORT, wwn_str) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to create "
			    "property for iport target-port %s (sas_wwn)",
			    wwn_str);
			ndi_rtn = NDI_FAILURE;
			goto smp_create_done;
		}

		mutex_enter(&mpt->m_mutex);

		page_address = (MPI2_SAS_EXPAND_PGAD_FORM_HNDL &
		    MPI2_SAS_EXPAND_PGAD_FORM_MASK) | smp_node->m_devhdl;
		rval = mptsas_get_sas_expander_page0(mpt, page_address,
		    &dev_info);
		if (rval != DDI_SUCCESS) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN,
			    "mptsas unable to get expander "
			    "parent device info for %x", page_address);
			ndi_rtn = NDI_FAILURE;
			goto smp_create_done;
		}

		smp_node->m_pdevhdl = dev_info.m_pdevhdl;
		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) |
		    (uint32_t)dev_info.m_pdevhdl;
		rval = mptsas_get_sas_device_page0(mpt, page_address,
		    &dev_hdl, &sas_wwn, &smp_node->m_pdevinfo, &physport,
		    &phy_id, &pdev_hdl, &bay_num, &enclosure, &io_flags);
		if (rval != DDI_SUCCESS) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "mptsas unable to get "
			    "device info for %x", page_address);
			ndi_rtn = NDI_FAILURE;
			goto smp_create_done;
		}

		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) |
		    (uint32_t)dev_info.m_devhdl;
		rval = mptsas_get_sas_device_page0(mpt, page_address,
		    &dev_hdl, &smp_sas_wwn, &smp_node->m_deviceinfo,
		    &physport, &phy_id, &pdev_hdl, &bay_num, &enclosure,
		    &io_flags);
		if (rval != DDI_SUCCESS) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "mptsas unable to get "
			    "device info for %x", page_address);
			ndi_rtn = NDI_FAILURE;
			goto smp_create_done;
		}
		mutex_exit(&mpt->m_mutex);

		/*
		 * If this smp direct attached to the controller
		 * set the attached-port to the base wwid
		 */
		if ((smp_node->m_deviceinfo & DEVINFO_DIRECT_ATTACHED)
		    != DEVINFO_DIRECT_ATTACHED) {
			(void) sprintf(attached_wwn_str, "w%016"PRIx64,
			    sas_wwn);
		} else {
			(void) sprintf(attached_wwn_str, "w%016"PRIx64,
			    mpt->un.m_base_wwid);
		}

		if (ndi_prop_update_string(DDI_DEV_T_NONE,
		    *smp_dip, SCSI_ADDR_PROP_ATTACHED_PORT, attached_wwn_str) !=
		    DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to create "
			    "property for smp attached-port %s (sas_wwn)",
			    attached_wwn_str);
			ndi_rtn = NDI_FAILURE;
			goto smp_create_done;
		}

		if (ndi_prop_create_boolean(DDI_DEV_T_NONE,
		    *smp_dip, SMP_PROP) != DDI_PROP_SUCCESS) {
			mptsas_log(mpt, CE_WARN, "mptsas unable to "
			    "create property for SMP %s (SMP_PROP) ",
			    wwn_str);
			ndi_rtn = NDI_FAILURE;
			goto smp_create_done;
		}

		/*
		 * check the smp to see whether it direct
		 * attached to the controller
		 */
		if ((smp_node->m_deviceinfo & DEVINFO_DIRECT_ATTACHED)
		    != DEVINFO_DIRECT_ATTACHED) {
			goto smp_create_done;
		}
		numphys = ddi_prop_get_int(DDI_DEV_T_ANY, pdip,
		    DDI_PROP_DONTPASS, MPTSAS_NUM_PHYS, -1);
		if (numphys > 0) {
			goto smp_create_done;
		}
		/*
		 * this iport is an old iport, we need to
		 * reconfig the props for it.
		 */
		if (ddi_prop_update_int(DDI_DEV_T_NONE, pdip,
		    MPTSAS_VIRTUAL_PORT, 0) !=
		    DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, pdip,
			    MPTSAS_VIRTUAL_PORT);
			mptsas_log(mpt, CE_WARN, "mptsas virtual port "
			    "prop update failed");
			goto smp_create_done;
		}

		mutex_enter(&mpt->m_mutex);
		numphys = 0;
		iport = ddi_get_name_addr(pdip);
		for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
			bzero(phymask, sizeof (phymask));
			(void) sprintf(phymask,
			    "%x", mpt->m_phy_info[i].phy_mask);
			if (strcmp(phymask, iport) == 0) {
				phy_mask = mpt->m_phy_info[i].phy_mask;
				break;
			}
		}

		for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
			if ((phy_mask >> i) & 0x01) {
				numphys++;
			}
		}
		/*
		 * Update PHY info for smhba
		 */
		if (mptsas_smhba_phy_init(mpt)) {
			mutex_exit(&mpt->m_mutex);
			mptsas_log(mpt, CE_WARN, "mptsas phy update "
			    "failed");
			goto smp_create_done;
		}
		mutex_exit(&mpt->m_mutex);

		mptsas_smhba_set_all_phy_props(mpt, pdip, numphys, phy_mask,
		    &attached_devhdl);

		if (ddi_prop_update_int(DDI_DEV_T_NONE, pdip,
		    MPTSAS_NUM_PHYS, numphys) !=
		    DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, pdip,
			    MPTSAS_NUM_PHYS);
			mptsas_log(mpt, CE_WARN, "mptsas update "
			    "num phys props failed");
			goto smp_create_done;
		}
		/*
		 * Add parent's props for SMHBA support
		 */
		if (ddi_prop_update_string(DDI_DEV_T_NONE, pdip,
		    SCSI_ADDR_PROP_ATTACHED_PORT, wwn_str) !=
		    DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, pdip,
			    SCSI_ADDR_PROP_ATTACHED_PORT);
			mptsas_log(mpt, CE_WARN, "mptsas update iport"
			    "attached-port failed");
			goto smp_create_done;
		}

smp_create_done:
		/*
		 * If props were setup ok, online the lun
		 */
		if (ndi_rtn == NDI_SUCCESS) {
			/*
			 * Try to online the new node
			 */
			ndi_rtn = ndi_devi_online(*smp_dip, NDI_ONLINE_ATTACH);
		}

		/*
		 * If success set rtn flag, else unwire alloc'd lun
		 */
		if (ndi_rtn != NDI_SUCCESS) {
			NDBG12(("%d: unable to online "
			    "SMP target %s", mpt->m_instance, wwn_str));
			ndi_prop_remove_all(*smp_dip);
			(void) ndi_devi_free(*smp_dip);
		}
	}

	return ((ndi_rtn == NDI_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

/* smp transport routine */
static int mptsas_smp_start(struct smp_pkt *smp_pkt)
{
	uint64_t			wwn;
	Mpi2SmpPassthroughRequest_t	req;
	Mpi2SmpPassthroughReply_t	rep;
	uint8_t				direction = 0;
	mptsas_t			*mpt;
	int				ret;
	uint64_t			tmp64;
	uint_t				iocstatus;

	mpt = (mptsas_t *)smp_pkt->smp_pkt_address->
	    smp_a_hba_tran->smp_tran_hba_private;

	bcopy(smp_pkt->smp_pkt_address->smp_a_wwn, &wwn, SAS_WWN_BYTE_SIZE);
	/*
	 * Need to compose a SMP request message
	 * and call mptsas_do_passthru() function
	 */
	bzero(&req, sizeof (req));
	bzero(&rep, sizeof (rep));
	req.PassthroughFlags = 0;
	req.PhysicalPort = 0xff;
	req.ChainOffset = 0;
	req.Function = MPI2_FUNCTION_SMP_PASSTHROUGH;

	if ((smp_pkt->smp_pkt_reqsize & 0xffff0000ul) != 0) {
		smp_pkt->smp_pkt_reason = ERANGE;
		return (DDI_FAILURE);
	}
	req.RequestDataLength = LE_16((uint16_t)(smp_pkt->smp_pkt_reqsize - 4));

	req.MsgFlags = 0;
	tmp64 = LE_64(wwn);
	bcopy(&tmp64, &req.SASAddress, SAS_WWN_BYTE_SIZE);
	if (smp_pkt->smp_pkt_rspsize > 0) {
		direction |= MPTSAS_PASS_THRU_DIRECTION_READ;
	}
	if (smp_pkt->smp_pkt_reqsize > 0) {
		direction |= MPTSAS_PASS_THRU_DIRECTION_WRITE;
	}

	mutex_enter(&mpt->m_mutex);
	ret = mptsas_do_passthru(mpt, (uint8_t *)&req, (uint8_t *)&rep,
	    (uint8_t *)smp_pkt->smp_pkt_rsp,
	    offsetof(Mpi2SmpPassthroughRequest_t, SGL), sizeof (rep),
	    smp_pkt->smp_pkt_rspsize - 4, direction,
	    (uint8_t *)smp_pkt->smp_pkt_req, smp_pkt->smp_pkt_reqsize - 4,
	    smp_pkt->smp_pkt_timeout, FKIOCTL);
	mutex_exit(&mpt->m_mutex);
	if (ret != 0) {
		cmn_err(CE_WARN, "smp_start do passthru error %d", ret);
		smp_pkt->smp_pkt_reason = (uchar_t)(ret);
		return (DDI_FAILURE);
	}
	/* do passthrough success, check the smp status */
	iocstatus = LE_16(rep.IOCStatus);
	if (iocstatus != MPI2_IOCSTATUS_SUCCESS) {
		switch (iocstatus & MPI2_IOCSTATUS_MASK) {
		case MPI2_IOCSTATUS_SCSI_DEVICE_NOT_THERE:
			smp_pkt->smp_pkt_reason = ENODEV;
			break;
		case MPI2_IOCSTATUS_SAS_SMP_DATA_OVERRUN:
			smp_pkt->smp_pkt_reason = EOVERFLOW;
			break;
		case MPI2_IOCSTATUS_SAS_SMP_REQUEST_FAILED:
			smp_pkt->smp_pkt_reason = EIO;
			break;
		default:
			mptsas_log(mpt, CE_NOTE, "?smp_start: received unknown "
			    "ioc status:0x%x", iocstatus);
			if (iocstatus & MPI2_IOCSTATUS_FLAG_LOG_INFO_AVAILABLE)
				mptsas_log(mpt, CE_NOTE, "?   IOCLogINFO:0x%x",
				    LE_32(rep.IOCLogInfo));
			smp_pkt->smp_pkt_reason = EIO;
			break;
		}
		return (DDI_FAILURE);
	}
	if (rep.SASStatus != MPI2_SASSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_NOTE, "smp_start: get error SAS status:%x",
		    rep.SASStatus);
		smp_pkt->smp_pkt_reason = EIO;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * If we didn't get a match, we need to get sas page0 for each device, and
 * until we get a match. If failed, return NULL.
 * If we succeed lock the target.
 */
static mptsas_target_t *
mptsas_phy_to_tgt(mptsas_t *mpt, mptsas_phymask_t phymask, uint8_t phy)
{
	int		i, j = 0;
	int		rval = 0;
	uint16_t	cur_handle;
	uint32_t	page_address;
	mptsas_target_t	*ptgt;

	/*
	 * PHY named device must be direct attached and attaches to
	 * narrow port, if the iport is not parent of the device which
	 * we are looking for.
	 */
	for (i = 0; i < MPTSAS_MAX_PHYS; i++) {
		if ((1 << i) & phymask)
			j++;
	}

	if (j > 1)
		return (NULL);

	/*
	 * Must be a narrow port and single device attached to the narrow port
	 * So the physical port num of device  which is equal to the iport's
	 * port num is the device what we are looking for.
	 */

	if (mpt->m_phy_info[phy].phy_mask != phymask)
		return (NULL);

	ptgt = refhash_linear_search(mpt->m_targets, mptsas_target_eval_nowwn,
	    &phy);
	if (ptgt != NULL && ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL) {
		mutex_enter(&ptgt->m_t_mutex);
		return (ptgt);
	}

	if (mpt->m_done_traverse_dev) {
		return (NULL);
	}

	/* If didn't get a match, come here */
	cur_handle = mpt->m_dev_handle;
	for (; ; ) {
		ptgt = NULL;
		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_GET_NEXT_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) | (uint32_t)cur_handle;
		rval = mptsas_get_target_device_info(mpt, page_address,
		    &cur_handle, &ptgt);
		if (rval == DEV_INFO_FAIL_PAGE0) {
			break;
		}
		if ((rval == DEV_INFO_WRONG_DEVICE_TYPE) ||
		    (rval == DEV_INFO_PHYS_DISK)) {
			continue;
		}
		/* Must be SUCCESS, target will be locked */
		mpt->m_dev_handle = cur_handle;

		if ((ptgt->m_addr.mta_wwn == 0) && (ptgt->m_phynum == phy)) {
			break;
		}
		mutex_exit(&ptgt->m_t_mutex);
	}

	return (ptgt);
}

/*
 * The ptgt->m_addr.mta_wwn contains the wwid for each disk.
 * For Raid volumes, we need to check m_raidvol[x].m_raidwwid
 * If we didn't get a match, we need to get sas page0 for each device, and
 * untill we get a match
 * If failed, return NULL
 * If we succeed lock the target.
 */
static mptsas_target_t *
mptsas_wwid_to_ptgt(mptsas_t *mpt, mptsas_phymask_t phymask, uint64_t wwid)
{
	int		rval = 0;
	uint16_t	cur_handle;
	uint32_t	page_address;
	mptsas_target_t	*ptgt;
	mptsas_target_addr_t addr;

	addr.mta_wwn = wwid;
	addr.mta_phymask = phymask;
	ptgt = refhash_lookup(mpt->m_targets, &addr);
	if (ptgt != NULL && ptgt->m_devhdl != MPTSAS_INVALID_DEVHDL) {
		mutex_enter(&ptgt->m_t_mutex);
		return (ptgt);
	}

	if (phymask == 0) {
		/*
		 * It's IR volume
		 */
		rval = mptsas_get_raid_info(mpt);
		ptgt = NULL;
		if (rval) {
			ptgt = refhash_lookup(mpt->m_targets, &addr);
		}
		if (ptgt != NULL) {
			mutex_enter(&ptgt->m_t_mutex);
		}
		return (ptgt);
	}

	if (mpt->m_done_traverse_dev) {
		return (NULL);
	}

	/* If didn't get a match, come here */
	cur_handle = mpt->m_dev_handle;
	for (;;) {
		ptgt = NULL;
		page_address = (MPI2_SAS_DEVICE_PGAD_FORM_GET_NEXT_HANDLE &
		    MPI2_SAS_DEVICE_PGAD_FORM_MASK) | cur_handle;
		rval = mptsas_get_target_device_info(mpt, page_address,
		    &cur_handle, &ptgt);
		if (rval == DEV_INFO_FAIL_PAGE0) {
			ptgt = NULL;
			break;
		}
		if ((rval == DEV_INFO_WRONG_DEVICE_TYPE) ||
		    (rval == DEV_INFO_PHYS_DISK)) {
			continue;
		}
		/* Must be SUCCESS, target will be locked. */
		mpt->m_dev_handle = cur_handle;
		if ((ptgt->m_addr.mta_wwn) &&
		    (ptgt->m_addr.mta_wwn == wwid) &&
		    (ptgt->m_addr.mta_phymask == phymask)) {
			break;
		}
		mutex_exit(&ptgt->m_t_mutex);
	}

	return (ptgt);
}

static mptsas_smp_t *
mptsas_wwid_to_psmp(mptsas_t *mpt, mptsas_phymask_t phymask, uint64_t wwid)
{
	int		rval = 0;
	uint16_t	cur_handle;
	uint32_t	page_address;
	mptsas_smp_t	smp_node, *psmp = NULL;
	mptsas_target_addr_t addr;

	addr.mta_wwn = wwid;
	addr.mta_phymask = phymask;
	mutex_enter(&mpt->m_mutex);
	psmp = refhash_lookup(mpt->m_smp_targets, &addr);
	if (psmp != NULL && psmp->m_devhdl != MPTSAS_INVALID_DEVHDL) {
		mutex_exit(&mpt->m_mutex);
		return (psmp);
	}

	if (mpt->m_done_traverse_smp) {
		mutex_exit(&mpt->m_mutex);
		return (NULL);
	}

	/* If didn't get a match, come here */
	cur_handle = mpt->m_smp_devhdl;
	for (;;) {
		psmp = NULL;
		page_address = (MPI2_SAS_EXPAND_PGAD_FORM_GET_NEXT_HNDL &
		    MPI2_SAS_EXPAND_PGAD_FORM_MASK) | (uint32_t)cur_handle;
		rval = mptsas_get_sas_expander_page0(mpt, page_address,
		    &smp_node);
		if (rval != DDI_SUCCESS) {
			break;
		}
		mpt->m_smp_devhdl = cur_handle = smp_node.m_devhdl;
		psmp = mptsas_smp_alloc(mpt, &smp_node);
		ASSERT(psmp);
		if ((psmp->m_addr.mta_wwn) && (psmp->m_addr.mta_wwn == wwid) &&
		    (psmp->m_addr.mta_phymask == phymask)) {
			break;
		}
	}

	mutex_exit(&mpt->m_mutex);
	return (psmp);
}

/*
 * Allocate target structure (or return existing one).
 * Set initializing flags and return with the target mutex held.
 */
mptsas_target_t *
mptsas_tgt_alloc(mptsas_t *mpt, uint16_t devhdl, uint64_t wwid,
    uint32_t devinfo, mptsas_phymask_t phymask, uint8_t phynum)
{
	mptsas_target_t *tmp_tgt = NULL;
	mptsas_target_addr_t addr;

	addr.mta_wwn = wwid;
	addr.mta_phymask = phymask;
	tmp_tgt = refhash_lookup(mpt->m_targets, &addr);
	if (tmp_tgt != NULL) {
		NDBG20(("%d: Hash item already exists, devhdl 0x%x->0x%x"
		    " init %d", mpt->m_instance, tmp_tgt->m_devhdl, devhdl,
		    tmp_tgt->m_t_init));
		mutex_enter(&tmp_tgt->m_t_mutex);
		if (tmp_tgt->m_devhdl == MPTSAS_INVALID_DEVHDL) {
			tmp_tgt->m_deviceinfo = devinfo;
			tmp_tgt->m_devhdl = devhdl;
			tmp_tgt->m_shdwhdl = MPTSAS_INVALID_DEVHDL;
			tmp_tgt->m_t_throttle = tmp_tgt->m_t_maxthrottle;
#ifdef AUTO_OFFLINE_TARGETS
			tmp_tgt->m_timeout_ncmd = 0;
#endif
			ASSERT(tmp_tgt->m_t_init <= TINIT_UPDATE);
			if (tmp_tgt->m_t_init == TINIT_UPDATE)
				tmp_tgt->m_t_init = TINIT_UPDATED;
			else
				tmp_tgt->m_t_init = TINIT_FOUND;
		}
		return (tmp_tgt);
	}
	tmp_tgt = kmem_zalloc(sizeof (struct mptsas_target), KM_SLEEP);
	/* Initialized the tgt structure */
	mutex_init(&tmp_tgt->m_t_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tmp_tgt->m_t_cv, NULL, CV_DRIVER, NULL);
	tmp_tgt->m_devhdl = devhdl;
	tmp_tgt->m_shdwhdl = MPTSAS_INVALID_DEVHDL;
	tmp_tgt->m_addr.mta_wwn = wwid;
	tmp_tgt->m_deviceinfo = devinfo;
	tmp_tgt->m_addr.mta_phymask = phymask;
	tmp_tgt->m_phynum = phynum;
	tmp_tgt->m_qfull_retries = QFULL_RETRIES;
	tmp_tgt->m_qfull_retry_interval =
	    drv_usectohz(QFULL_RETRY_INTERVAL * 1000);
	if (devinfo & MPI2_SAS_DEVICE_INFO_SEP)
		tmp_tgt->m_t_maxthrottle = 1;
	else
		tmp_tgt->m_t_maxthrottle = (int16_t)mptsas_max_throttle;
	tmp_tgt->m_t_throttle = tmp_tgt->m_t_maxthrottle;
	TAILQ_INIT(&tmp_tgt->m_active_cmdq);
	STAILQ_INIT(&tmp_tgt->m_t_wait.cl_q);

	mutex_enter(&tmp_tgt->m_t_mutex);
	tmp_tgt->m_t_init = TINIT_ALLOCED;
	refhash_insert(mpt->m_targets, tmp_tgt);

	return (tmp_tgt);
}

static void
mptsas_smp_target_copy(mptsas_smp_t *src, mptsas_smp_t *dst)
{
	dst->m_devhdl = src->m_devhdl;
	dst->m_deviceinfo = src->m_deviceinfo;
	dst->m_pdevhdl = src->m_pdevhdl;
	dst->m_pdevinfo = src->m_pdevinfo;
}

static mptsas_smp_t *
mptsas_smp_alloc(mptsas_t *mpt, mptsas_smp_t *data)
{
	mptsas_target_addr_t addr;
	mptsas_smp_t *ret_data;

	addr.mta_wwn = data->m_addr.mta_wwn;
	addr.mta_phymask = data->m_addr.mta_phymask;
	ret_data = refhash_lookup(mpt->m_smp_targets, &addr);
	/*
	 * If there's already a matching SMP target, update its fields
	 * in place.  Since the address is not changing, it's safe to do
	 * this.  We cannot just bcopy() here because the structure we've
	 * been given has invalid hash links.
	 */
	if (ret_data != NULL) {
		mptsas_smp_target_copy(data, ret_data);
		return (ret_data);
	}

	ret_data = kmem_alloc(sizeof (mptsas_smp_t), KM_SLEEP);
	bcopy(data, ret_data, sizeof (mptsas_smp_t));
	refhash_insert(mpt->m_smp_targets, ret_data);
	return (ret_data);
}

/*
 * Functions for SGPIO LED support
 */
static dev_info_t *
mptsas_get_dip_from_dev(dev_t dev, mptsas_phymask_t *phymask)
{
	dev_info_t	*dip;
	int		prop;
	dip = e_ddi_hold_devi_by_dev(dev, 0);
	if (dip == NULL)
		return (dip);
	prop = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "phymask", 0);
	*phymask = (mptsas_phymask_t)prop;
	ddi_release_devi(dip);
	return (dip);
}

static mptsas_target_t *
mptsas_addr_to_ptgt(mptsas_t *mpt, char *addr, mptsas_phymask_t phymask,
    uint8_t *ppnum, uint64_t *pwwn, int *plun)
{
	uint8_t			phynum;
	uint64_t		wwn;
	int			lun;
	mptsas_target_t		*ptgt = NULL;

	if (mptsas_parse_address(addr, &wwn, &phynum, &lun) != DDI_SUCCESS) {
		return (NULL);
	}
	if (plun != NULL)
		*plun = lun;
	if (addr[0] == 'w') {
		if (pwwn != NULL)
			*pwwn = wwn;
		ptgt = mptsas_wwid_to_ptgt(mpt, (int)phymask, wwn);
	} else {
		if (ppnum != NULL)
			*ppnum = phynum;
		ptgt = mptsas_phy_to_tgt(mpt, (int)phymask, phynum);
	}
	return (ptgt);
}

static int
mptsas_flush_led_status(mptsas_t *mpt, mptsas_target_t *ptgt)
{
	uint32_t slotstatus = 0;

	/* Build an MPI2 Slot Status based on our view of the world */
	if (ptgt->m_led_status & (1 << (MPTSAS_LEDCTL_LED_IDENT - 1)))
		slotstatus |= MPI2_SEP_REQ_SLOTSTATUS_IDENTIFY_REQUEST;
	if (ptgt->m_led_status & (1 << (MPTSAS_LEDCTL_LED_FAIL - 1)))
		slotstatus |= MPI2_SEP_REQ_SLOTSTATUS_PREDICTED_FAULT;
	if (ptgt->m_led_status & (1 << (MPTSAS_LEDCTL_LED_OK2RM - 1)))
		slotstatus |= MPI2_SEP_REQ_SLOTSTATUS_REQUEST_REMOVE;

	/* Write it to the controller */
	NDBG14(("%d: ioctl: set LED status %x for slot %x",
	    mpt->m_instance, slotstatus, ptgt->m_slot_num));
	return (mptsas_send_sep(mpt, ptgt, &slotstatus,
	    MPI2_SEP_REQ_ACTION_WRITE_STATUS));
}

/*
 *  send sep request, use enclosure/slot addressing
 */
static int
mptsas_send_sep(mptsas_t *mpt, mptsas_target_t *ptgt,
    uint32_t *status, uint8_t act)
{
	Mpi2SepRequest_t	req;
	Mpi2SepReply_t		rep;
	int			ret;

	ASSERT(mutex_owned(&mpt->m_mutex));

	/*
	 * We only support SEP control of directly-attached targets, in which
	 * case the "SEP" we're talking to is a virtual one contained within
	 * the HBA itself.  This is necessary because DA targets typically have
	 * no other mechanism for LED control.  Targets for which a separate
	 * enclosure service processor exists should be controlled via ses(7d)
	 * or sgen(7d).  Furthermore, since such requests can time out, they
	 * should be made in user context rather than in response to
	 * asynchronous fabric changes.
	 *
	 * In addition, we do not support this operation for RAID volumes,
	 * since there is no slot associated with them.
	 */
	if (!(ptgt->m_deviceinfo & DEVINFO_DIRECT_ATTACHED) ||
	    ptgt->m_addr.mta_phymask == 0) {
		return (ENOTTY);
	}

	bzero(&req, sizeof (req));
	bzero(&rep, sizeof (rep));

	req.Function = MPI2_FUNCTION_SCSI_ENCLOSURE_PROCESSOR;
	req.Action = act;
	req.Flags = MPI2_SEP_REQ_FLAGS_ENCLOSURE_SLOT_ADDRESS;
	req.EnclosureHandle = LE_16(ptgt->m_enclosure);
	req.Slot = LE_16(ptgt->m_slot_num);
	if (act == MPI2_SEP_REQ_ACTION_WRITE_STATUS) {
		req.SlotStatus = LE_32(*status);
	}
	ret = mptsas_do_passthru(mpt, (uint8_t *)&req, (uint8_t *)&rep, NULL,
	    sizeof (req), sizeof (rep), 0, 0, NULL, 0, 60, FKIOCTL);
	if (ret != 0) {
		mptsas_log(mpt, CE_NOTE, "mptsas_send_sep: passthru SEP "
		    "Processor Request message error %d", ret);
		return (ret);
	}
	/* do passthrough success, check the ioc status */
	if (LE_16(rep.IOCStatus) != MPI2_IOCSTATUS_SUCCESS) {
		mptsas_log(mpt, CE_NOTE, "send_sep act %x: ioc "
		    "status:%x loginfo %x", act, LE_16(rep.IOCStatus),
		    LE_32(rep.IOCLogInfo));
		switch (LE_16(rep.IOCStatus) & MPI2_IOCSTATUS_MASK) {
		case MPI2_IOCSTATUS_INVALID_FUNCTION:
		case MPI2_IOCSTATUS_INVALID_VPID:
		case MPI2_IOCSTATUS_INVALID_FIELD:
		case MPI2_IOCSTATUS_INVALID_STATE:
		case MPI2_IOCSTATUS_OP_STATE_NOT_SUPPORTED:
		case MPI2_IOCSTATUS_CONFIG_INVALID_ACTION:
		case MPI2_IOCSTATUS_CONFIG_INVALID_TYPE:
		case MPI2_IOCSTATUS_CONFIG_INVALID_PAGE:
		case MPI2_IOCSTATUS_CONFIG_INVALID_DATA:
		case MPI2_IOCSTATUS_CONFIG_NO_DEFAULTS:
			return (EINVAL);
		case MPI2_IOCSTATUS_BUSY:
			return (EBUSY);
		case MPI2_IOCSTATUS_INSUFFICIENT_RESOURCES:
			return (EAGAIN);
		case MPI2_IOCSTATUS_INVALID_SGL:
		case MPI2_IOCSTATUS_INTERNAL_ERROR:
		case MPI2_IOCSTATUS_CONFIG_CANT_COMMIT:
		default:
			return (EIO);
		}
	}
	if (act != MPI2_SEP_REQ_ACTION_WRITE_STATUS) {
		*status = LE_32(rep.SlotStatus);
	}

	return (0);
}

int
mptsas_dma_addr_create(mptsas_t *mpt, ddi_dma_attr_t dma_attr,
    ddi_dma_handle_t *dma_hdp, ddi_acc_handle_t *acc_hdp, caddr_t *dma_memp,
    uint32_t alloc_size, ddi_dma_cookie_t *cookiep)
{
	ddi_dma_cookie_t	new_cookie;
	size_t			alloc_len;
	uint_t			ncookie;

	if (cookiep == NULL)
		cookiep = &new_cookie;

	if (ddi_dma_alloc_handle(mpt->m_dip, &dma_attr, DDI_DMA_SLEEP,
	    NULL, dma_hdp) != DDI_SUCCESS) {
		return (FALSE);
	}

	if (ddi_dma_mem_alloc(*dma_hdp, alloc_size, &mpt->m_dev_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, dma_memp, &alloc_len,
	    acc_hdp) != DDI_SUCCESS) {
		ddi_dma_free_handle(dma_hdp);
		return (FALSE);
	}

	if (ddi_dma_addr_bind_handle(*dma_hdp, NULL, *dma_memp, alloc_len,
	    (DDI_DMA_RDWR | DDI_DMA_CONSISTENT), DDI_DMA_SLEEP, NULL,
	    cookiep, &ncookie) != DDI_DMA_MAPPED) {
		(void) ddi_dma_mem_free(acc_hdp);
		ddi_dma_free_handle(dma_hdp);
		return (FALSE);
	}

	return (TRUE);
}

void
mptsas_dma_addr_destroy(ddi_dma_handle_t *dma_hdp, ddi_acc_handle_t *acc_hdp)
{
	if (*dma_hdp == NULL)
		return;

	(void) ddi_dma_unbind_handle(*dma_hdp);
	(void) ddi_dma_mem_free(acc_hdp);
	ddi_dma_free_handle(dma_hdp);
}
