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

#include "vioscsi.h"

/* Configuration registers */
/*
 * Static Variables.
 */
static char vioscsi_ident[] = "VirtIO SCSI HBA driver";

static uint_t vioscsi_control_handler(caddr_t arg1, caddr_t arg2);
static uint_t vioscsi_event_handler(caddr_t arg1, caddr_t arg2);
static uint_t vioscsi_rqst_handler(caddr_t arg1, caddr_t arg2);
static int vioscsi_attach(dev_info_t *, ddi_attach_cmd_t);
static int vioscsi_detach(dev_info_t *, ddi_detach_cmd_t);
static int vioscsi_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

static int vioscsi_quiesce(dev_info_t *);

static int vioscsi_tran_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *, dev_info_t **);

static int vioscsi_tran_bus_reset(dev_info_t *hba_dip, int level);

static int vioscsi_tran_getcap(struct scsi_address *ap, char *cap, int whom);

static int vioscsi_tran_setcap(struct scsi_address *ap, char *cap, int value,
    int whom);
static int vioscsi_tran_reset(struct scsi_address *ap, int level);
static int vioscsi_tran_reset_notify(struct scsi_address *ap,
    int flag, void (*callback)(caddr_t), caddr_t arg);

static int vioscsi_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int vioscsi_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int vioscsi_tran_bus_unquiesce(dev_info_t *hba_dip);
static int vioscsi_tran_bus_quiesce(dev_info_t *hba_dip);

static int vioscsi_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int vioscsi_tran_tgt_probe(struct scsi_device *sd,
    int (*waitfunc)(void));
static void vioscsi_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);


void *vioscsi_state;

static struct dev_ops vioscsi_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = vioscsi_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = vioscsi_attach,
	.devo_detach = vioscsi_detach,
	.devo_reset = nodev,
	.devo_cb_ops = NULL,
	.devo_bus_ops = NULL,
	.devo_power = NULL,
	.devo_quiesce = vioscsi_quiesce
};

/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = vioscsi_ident,
	.drv_dev_ops = &vioscsi_dev_ops
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = {
		(void *)&modldrv,
		NULL,
	},
};

static ddi_device_acc_attr_t virtio_scsi_acc_attr = {
	.devacc_attr_version = DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC,
	.devacc_attr_dataorder = DDI_STORECACHING_OK_ACC,
	.devacc_attr_access = DDI_DEFAULT_ACC
};

/* DMA attr for the data blocks. */
static ddi_dma_attr_t virtio_scsi_data_dma_attr = {
	.dma_attr_version = DMA_ATTR_V0,
	.dma_attr_addr_lo = 0,
	.dma_attr_addr_hi = 0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max = 0x00000000FFFFFFFFull,
	.dma_attr_align = 1,
	.dma_attr_burstsizes = 1,
	.dma_attr_minxfer = 1,
	.dma_attr_maxxfer = 0xFFFFFFFFull,
	.dma_attr_seg = 0xFFFFFFFFFFFFFFFFull,
	.dma_attr_sgllen = 64,
	.dma_attr_granular = 1,
	.dma_attr_flags = 0,
};

static int
vioscsi_tran_tgt_probe(struct scsi_device *sd, int (*waitfunc)(void))
{
	return (scsi_hba_probe(sd, waitfunc));
}

static dev_info_t *
vioscsi_find_child(vioscsi_softc_t sc, uint16_t tgt, uint8_t lun)
{
	vioscsi_dev_t	*vd;

	/*
	 * Should rethink the search method if the driver needs to support
	 * more than 8 or 9 virtual drives.
	 */
	mutex_enter(&sc->vs_devs_mutex);
	for (vd = list_head(&sc->vs_devs); vd != NULL;
	     vd = list_next(&sc->vs_devs, vd)) {
		if (vd->vd_target == tgt && vd->vd_lun == lun) {
			mutex_exit(&sc->vs_devs_mutex);
			return (vd->vd_dip);
		}
	}
	mutex_exit(&sc->vs_devs_mutex);

	return (NULL);
}

static void
vioscsi_delete_child(vioscsi_softc_t sc, uint16_t tgt, uint8_t lun,
    dev_info_t *child)
{
	vioscsi_dev_t	*vd;

	mutex_enter(&sc->vs_devs_mutex);
	for (vd = list_head(&sc->vs_devs); vd != NULL;
	     vd = list_next(&sc->vs_devs, vd)) {
		if (vd->vd_target == tgt && vd->vd_lun == lun) {
			list_remove(&sc->vs_devs, vd);
			kmem_free(vd, sizeof (*vd));
			mutex_exit(&sc->vs_devs_mutex);
			return;
		}
	}
	mutex_exit(&sc->vs_devs_mutex);
}

static int
vioscsi_tran_tgt_init(dev_info_t *hba_dip,
    dev_info_t *tgt_dip, scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	vioscsi_softc_t sc = sd->sd_address.a_hba_tran->tran_hba_private;
	uint16_t tgt = sd->sd_address.a_target;
	uint8_t lun = sd->sd_address.a_lun;

	if (vioscsi_find_child(sc, tgt, lun) == NULL)
		return (DDI_FAILURE);
	else
		return (DDI_SUCCESS);
}

static void
vioscsi_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
}

static void
vioscsi_load_indirect(struct scsi_pkt *pkt, struct vq_entry *ve)
{
	int			i;
	ddi_dma_cookie_t	*dmac;

	for (i = 0; i < pkt->pkt_numcookies; i ++) {
		dmac = &pkt->pkt_cookies[i];
		virtio_ve_add_indirect_buf(ve, dmac->dmac_laddress,
		    dmac->dmac_size, pkt->pkt_dma_flags & DDI_DMA_WRITE);
	}
}

static struct vq_entry *
vioscsi_add_entry(vioscsi_softc_t sc, ddi_dma_cookie_t *dmac, boolean_t write, struct vq_entry *ve_last)
{
	struct vq_entry	*ve;

	if ((ve = vq_alloc_entry(sc->vs_rqst_vq)) == NULL) {
		dev_debug(sc->vs_dip, CE_WARN, "No more ring space");
		return (NULL);
	}

	virtio_ve_set(ve, dmac->dmac_laddress, dmac->dmac_size, write);
	virtio_ventry_stick(ve_last, ve);

	return (ve);
}

static boolean_t
vioscsi_load_ring_entries(vioscsi_softc_t sc, vioscsi_request_t req)
{
	struct vq_entry		*ve,
				*ve_head,
				*ve_last;
	vioscsi_buffer_t	req_buf = &req->vr_headers_buf;
	struct scsi_pkt		*pkt = req->vr_req_pkt;
	ddi_dma_cookie_t	*dmac;

	if ((ve = vq_alloc_entry(sc->vs_rqst_vq)) == NULL) {
		dev_debug(sc->vs_dip, CE_WARN, "No more ring space");
		return (B_FALSE);
	}

	ve->qe_private = req;
	req->vr_ve = ve;
	ve_head = ve_last = ve;
	/* ---- First the request header ---- */
	virtio_ve_set(ve, req_buf->vb_dmac.dmac_laddress,
	    sizeof (struct virtio_scsi_cmd_req), B_TRUE);

	/* ---- Now add all outgoing write buffers ---- */
	if (pkt->pkt_dma_flags & DDI_DMA_WRITE) {
		for (int i = 0; i < pkt->pkt_numcookies; i++) {
			dmac = &pkt->pkt_cookies[i];
			ve_last = vioscsi_add_entry(sc, dmac,
			    pkt->pkt_dma_flags & DDI_DMA_WRITE, ve_last);
			if (ve_last == NULL) {
				virtio_free_chain(ve_head);
				return (B_FALSE);
			}
		}
	}

	if ((ve = vq_alloc_entry(sc->vs_rqst_vq)) == NULL) {
		dev_debug(sc->vs_dip, CE_WARN, "No more ring space");
		virtio_free_chain(ve_head);
		return (B_FALSE);
	}

	/* ---- Now the SCSI sense buffer ---- */
	virtio_ve_set(ve, req_buf->vb_dmac.dmac_laddress +
	    sizeof (struct virtio_scsi_cmd_req),
	    sizeof (struct virtio_scsi_cmd_resp), B_FALSE);
	virtio_ventry_stick(ve_last, ve);
	ve_last = ve;

	/* ---- Finally any incoming read buffers ---- */
	if (pkt->pkt_dma_flags & DDI_DMA_READ) {
		for (int i = 0; i < pkt->pkt_numcookies; i++) {
			dmac = &pkt->pkt_cookies[i];
			ve_last = vioscsi_add_entry(sc, dmac,
			    pkt->pkt_dma_flags & DDI_DMA_WRITE, ve_last);
			if (ve_last == NULL) {
				virtio_free_chain(ve_head);
				return (B_FALSE);
			}
		}
	}

	virtio_push_chain(ve_head, B_TRUE);
	return (B_TRUE);
}

static int
vioscsi_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct vq_entry		*ve;
	vioscsi_request_t	req	= pkt->pkt_ha_private;
	vioscsi_softc_t		sc	= ap->a_hba_tran->tran_hba_private;
	struct virtio_scsi_cmd_req	*cmd_req;
	vioscsi_buffer_t	req_buf	= &req->vr_headers_buf;

	if (pkt->pkt_cdbp == NULL)
		return (TRAN_BADPKT);

	req->vr_req_pkt = pkt;
	cmd_req = (struct virtio_scsi_cmd_req *)req_buf->vb_virt;
	bzero(cmd_req, sizeof (*cmd_req));

	/* fill in cmd_req */
	cmd_req->lun[0] = 1;
	cmd_req->lun[1] = ap->a_target;
	cmd_req->lun[2] = 0x40;
	cmd_req->lun[3] = ap->a_lun;
	cmd_req->tag = (unsigned long)pkt;
	cmd_req->task_attr = 0;
	cmd_req->prio = 0;
	cmd_req->crn = 0;

	(void) memcpy(cmd_req->cdb, pkt->pkt_cdbp, pkt->pkt_cdblen);

	/*
	 * The KVM scsi emulation requires that all outgoing buffers
	 * are added first with the request header being the first
	 * entry. After the outgoing have been added then the incoming
	 * buffers with the response buffer being the first of the incoming.
	 * This requirement is indepentent of using chained ring entries or
	 * one ring entry with indirect buffers.
	 */
	if (sc->vs_virtio.sc_features & VIRTIO_F_RING_INDIRECT_DESC) {
		/* ---- allocate vq_entry ---- */
		if ((ve = vq_alloc_entry(sc->vs_rqst_vq)) == NULL)
			return (TRAN_BUSY);

		/* ---- add request header ---- */
		virtio_ve_add_indirect_buf(ve, req_buf->vb_dmac.dmac_laddress,
		    sizeof (struct virtio_scsi_cmd_req), B_TRUE);

		/* ---- add write buffers ---- */
		if (pkt->pkt_dma_flags & DDI_DMA_WRITE)
			vioscsi_load_indirect(pkt, ve);

		/* ---- add the response header ---- */
		virtio_ve_add_indirect_buf(ve, req_buf->vb_dmac.dmac_laddress +
		    sizeof (struct virtio_scsi_cmd_req),
		    sizeof (struct virtio_scsi_cmd_resp), B_FALSE);

		/* ---- add read buffers ---- */
		if (pkt->pkt_dma_flags & DDI_DMA_READ)
			vioscsi_load_indirect(pkt, ve);

		ve->qe_private = req;
		req->vr_ve = ve;
		sc->vs_poll_done = B_FALSE;

		/* ---- push vq_entry into the queue ---- */
		virtio_push_chain(ve, B_TRUE);
	} else {
		if (vioscsi_load_ring_entries(sc, req) == B_FALSE)
			return (TRAN_BUSY);
	}

	if (pkt->pkt_flags & FLAG_NOINTR) {
		int32_t	one_sec_wait = MICROSEC / 10;
		/* ---- disable interrupts for a while ---- */
		virtio_stop_vq_intr(sc->vs_rqst_vq);

		while (sc->vs_poll_done == B_FALSE && one_sec_wait--) {
			(void) vioscsi_rqst_handler((caddr_t)&sc->vs_virtio,
			    NULL);
			drv_usecwait(10);
		}

		/* ---- After vioscsi_rqst_handler don't touch req ---- */
		virtio_start_vq_intr(sc->vs_rqst_vq);
	}

	return (TRAN_ACCEPT);
}

static int
vioscsi_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	return (DDI_FAILURE);
}

static void
vioscsi_buffer_release(vioscsi_buffer_t vb)
{
	if (vb->vb_state != VIOSCSI_BUFFER_ALLOCATED)
		return;

	(void) ddi_dma_unbind_handle(vb->vb_dmah);

	if (vb->vb_acch)
		(void) ddi_dma_mem_free(&vb->vb_acch);

	(void) ddi_dma_free_handle(&vb->vb_dmah);

	vb->vb_state = VIOSCSI_BUFFER_FREE;
}

static int
vioscsi_buffer_setup(vioscsi_softc_t sc, vioscsi_buffer_t vb, size_t vb_size,
    int kmflags)
{
	size_t	len;
	int	(*cb) (caddr_t);

	cb = (kmflags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;
	if (vb->vb_state != VIOSCSI_BUFFER_FREE)
		return (DDI_FAILURE);

	if (ddi_dma_alloc_handle(sc->vs_dip, &virtio_scsi_data_dma_attr,
	    cb, NULL, &vb->vb_dmah) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (ddi_dma_mem_alloc(vb->vb_dmah, vb_size, &virtio_scsi_acc_attr,
	    DDI_DMA_STREAMING, cb, NULL, &vb->vb_virt, &len,
	    &vb->vb_acch) != DDI_SUCCESS) {
		goto unbind_handle;
	}
	ASSERT3U(len, >=, (sizeof (struct virtio_scsi_cmd_req) +
	    sizeof (struct virtio_scsi_cmd_resp)));
	bzero(vb->vb_virt, len);

	if (ddi_dma_addr_bind_handle(vb->vb_dmah, NULL, vb->vb_virt,
	    len, DDI_DMA_READ | DDI_DMA_WRITE, cb, NULL,
	    &vb->vb_dmac, &vb->vb_ncookies) != DDI_SUCCESS) {
		goto release_dma_mem;
	}
	vb->vb_state = VIOSCSI_BUFFER_ALLOCATED;

	return (DDI_SUCCESS);

release_dma_mem:
	(void) ddi_dma_mem_free(&vb->vb_acch);

unbind_handle:
	(void) ddi_dma_unbind_handle(vb->vb_dmah);

	return (DDI_FAILURE);
}

static int
vioscsi_req_construct(void *buffer, void *user_arg, int kmflags)
{
	vioscsi_softc_t sc = user_arg;
	vioscsi_request_t req = buffer;
	vioscsi_buffer_t buf;

	buf = &req->vr_headers_buf;

	buf->vb_state = VIOSCSI_BUFFER_FREE;

	/* allocate DMA resources for the vioscsi headers */
	/* SCSA will allocate the rest */
	if (vioscsi_buffer_setup(sc, buf,
	    sizeof (struct virtio_scsi_cmd_req) +
	    sizeof (struct virtio_scsi_cmd_resp), kmflags) != DDI_SUCCESS)
		return (ENOMEM);

	return (0);
}

static void
virtio_scsi_req_destruct(void *buffer, void *user_args)
{
	vioscsi_request_t req = buffer;

	vioscsi_buffer_release(&req->vr_headers_buf);
}

static int
vioscsi_tran_setup_pkt(struct scsi_pkt *pkt,
    int (*callback)(caddr_t), caddr_t arg)
{
	/*
	 * Nothing to do here, but having this function serves two purposes.
	 * 1) At some point in the future it might be desirable to due
	 *    some initial processing.
	 * 2) By providing a tran_setup_pkt routine to the SCSA layer that
	 *    causes SCSA to provide a generic init_pkt and destroy_pkt
	 *    functions that perform the grunge work of allocation and getting
	 *    DMA cookies.
	 */
	return (0);
}

static void
vioscsi_tran_teardown_pkt(struct scsi_pkt *pkt)
{
	/* nothing to do. resources will be released by packet destructor */
}

static int
vioscsi_tran_pkt_constructor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran,
    int kmflags)
{
	vioscsi_request_t	req	= pkt->pkt_ha_private;
	vioscsi_softc_t		sc	= tran->tran_hba_private;

	(void) memset(req, 0, sizeof (*req));

	return (vioscsi_req_construct(req, sc, kmflags));
}

static void
vioscsi_tran_pkt_destructor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran)
{
	vioscsi_request_t req = pkt->pkt_ha_private;
	vioscsi_softc_t sc = tran->tran_hba_private;

	virtio_scsi_req_destruct(req, sc);
}

static int
vioscsi_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int rval = 0;
	vioscsi_softc_t sc = ap->a_hba_tran->tran_hba_private;

	if (cap == NULL)
		return (-1);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_CDB_LEN:
		rval = sc->vs_cdb_size;
		break;

	case SCSI_CAP_ARQ:
		rval = 1;
		break;

	case SCSI_CAP_LUN_RESET:
		rval = 1;
		break;

	case SCSI_CAP_UNTAGGED_QING:
		rval = 1;
		break;

	default:
		rval = -1;
	}
	return (rval);
}

static int
vioscsi_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int rval = 1;

	if (cap == NULL || whom == 0)
		return (-1);

	switch (scsi_hba_lookup_capstr(cap)) {
		default:
			rval = 1;
	}
	return (rval);
}

static int
vioscsi_tran_reset(struct scsi_address *ap, int level)
{
	/* TODO: implement RESET for VIRTIO SCSI */
	return (DDI_FAILURE);
}

static int
vioscsi_tran_reset_notify(struct scsi_address *ap, int flags,
    void (*callback)(caddr_t), caddr_t arg)
{
	/* TODO: implement RESET for VIRTIO SCSI */
	return (DDI_FAILURE);
}

static boolean_t
vioscsi_send_pkt(struct scsi_pkt *pkt)
{
	*pkt->pkt_scbp = pkt->pkt_reason = pkt->pkt_state = 0;
	if (scsi_transport(pkt) == TRAN_ACCEPT &&
	    pkt->pkt_reason == CMD_CMPLT &&
	    (*pkt->pkt_scbp & STATUS_MASK) == STATUS_GOOD) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

#define	ROUTE	(&sd->sd_address)
static boolean_t
vioscsi_probe_lun(struct scsi_device *sd)
{
	struct scsi_pkt	*tur_pkt = NULL;
	struct buf	*tur_bp = NULL;

	if ((tur_bp = scsi_alloc_consistent_buf(ROUTE, NULL, SUN_INQSIZE,
	    B_READ, NULL_FUNC, NULL)) == NULL) {
		goto error;
	}

	if ((tur_pkt = scsi_init_pkt(ROUTE, NULL, tur_bp, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, PKT_CONSISTENT, NULL_FUNC,
	    NULL)) == NULL) {
		goto error;
	}
	(void) scsi_setup_cdb((union scsi_cdb *)tur_pkt->pkt_cdbp,
	    SCMD_TEST_UNIT_READY, 0, 0, 0);
	tur_pkt->pkt_flags = FLAG_NOINTR | FLAG_NOPARITY;
	if (vioscsi_send_pkt(tur_pkt) == B_FALSE)
		return (B_FALSE);

	return ((scsi_hba_probe(sd, NULL_FUNC) == SCSIPROBE_EXISTS) ? B_TRUE :
	    B_FALSE);
error:
	if (tur_bp != NULL)
		scsi_free_consistent_buf(tur_bp);
	if (tur_pkt != NULL)
		scsi_destroy_pkt(tur_pkt);
	return (B_FALSE);
}

static int
vioscsi_config_child(vioscsi_softc_t sc, struct scsi_device *sd,
    dev_info_t **ddip)
{
	char		*nodename	= NULL,
			**compatible	= NULL;
	dev_info_t	*ldip		= NULL;
	int		tgt		= sd->sd_address.a_target,
			lun		= sd->sd_address.a_lun,
			dtype		= sd->sd_inq->inq_dtype & DTYPE_MASK,
			ncompatible	= 0;
	vioscsi_dev_t	*vd;

	scsi_hba_nodename_compatible_get(sd->sd_inq, NULL, dtype, NULL,
	    &nodename, &compatible, &ncompatible);

	if (nodename == NULL)
		return (NDI_FAILURE);

	if (ndi_devi_alloc(sc->vs_dip, nodename, DEVI_SID_NODEID, &ldip) !=
	    NDI_SUCCESS) {
		goto free_nodename;
	}

	/*
	 * Need to allocate and link in the vioscsi_dev structure before
	 * any other calls to the NDI API takes place. In particular,
	 * ndi_devi_online which will issue SCSI commands to the driver. If
	 * this is not done the driver will not be able to find/validate the
	 * target/lun pair when starting the SCSI commands. The only downside
	 * of allocating and linking here is that if an error occurs during
	 * the clean up the structure will need to be removed and freed.
	 */
	vd = kmem_alloc(sizeof (*vd), KM_SLEEP);
	vd->vd_dip = ldip;
	vd->vd_target = tgt;
	vd->vd_lun = lun;
	mutex_enter(&sc->vs_devs_mutex);
	list_insert_tail(&sc->vs_devs, vd);
	mutex_exit(&sc->vs_devs_mutex);

	if (ndi_prop_update_string(DDI_DEV_T_NONE, ldip, "device-type",
	    "scsi") != DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, TARGET_PROP,
	    tgt) != DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, LUN_PROP, lun) !=
	    DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (ndi_prop_update_int64(DDI_DEV_T_NONE, ldip, LUN64_PROP,
	    (int64_t)lun) != DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, ldip, COMPAT_PROP,
	    compatible, ncompatible) != DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "pm-capable", 1) !=
	    DDI_PROP_SUCCESS) {
		goto free_devi;
	}

	if (ndi_devi_online(ldip, NDI_ONLINE_ATTACH) != NDI_SUCCESS)
		goto free_devi;

	if (ddip)
		*ddip = ldip;

	scsi_hba_nodename_compatible_free(nodename, compatible);

	return (NDI_SUCCESS);

free_devi:
	ndi_prop_remove_all(ldip);
	(void) ndi_devi_free(ldip);

	mutex_enter(&sc->vs_devs_mutex);
	list_remove(&sc->vs_devs, vd);
	mutex_exit(&sc->vs_devs_mutex);
	kmem_free(vd, sizeof (*vd));

free_nodename:
	scsi_hba_nodename_compatible_free(nodename, compatible);
	return (NDI_FAILURE);
}

static int
vioscsi_config_lun(vioscsi_softc_t sc, int tgt, uint8_t lun,
    dev_info_t **ldip)
{
	struct scsi_device	sd;
	dev_info_t		*child;
	boolean_t		probe_rval;
	int			err;

	bzero(&sd, sizeof (sd));
	sd.sd_inq = kmem_alloc(SUN_INQSIZE, KM_SLEEP);
	sd.sd_address.a_hba_tran = sc->vs_hba_tran;
	sd.sd_address.a_target = (uint16_t)tgt;
	sd.sd_address.a_lun = (uint8_t)lun;

	probe_rval = vioscsi_probe_lun(&sd);

	if ((child = vioscsi_find_child(sc, tgt, lun)) != NULL) {
		if (probe_rval == B_FALSE) {
			(void) ndi_devi_offline(child,
			    NDI_DEVFS_CLEAN | NDI_DEVI_REMOVE | NDI_DEVI_GONE);
			vioscsi_delete_child(sc, tgt, lun, child);
			err = NDI_FAILURE;
		} else {
			if (ldip != NULL)
				*ldip = child;
			err = NDI_SUCCESS;
		}
	} else if (probe_rval == B_FALSE) {
		err = NDI_FAILURE;
	} else {
		err = vioscsi_config_child(sc, &sd, ldip);
	}
	kmem_free(sd.sd_inq, SUN_INQSIZE);
	return (err);
}

static boolean_t
vioscsi_scsi_parse_devname(char *devnm, int *tgt, int *lun)
{
	char devbuf[SCSI_MAXNAMELEN];
	char *addr;
	char *p, *tp, *lp;
	long num;

	(void) strcpy(devbuf, devnm);
	addr = "";

	for (p = devbuf; *p != '\0'; p ++) {
		if (*p == '@') {
			addr = p + 1;
			*p = '\0';
		} else if (*p == ':') {
			*p = '\0';
			break;
		}
	}
	for (p = tp = addr, lp = NULL; *p != '\0'; p ++) {
		if (*p == ',') {
			lp = p + 1;
			*p = '\0';
			break;
		}
	}
	if (tgt != NULL && tp != NULL) {
		if (ddi_strtol(tp, NULL, 0x10, &num)) {
			return (B_FALSE);
		}
		*tgt = (int)num;
	}
	if (lun != NULL && lp != NULL) {
		if (ddi_strtol(lp, NULL, 0x10, &num)) {
			return (B_FALSE);
		}
		*lun = (int)num;
	}
	return (B_TRUE);
}

static int
vioscsi_tran_bus_config(dev_info_t *hba_dip, uint_t flags,
    ddi_bus_config_op_t op,  void *arg, dev_info_t **childs)
{
	vioscsi_softc_t	sc;
	int		circ,
			ret	= NDI_SUCCESS,
			tgt,
			lun;

	if ((sc = ddi_get_soft_state(vioscsi_state,
	    ddi_get_instance(hba_dip))) == NULL) {
		return (NDI_FAILURE);
	}

	ndi_devi_enter(hba_dip, &circ);

	switch (op) {
	case BUS_CONFIG_ONE:
		if (strchr((char *)arg, '@') == NULL) {
			ret = DDI_FAILURE;
			break;
		}

		if (vioscsi_scsi_parse_devname(arg, &tgt, &lun) == B_TRUE)
			ret = vioscsi_config_lun(sc, tgt, lun, childs);
		else
			ret = NDI_FAILURE;
		break;

	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL:
		for (tgt = 0; tgt < sc->vs_max_target; tgt++)
			for (lun = 0; lun  < sc->vs_max_lun; lun++)
				(void) vioscsi_config_lun(sc, tgt, lun, NULL);

		break;

	default:
		ret = NDI_FAILURE;
		break;
	}

	if (ret == NDI_SUCCESS)
		ret = ndi_busop_bus_config(hba_dip, flags, op, arg, childs, 0);
	ndi_devi_exit(hba_dip, circ);

	return (ret);
}

static int
vioscsi_tran_bus_reset(dev_info_t *hba_dip, int level)
{
	/* ---- TODO: implement bus reset? ---- */
	return (DDI_FAILURE);
}

static int
vioscsi_tran_bus_quiesce(dev_info_t *hba_dip)
{
	/*
	 * TODO: although virtual scsi bus cannot be quiesced
	 * probalby we need to stop putting requests into the VQ
	 * and notify the host SCSI bus somehow that we are stopped.
	 * not sure if current virtio SCSI  provides such a capability
	 */
	printf("%s: called!\n", __FUNCTION__);
	return (DDI_SUCCESS);
}

static int
vioscsi_tran_bus_unquiesce(dev_info_t *hba_dip)
{
	/* TODO: the same comment as for virtio_tran_bus_quiesce */
	printf("%s: called!\n", __FUNCTION__);
	return (DDI_SUCCESS);
}

uint_t
vioscsi_control_handler(caddr_t arg1, caddr_t arg2)
{
	cmn_err(CE_WARN, "%s: Unhandled control interrupt", __func__);
	return (DDI_INTR_CLAIMED);
}

uint_t
vioscsi_event_handler(caddr_t arg1, caddr_t arg2)
{
	cmn_err(CE_WARN, "%s: Unhandled event interrupt", __func__);
	return (DDI_INTR_CLAIMED);
}

uint_t
vioscsi_rqst_handler(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *) arg1;
	vioscsi_softc_t sc = container_of(vsc, struct vioscsi_softc, vs_virtio);
	struct vq_entry *ve;
	vioscsi_request_t req;
	struct virtio_scsi_cmd_resp *resp;
	struct scsi_arq_status *arqstat;
	struct scsi_pkt *pkt;
	uint32_t len;
	vioscsi_buffer_t req_buf = NULL;

	/* TODO: push request into the ready queue and schedule taskq */
	while ((ve = virtio_pull_chain(sc->vs_rqst_vq, &len))) {
		if ((req = ve->qe_private) == NULL) {
			/* ---- DEBUG ---- */
			cmn_err(CE_WARN, "%s: qe_private(%p) is NULL",
			    __func__, (void *)ve);
			return (DDI_INTR_CLAIMED);
		}

		ve->qe_private = NULL;
		pkt = req->vr_req_pkt;
		req_buf = &req->vr_headers_buf;

		resp = (struct virtio_scsi_cmd_resp *)(req_buf->vb_virt +
		    sizeof (struct virtio_scsi_cmd_req));

		switch (resp->response) {

		/*
		 * virtio scsi processes request sucessfully, check the
		 * request SCSI status
		 */
		case VIRTIO_SCSI_S_OK:

			switch (resp->status) {
			case 0:
				/* ---- request processed by host SCSI ---- */
				pkt->pkt_scbp[0] = STATUS_GOOD;
				break;

			default:
				/*CSTYLED*/
				((struct scsi_status *)pkt->pkt_scbp)->sts_chk = 1;
				if (pkt->pkt_cdbp[0] != SCMD_TEST_UNIT_READY) {
					pkt->pkt_state |= STATE_ARQ_DONE;
					arqstat = (void *)(pkt->pkt_scbp);
					arqstat->sts_rqpkt_reason = CMD_CMPLT;
					arqstat->sts_rqpkt_resid = 0;
					arqstat->sts_rqpkt_state =
					    STATE_GOT_BUS | STATE_GOT_TARGET |
					    STATE_SENT_CMD | STATE_XFERRED_DATA;
					*(uint8_t *)&arqstat->sts_rqpkt_status =
					    STATUS_GOOD;
					(void) memcpy(&arqstat->sts_sensedata,
					    resp->sense, resp->sense_len);
				}
			}
			pkt->pkt_resid = 0;
			pkt->pkt_state |= STATE_XFERRED_DATA;
			pkt->pkt_reason = CMD_CMPLT;
			break;

		case VIRTIO_SCSI_S_BAD_TARGET:
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case VIRTIO_SCSI_S_OVERRUN:
			dev_debug(sc->vs_dip, CE_WARN, "OVERRUN");
			pkt->pkt_reason = CMD_DATA_OVR;
			break;

		default:
			dev_debug(sc->vs_dip, CE_WARN, "Unknown response: 0x%x",
			    resp->response);
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;
		}

		/*
		 * if packet is processed in polling mode - notify the caller
		 * that it may done no races, because in this case we are not
		 * invoked by virtio interrupt
		 */
		sc->vs_poll_done = B_TRUE;

		virtio_free_chain(ve);
		scsi_hba_pkt_comp(pkt);
		/* ---- Don't touch req after here ---- */
	}
	return (DDI_INTR_CLAIMED);
}

static uint_t
vioscsi_config_handler(caddr_t arg1, caddr_t arg2)
{
	cmn_err(CE_WARN, "%s: noop", __func__);
	return (DDI_INTR_CLAIMED);
}

static int
vioscsi_register_ints(vioscsi_softc_t sc)
{
	int ret;

	struct virtio_int_handler vioscsi_conf_h = {
		vioscsi_config_handler
	};

	struct virtio_int_handler virtio_scsi_intr_h[] = {
		{ vioscsi_control_handler },
		{ vioscsi_event_handler },
		{ vioscsi_rqst_handler },
		{ NULL },
	};

	ret = virtio_register_ints(&sc->vs_virtio,
	    &vioscsi_conf_h, virtio_scsi_intr_h);

	return (ret);
}

static int
vioscsi_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	int	rval		= DDI_SUCCESS,
		minor		= getminor((dev_t)arg);
	vioscsi_softc_t sc;

	if ((sc = ddi_get_soft_state(vioscsi_state,
	    ddi_get_instance(dip))) == NULL) {
		return (NDI_FAILURE);
	}

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = sc->vs_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(intptr_t)(MINOR2INST(minor));
		break;

	default:
		rval = DDI_FAILURE;
		*resultp = NULL;
	}
	return (rval);
}

static void
vioscsi_show_features(const char *prefix, uint32_t features)
{
	char	buf[512],
		*bufp	= buf,
		*bufend	= buf + sizeof (buf);

	bufp += snprintf(bufp, bufend - bufp, prefix);

	bufp += virtio_show_features(features, bufp, bufend - bufp);

	bufp += snprintf(bufp, bufend - bufp, "Vioscsi (0x%x ", features);

	if (features & VIRTIO_SCSI_F_INOUT)
		bufp += snprintf(bufp, bufend - bufp, "INOUT ");
	if (features & VIRTIO_SCSI_F_HOTPLUG)
		bufp += snprintf(bufp, bufend - bufp, "HOTPLUG ");
	if (features & VIRTIO_SCSI_F_CHANGE)
		bufp += snprintf(bufp, bufend - bufp, "CHANGE ");
	if (features & VIRTIO_SCSI_F_T10_PI)
		bufp += snprintf(bufp, bufend - bufp, "T10-PI ");

	bufp += snprintf(bufp, bufend - bufp, ")");
	*bufp = '\0';

	cmn_err(CE_NOTE, "%s", buf);
}


static int
vioscsi_dev_features(vioscsi_softc_t sc)
{
	uint32_t host_features;

	host_features = virtio_negotiate_features(&sc->vs_virtio,
	    VIRTIO_SCSI_F_INOUT | VIRTIO_SCSI_F_HOTPLUG |
	    VIRTIO_SCSI_F_CHANGE | VIRTIO_SCSI_F_T10_PI |
	    VIRTIO_F_RING_INDIRECT_DESC);

	vioscsi_show_features("Host features: ", host_features);
	vioscsi_show_features("Negotiated features: ",
	    sc->vs_virtio.sc_features);

	if (!(sc->vs_virtio.sc_features & VIRTIO_F_RING_INDIRECT_DESC)) {
		dev_err(sc->vs_dip, CE_NOTE,
		    "Host does not support RING_INDIRECT_DESC");
	}

	return (DDI_SUCCESS);
}

static int
vioscsi_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int			ret		 = DDI_SUCCESS,
				instance,
				indirect_count;
	vioscsi_softc_t		sc;
	struct virtio_softc	*vsc;
	scsi_hba_tran_t		*hba_tran;

	instance = ddi_get_instance(devinfo);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		ret = DDI_FAILURE;
		break;

	default:
		ret = DDI_FAILURE;
		break;
	}
	if (ret != DDI_SUCCESS)
		return (ret);

	if (ddi_soft_state_zalloc(vioscsi_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if ((sc = ddi_get_soft_state(vioscsi_state, instance)) == NULL)
		return (DDI_FAILURE);

	vsc = &sc->vs_virtio;

	/* ---- Duplicate for faster access / less typing ---- */
	sc->vs_dip = devinfo;
	vsc->sc_dev = devinfo;
	list_create(&sc->vs_devs, sizeof (struct vioscsi_dev),
	    offsetof(struct vioscsi_dev, vd_node));
	mutex_init(&sc->vs_devs_mutex, NULL, MUTEX_DRIVER, NULL);

	/* ---- map BAR0 ---- */
	ret = ddi_regs_map_setup(devinfo, 1,
	    (caddr_t *)&sc->vs_virtio.sc_io_addr, 0, 0, &virtio_scsi_acc_attr,
	    &sc->vs_virtio.sc_ioh);

	if (ret != DDI_SUCCESS) {
		goto exit_sc;
	}

	virtio_device_reset(&sc->vs_virtio);
	virtio_set_status(&sc->vs_virtio, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(&sc->vs_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	if (vioscsi_register_ints(sc)) {
		goto enable_intrs_fail;
	}

	sc->vs_max_target = min(VIOSCSI_MAX_TARGET,
	    virtio_read_device_config_2(&sc->vs_virtio,
	    VIRTIO_SCSI_CFG_MAX_TARGET));

	sc->vs_max_lun = min(VIOSCSI_MAX_LUN,
	    virtio_read_device_config_4(&sc->vs_virtio,
	    VIRTIO_SCSI_CFG_MAX_LUN));

	sc->vs_max_channel = virtio_read_device_config_4(&sc->vs_virtio,
	    VIRTIO_SCSI_CFG_MAX_CHANNEL);

	sc->vs_max_req = sc->vs_max_lun *
		virtio_read_device_config_4(&sc->vs_virtio,
			VIRTIO_SCSI_CFG_CMD_PER_LUN);

	sc->vs_cdb_size = virtio_read_device_config_4(&sc->vs_virtio,
	    VIRTIO_SCSI_CFG_CDB_SIZE);

	sc->vs_max_seg = virtio_read_device_config_4(&sc->vs_virtio,
	    VIRTIO_SCSI_CFG_SEG_MAX);

	if (vioscsi_dev_features(sc))
		goto enable_intrs_fail;

	/* allocate queues */

	if (sc->vs_virtio.sc_features & VIRTIO_F_RING_INDIRECT_DESC) {
		/* ---- 128 indirect descriptors seems to be enough ---- */
		indirect_count = 128;
	} else {
		indirect_count = 0;
	}

	if ((sc->vs_ctrl_vq = virtio_alloc_vq(&sc->vs_virtio, 0,
	    0, indirect_count, "Virtio SCSI control queue")) == NULL) {
		goto enable_intrs_fail;
	}
	if ((sc->vs_event_vq = virtio_alloc_vq(&sc->vs_virtio, 1,
	    0, indirect_count, "Virtio SCSI event queue")) == NULL) {
		goto release_control;
	}
	if ((sc->vs_rqst_vq = virtio_alloc_vq(&sc->vs_virtio, 2,
	    0, indirect_count, "Virtio SCSI request queue")) == NULL) {
		goto release_event;
	}

	hba_tran = scsi_hba_tran_alloc(devinfo, SCSI_HBA_CANSLEEP);

	sc->vs_hba_tran = hba_tran;

	hba_tran->tran_hba_len = sizeof (struct vioscsi_request);
	hba_tran->tran_hba_private = sc;
	hba_tran->tran_tgt_private = NULL;
	hba_tran->tran_tgt_init = vioscsi_tran_tgt_init;
	hba_tran->tran_tgt_probe = vioscsi_tran_tgt_probe;
	hba_tran->tran_tgt_free = vioscsi_tran_tgt_free;

	hba_tran->tran_start = vioscsi_tran_start;
	hba_tran->tran_abort = vioscsi_tran_abort;
	hba_tran->tran_reset = vioscsi_tran_reset;
	hba_tran->tran_getcap = vioscsi_tran_getcap;
	hba_tran->tran_setcap = vioscsi_tran_setcap;

	hba_tran->tran_setup_pkt = vioscsi_tran_setup_pkt;
	hba_tran->tran_teardown_pkt = vioscsi_tran_teardown_pkt;
	hba_tran->tran_pkt_constructor = vioscsi_tran_pkt_constructor;
	hba_tran->tran_pkt_destructor = vioscsi_tran_pkt_destructor;

	hba_tran->tran_reset_notify = vioscsi_tran_reset_notify;
	hba_tran->tran_quiesce = vioscsi_tran_bus_quiesce;
	hba_tran->tran_unquiesce = vioscsi_tran_bus_unquiesce;
	hba_tran->tran_bus_reset = vioscsi_tran_bus_reset;
	hba_tran->tran_bus_config = vioscsi_tran_bus_config;

	ret = scsi_hba_attach_setup(devinfo, &virtio_scsi_data_dma_attr,
	    hba_tran, SCSI_HBA_TRAN_CLONE | SCSI_HBA_TRAN_CDB |
	    SCSI_HBA_TRAN_SCB);
	if (ret != DDI_SUCCESS) {
		goto release_request;
	}

	ddi_report_dev(devinfo);

	virtio_set_status(&sc->vs_virtio,
	    VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);
	virtio_start_vq_intr(sc->vs_ctrl_vq);
	virtio_start_vq_intr(sc->vs_event_vq);
	virtio_start_vq_intr(sc->vs_rqst_vq);

	ret = virtio_enable_ints(&sc->vs_virtio);

	return (DDI_SUCCESS);

release_request:
	virtio_free_vq(sc->vs_rqst_vq);

release_event:
	virtio_free_vq(sc->vs_event_vq);

release_control:
	virtio_free_vq(sc->vs_ctrl_vq);

enable_intrs_fail:
	ddi_regs_map_free(&sc->vs_virtio.sc_ioh);

exit_sc:
	ddi_soft_state_free(vioscsi_state, instance);
	return (DDI_FAILURE);
}

static int vioscsi_quiesce(dev_info_t *devinfo)
{
	return (DDI_SUCCESS);
}

static int
vioscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vioscsi_softc_t sc;
	int		instance;

	instance = ddi_get_instance(dip);
	if ((sc = ddi_get_soft_state(vioscsi_state, instance)) == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_PM_SUSPEND:
		cmn_err(CE_WARN, "suspend not supported yet");
		return (DDI_FAILURE);

	default:
		cmn_err(CE_WARN, "cmd 0x%x unrecognized", cmd);
		return (DDI_FAILURE);
	}

	virtio_stop_vq_intr(sc->vs_rqst_vq);

	virtio_release_ints(&sc->vs_virtio);

	if (scsi_hba_detach(dip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	virtio_free_vq(sc->vs_rqst_vq);
	virtio_free_vq(sc->vs_event_vq);
	virtio_free_vq(sc->vs_ctrl_vq);
	mutex_destroy(&sc->vs_devs_mutex);

	ddi_soft_state_free(vioscsi_state, instance);

	return (DDI_SUCCESS);
}

int
_init(void)
{
	int err = 0;

	if ((err = ddi_soft_state_init(&vioscsi_state,
	    sizeof (struct vioscsi_softc), 1)) != 0) {
		return (err);
	}

	if ((err = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&vioscsi_state);
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&vioscsi_state);
		scsi_hba_fini(&modlinkage);
		return (err);
	}

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	scsi_hba_fini(&modlinkage);

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
