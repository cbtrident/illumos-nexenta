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
 * Copyright (c) 2009-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */



/*
 * Source file containing the implementation of the Transmit
 * Path
 */

#include <oce_impl.h>

static void oce_free_wqed(struct oce_wq *wq,  oce_wqe_desc_t *wqed);
static int oce_map_wqe(struct oce_wq *wq, oce_wqe_desc_t *wqed,
    mblk_t *mp, uint32_t pkt_len);
static int oce_bcopy_wqe(struct oce_wq *wq, oce_wqe_desc_t *wqed, mblk_t *mp,
    uint32_t pkt_len);
static inline oce_wq_bdesc_t *oce_wqb_alloc(struct oce_wq *wq);
static void oce_wqb_free(struct oce_wq *wq, oce_wq_bdesc_t *wqbd);

static void oce_wqmd_free(struct oce_wq *wq, oce_wq_mdesc_t *wqmd);
static void oce_wqm_free(struct oce_wq *wq, oce_wq_mdesc_t *wqmd);
static inline oce_wq_mdesc_t *oce_wqm_alloc(struct oce_wq *wq);
static int oce_wqm_ctor(oce_wq_mdesc_t *wqmd, struct oce_wq *wq);
static void oce_wqm_dtor(struct oce_wq *wq, oce_wq_mdesc_t *wqmd);
static void oce_fill_ring_descs(struct oce_wq *wq, oce_wqe_desc_t *wqed);
static inline int oce_process_tx_compl(struct oce_wq *wq, boolean_t rearm);


/*
 * WQ map handle destructor
 *
 * wq - Pointer to WQ structure
 * wqmd - pointer to WQE mapping handle descriptor
 *
 * return none
 */

static void
oce_wqm_dtor(struct oce_wq *wq, oce_wq_mdesc_t *wqmd)
{
	_NOTE(ARGUNUSED(wq));
	/* Free the DMA handle */
	if (wqmd->dma_handle != NULL)
		(void) ddi_dma_free_handle(&(wqmd->dma_handle));
	wqmd->dma_handle = NULL;
} /* oce_wqm_dtor */

/*
 * WQ map handles contructor
 *
 * wqmd - pointer to WQE mapping handle descriptor
 * wq - Pointer to WQ structure
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
static int
oce_wqm_ctor(oce_wq_mdesc_t *wqmd, struct oce_wq *wq)
{
	struct oce_dev *dev;
	int ret;
	ddi_dma_attr_t tx_map_attr = {0};

	dev = wq->parent;
	/* Populate the DMA attributes structure */
	tx_map_attr.dma_attr_version	= DMA_ATTR_V0;
	tx_map_attr.dma_attr_addr_lo	= 0x0000000000000000ull;
	tx_map_attr.dma_attr_addr_hi	= 0xFFFFFFFFFFFFFFFFull;
	tx_map_attr.dma_attr_count_max	= 0x00000000FFFFFFFFull;
	tx_map_attr.dma_attr_align		= OCE_TXMAP_ALIGN;
	tx_map_attr.dma_attr_burstsizes = 0x000007FF;
	tx_map_attr.dma_attr_minxfer	= 0x00000001;
	tx_map_attr.dma_attr_maxxfer	= 0x00000000FFFFFFFFull;
	tx_map_attr.dma_attr_seg		= 0xFFFFFFFFFFFFFFFFull;
	tx_map_attr.dma_attr_sgllen		= OCE_MAX_TXDMA_COOKIES;
	tx_map_attr.dma_attr_granular	= 0x00000001;

	if (DDI_FM_DMA_ERR_CAP(dev->fm_caps)) {
		tx_map_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
	}
	/* Allocate DMA handle */
	ret = ddi_dma_alloc_handle(dev->dip, &tx_map_attr,
	    DDI_DMA_DONTWAIT, NULL, &wqmd->dma_handle);

	return (ret);
} /* oce_wqm_ctor */

/*
 * function to create WQ mapping handles cache
 *
 * wq - pointer to WQ structure
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
int
oce_wqm_cache_create(struct oce_wq *wq)
{
	struct oce_dev *dev = wq->parent;
	int size;
	int cnt;
	int ret;

	size = wq->cfg.nhdl * sizeof (oce_wq_mdesc_t);
	wq->wq_mdesc_array = kmem_zalloc(size, KM_NOSLEEP);
	if (wq->wq_mdesc_array == NULL) {
		return (DDI_FAILURE);
	}

	wq->wqm_freelist =
	    kmem_zalloc(wq->cfg.nhdl * sizeof (oce_wq_mdesc_t *), KM_NOSLEEP);
	if (wq->wqm_freelist == NULL) {
		kmem_free(wq->wq_mdesc_array, size);
		return (DDI_FAILURE);
	}

	for (cnt = 0; cnt < wq->cfg.nhdl; cnt++) {
		ret = oce_wqm_ctor(&wq->wq_mdesc_array[cnt], wq);
		if (ret != DDI_SUCCESS) {
			goto wqm_fail;
		}
		wq->wqm_freelist[cnt] = &wq->wq_mdesc_array[cnt];
		atomic_inc_32(&wq->wqm_free);
	}

	wq->wqmd_next_free = 0;
	wq->wqmd_rc_head = 0;

	mutex_init(&wq->wqm_alloc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->intr_pri));
	mutex_init(&wq->wqm_free_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->intr_pri));
	return (DDI_SUCCESS);

wqm_fail:
	oce_wqm_cache_destroy(wq);
	return (DDI_FAILURE);
}

/*
 * function to destroy WQ mapping handles cache
 *
 * wq - pointer to WQ structure
 *
 * return none
 */
void
oce_wqm_cache_destroy(struct oce_wq *wq)
{
	oce_wq_mdesc_t *wqmd;

	while ((wqmd = oce_wqm_alloc(wq)) != NULL) {
		oce_wqm_dtor(wq, wqmd);
	}

	mutex_destroy(&wq->wqm_alloc_lock);
	mutex_destroy(&wq->wqm_free_lock);
	kmem_free(wq->wqm_freelist,
	    wq->cfg.nhdl * sizeof (oce_wq_mdesc_t *));
	kmem_free(wq->wq_mdesc_array,
	    wq->cfg.nhdl * sizeof (oce_wq_mdesc_t));
}

/*
 * function to create  WQ buffer cache
 *
 * wq - pointer to WQ structure
 * buf_size - size of the buffer
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
int
oce_wqb_cache_create(struct oce_wq *wq, size_t buf_size)
{
	struct oce_dev *dev = wq->parent;
	oce_wq_bdesc_t *wqbd;
	uint64_t paddr;
	caddr_t  vaddr;
	int size;
	int bufs_per_cookie = 0;
	int tidx = 0;
	int ncookies = 0;
	int i = 0;
	ddi_dma_cookie_t cookie;
	ddi_dma_attr_t tx_buf_attr = {0};
	int ret;

	size = wq->cfg.nbufs * sizeof (oce_wq_bdesc_t);
	wq->wq_bdesc_array = kmem_zalloc(size, KM_NOSLEEP);
	if (wq->wq_bdesc_array == NULL) {
		return (DDI_FAILURE);
	}

	wq->wqb_freelist =
	    kmem_zalloc(wq->cfg.nbufs * sizeof (oce_wq_bdesc_t *), KM_NOSLEEP);
	if (wq->wqb_freelist == NULL) {
		kmem_free(wq->wq_bdesc_array,
		    wq->cfg.nbufs * sizeof (oce_wq_bdesc_t));
		return (DDI_FAILURE);
	}

	size = wq->cfg.nbufs * wq->cfg.buf_size;

	/* Populate dma attributes */
	tx_buf_attr.dma_attr_version	= DMA_ATTR_V0;
	tx_buf_attr.dma_attr_addr_lo	= 0x0000000000000000ull;
	tx_buf_attr.dma_attr_addr_hi	= 0xFFFFFFFFFFFFFFFFull;
	tx_buf_attr.dma_attr_count_max	= 0x00000000FFFFFFFFull;
	tx_buf_attr.dma_attr_align	= OCE_DMA_ALIGNMENT;
	tx_buf_attr.dma_attr_burstsizes	= 0x000007FF;
	tx_buf_attr.dma_attr_minxfer	= 0x00000001;
	tx_buf_attr.dma_attr_maxxfer	= 0x00000000FFFFFFFFull;
	tx_buf_attr.dma_attr_seg	= 0xFFFFFFFFFFFFFFFFull;
	tx_buf_attr.dma_attr_granular	= (uint32_t)buf_size;

	if (DDI_FM_DMA_ERR_CAP(dev->fm_caps)) {
		tx_buf_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
	}

	tx_buf_attr.dma_attr_sgllen = 1;

	ret = oce_alloc_dma_buffer(dev, &wq->wqb, size, &tx_buf_attr,
	    DDI_DMA_STREAMING|DDI_DMA_WRITE);
	if (ret != DDI_SUCCESS) {
		tx_buf_attr.dma_attr_sgllen =
		    size/ddi_ptob(dev->dip, (ulong_t)1) + 2;
		ret = oce_alloc_dma_buffer(dev, &wq->wqb, size, &tx_buf_attr,
		    DDI_DMA_STREAMING|DDI_DMA_WRITE);
		if (ret != DDI_SUCCESS) {
			kmem_free(wq->wq_bdesc_array,
			    wq->cfg.nbufs * sizeof (oce_wq_bdesc_t));
			kmem_free(wq->wqb_freelist,
			    wq->cfg.nbufs * sizeof (oce_wq_bdesc_t *));
			return (DDI_FAILURE);
		}
	}

	wqbd = wq->wq_bdesc_array;
	vaddr = wq->wqb.base;
	cookie = wq->wqb.cookie;
	ncookies = wq->wqb.ncookies;
	do {
		paddr = cookie.dmac_laddress;
		bufs_per_cookie = cookie.dmac_size/buf_size;
		for (i = 0; i <  bufs_per_cookie; i++, wqbd++) {
			wqbd->wqb.acc_handle = wq->wqb.acc_handle;
			wqbd->wqb.dma_handle = wq->wqb.dma_handle;
			wqbd->wqb.base = vaddr;
			wqbd->wqb.addr = paddr;
			wqbd->wqb.len  = buf_size;
			wqbd->wqb.size = buf_size;
			wqbd->wqb.off  = tidx * buf_size;
			wqbd->frag_addr.dw.addr_lo = ADDR_LO(paddr);
			wqbd->frag_addr.dw.addr_hi = ADDR_HI(paddr);
			wq->wqb_freelist[tidx] = wqbd;
			/* increment the addresses */
			paddr += buf_size;
			vaddr += buf_size;
			atomic_inc_32(&wq->wqb_free);
			tidx++;
			if (tidx >= wq->cfg.nbufs)
				break;
		}
		if (--ncookies > 0) {
			(void) ddi_dma_nextcookie(wq->wqb.dma_handle, &cookie);
		}
	} while (ncookies > 0);

	wq->wqbd_next_free = 0;
	wq->wqbd_rc_head = 0;

	mutex_init(&wq->wqb_alloc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->intr_pri));
	mutex_init(&wq->wqb_free_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->intr_pri));
	return (DDI_SUCCESS);
}

/*
 * function to destroy WQ buffer cache
 *
 * wq - pointer to WQ structure
 *
 * return none
 */
void
oce_wqb_cache_destroy(struct oce_wq *wq)
{
	/* Free Tx buffer dma memory */
	oce_free_dma_buffer(wq->parent, &wq->wqb);

	mutex_destroy(&wq->wqb_alloc_lock);
	mutex_destroy(&wq->wqb_free_lock);
	kmem_free(wq->wqb_freelist,
	    wq->cfg.nbufs * sizeof (oce_wq_bdesc_t *));
	wq->wqb_freelist = NULL;
	kmem_free(wq->wq_bdesc_array,
	    wq->cfg.nbufs * sizeof (oce_wq_bdesc_t));
}

/*
 * function to alloc   WQE buffer descriptor
 *
 * wq - pointer to WQ structure
 *
 * return pointer to WQE buffer descriptor
 */
static inline oce_wq_bdesc_t *
oce_wqb_alloc(struct oce_wq *wq)
{
	oce_wq_bdesc_t *wqbd;
	if (oce_atomic_reserve(&wq->wqb_free, 1) < 0) {
		return (NULL);
	}

	mutex_enter(&wq->wqb_alloc_lock);
	wqbd = wq->wqb_freelist[wq->wqbd_next_free];
	wq->wqb_freelist[wq->wqbd_next_free] = NULL;
	wq->wqbd_next_free = GET_Q_NEXT(wq->wqbd_next_free, 1, wq->cfg.nbufs);
	mutex_exit(&wq->wqb_alloc_lock);

	return (wqbd);
}

/*
 * function to free   WQE buffer descriptor
 *
 * wq - pointer to WQ structure
 * wqbd - pointer to WQ buffer descriptor
 *
 * return none
 */
static inline void
oce_wqb_free(struct oce_wq *wq, oce_wq_bdesc_t *wqbd)
{
	mutex_enter(&wq->wqb_free_lock);
	wq->wqb_freelist[wq->wqbd_rc_head] = wqbd;
	wq->wqbd_rc_head = GET_Q_NEXT(wq->wqbd_rc_head, 1, wq->cfg.nbufs);
	atomic_inc_32(&wq->wqb_free);
	mutex_exit(&wq->wqb_free_lock);
} /* oce_wqb_free */

/*
 * function to allocate   WQE mapping descriptor
 *
 * wq - pointer to WQ structure
 *
 * return pointer to WQE mapping descriptor
 */
static inline oce_wq_mdesc_t *
oce_wqm_alloc(struct oce_wq *wq)
{
	oce_wq_mdesc_t *wqmd;

	if (oce_atomic_reserve(&wq->wqm_free, 1) < 0) {
		return (NULL);
	}

	mutex_enter(&wq->wqm_alloc_lock);
	wqmd = wq->wqm_freelist[wq->wqmd_next_free];
	wq->wqm_freelist[wq->wqmd_next_free] = NULL;
	wq->wqmd_next_free = GET_Q_NEXT(wq->wqmd_next_free, 1, wq->cfg.nhdl);
	mutex_exit(&wq->wqm_alloc_lock);

	return (wqmd);
} /* oce_wqm_alloc */

/*
 * function to insert	WQE mapping descriptor to the list
 *
 * wq - pointer to WQ structure
 * wqmd - Pointer to WQ mapping descriptor
 *
 * return none
 */
static inline void
oce_wqm_free(struct oce_wq *wq, oce_wq_mdesc_t *wqmd)
{
	mutex_enter(&wq->wqm_free_lock);
	wq->wqm_freelist[wq->wqmd_rc_head] = wqmd;
	wq->wqmd_rc_head = GET_Q_NEXT(wq->wqmd_rc_head, 1, wq->cfg.nhdl);
	atomic_inc_32(&wq->wqm_free);
	mutex_exit(&wq->wqm_free_lock);
}

/*
 * function to free  WQE mapping descriptor
 *
 * wq - pointer to WQ structure
 * wqmd - Pointer to WQ mapping descriptor
 *
 * return none
 */
static void
oce_wqmd_free(struct oce_wq *wq, oce_wq_mdesc_t *wqmd)
{
	if (wqmd == NULL) {
		return;
	}
	(void) ddi_dma_unbind_handle(wqmd->dma_handle);
	oce_wqm_free(wq, wqmd);
}

/*
 * WQED kmem_cache constructor
 *
 * buf - pointer to WQE descriptor
 *
 * return DDI_SUCCESS
 */
int
oce_wqe_desc_ctor(void *buf, void *arg, int kmflags)
{
	_NOTE(ARGUNUSED(buf));
	_NOTE(ARGUNUSED(arg));
	_NOTE(ARGUNUSED(kmflags));

	return (DDI_SUCCESS);
}

/*
 * WQED kmem_cache destructor
 *
 * buf - pointer to WQE descriptor
 *
 * return none
 */
void
oce_wqe_desc_dtor(void *buf, void *arg)
{
	_NOTE(ARGUNUSED(buf));
	_NOTE(ARGUNUSED(arg));
}

/*
 * function to populate the single WQE
 *
 * wq - pointer to wq
 * wqed - pointer to WQ entry  descriptor
 *
 * return none
 */
#pragma inline(oce_fill_ring_descs)
static void
oce_fill_ring_descs(struct oce_wq *wq, oce_wqe_desc_t *wqed)
{

	struct oce_nic_frag_wqe *wqe;
	int i;
	/* Copy the precreate WQE descs to the ring desc */
	for (i = 0; i < wqed->wqe_cnt; i++) {
		wqe = RING_GET_PRODUCER_ITEM_VA(wq->ring,
		    struct oce_nic_frag_wqe);

		bcopy(&wqed->frag[i], wqe, NIC_WQE_SIZE);
		RING_PUT(wq->ring, 1);
	}
} /* oce_fill_ring_descs */

/*
 * function to copy the packet to preallocated Tx buffer
 *
 * wq - pointer to WQ
 * wqed - Pointer to WQE descriptor
 * mp - Pointer to packet chain
 * pktlen - Size of the packet
 *
 * return 0=>success, error code otherwise
 */
static int
oce_bcopy_wqe(struct oce_wq *wq, oce_wqe_desc_t *wqed, mblk_t *mp,
    uint32_t pkt_len)
{
	oce_wq_bdesc_t *wqbd;
	caddr_t buf_va;
	struct oce_dev *dev = wq->parent;
	int len = 0;

	wqbd = oce_wqb_alloc(wq);
	if (wqbd == NULL) {
		atomic_inc_32(&dev->tx_noxmtbuf);
		oce_log(dev, CE_WARN, MOD_TX, "%s",
		    "wqb pool empty");
		return (ENOMEM);
	}

	/* create a fragment wqe for the packet */
	wqed->frag[wqed->frag_idx].u0.s.frag_pa_hi = wqbd->frag_addr.dw.addr_hi;
	wqed->frag[wqed->frag_idx].u0.s.frag_pa_lo = wqbd->frag_addr.dw.addr_lo;
	buf_va = DBUF_VA(wqbd->wqb);

	/* copy pkt into buffer */
	for (len = 0; mp != NULL && len < pkt_len; mp = mp->b_cont) {
		bcopy(mp->b_rptr, buf_va, MBLKL(mp));
		buf_va += MBLKL(mp);
		len += MBLKL(mp);
	}

	DBUF_SYNC(wqbd->wqb, wqbd->wqb.off, pkt_len, DDI_DMA_SYNC_FORDEV);

	if (oce_fm_check_dma_handle(dev, DBUF_DHDL(wqbd->wqb))) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
		/* Free the buffer */
		oce_wqb_free(wq, wqbd);
		return (EIO);
	}
	wqed->frag[wqed->frag_idx].u0.s.frag_len   =  pkt_len;
	wqed->frag[wqed->frag_idx].u0.s.rsvd0 = 0;
	wqed->hdesc[wqed->nhdl].hdl = (void *)(wqbd);
	wqed->hdesc[wqed->nhdl].type = COPY_WQE;
	wqed->frag_cnt++;
	wqed->frag_idx++;
	wqed->nhdl++;
	return (0);
} /* oce_bcopy_wqe */

/*
 * function to copy the packet or dma map on the fly depending on size
 *
 * wq - pointer to WQ
 * wqed - Pointer to WQE descriptor
 * mp - Pointer to packet chain
 *
 * return DDI_SUCCESS=>success, DDI_FAILURE=>error
 */
static  int
oce_map_wqe(struct oce_wq *wq, oce_wqe_desc_t *wqed, mblk_t *mp,
    uint32_t pkt_len)
{
	ddi_dma_cookie_t cookie;
	oce_wq_mdesc_t *wqmd;
	uint32_t ncookies;
	int ret;
	struct oce_dev *dev = wq->parent;

	wqmd = oce_wqm_alloc(wq);
	if (wqmd == NULL) {
		oce_log(dev, CE_WARN, MOD_TX, "%s",
		    "wqm pool empty");
		return (ENOMEM);
	}

	ret = ddi_dma_addr_bind_handle(wqmd->dma_handle,
	    (struct as *)0, (caddr_t)mp->b_rptr,
	    pkt_len, DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, NULL, &cookie, &ncookies);
	if (ret != DDI_DMA_MAPPED) {
		oce_log(dev, CE_WARN, MOD_TX, "MAP FAILED %d",
		    ret);
		/* free the last one */
		oce_wqm_free(wq, wqmd);
		return (ENOMEM);
	}
	do {
		wqed->frag[wqed->frag_idx].u0.s.frag_pa_hi =
		    ADDR_HI(cookie.dmac_laddress);
		wqed->frag[wqed->frag_idx].u0.s.frag_pa_lo =
		    ADDR_LO(cookie.dmac_laddress);
		wqed->frag[wqed->frag_idx].u0.s.frag_len =
		    (uint32_t)cookie.dmac_size;
		wqed->frag[wqed->frag_idx].u0.s.rsvd0 = 0;
		wqed->frag_cnt++;
		wqed->frag_idx++;
		if (--ncookies > 0)
			ddi_dma_nextcookie(wqmd->dma_handle, &cookie);
		else
			break;
	} while (ncookies > 0);

	wqed->hdesc[wqed->nhdl].hdl = (void *)wqmd;
	wqed->hdesc[wqed->nhdl].type = MAPPED_WQE;
	wqed->nhdl++;
	return (0);
} /* oce_map_wqe */

static inline int
oce_process_tx_compl(struct oce_wq *wq, boolean_t rearm)
{
	struct oce_nic_tx_cqe *cqe;
	uint16_t num_cqe = 0;
	struct oce_cq *cq;
	oce_wqe_desc_t *wqed;
	int wqe_freed = 0;
	struct oce_dev *dev;
	list_t wqe_desc_list;

	cq  = wq->cq;
	dev = wq->parent;

	DBUF_SYNC(cq->ring->dbuf, 0, 0, DDI_DMA_SYNC_FORKERNEL);

	list_create(&wqe_desc_list, sizeof (oce_wqe_desc_t),
	    offsetof(oce_wqe_desc_t, link));

	mutex_enter(&wq->txc_lock);
	cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring, struct oce_nic_tx_cqe);
	while (WQ_CQE_VALID(cqe)) {

		DW_SWAP(u32ptr(cqe), sizeof (struct oce_nic_tx_cqe));

		/* update stats */
		if (cqe->u0.s.status != 0) {
			atomic_inc_32(&dev->tx_errors);
		}

		mutex_enter(&wq->wqed_list_lock);
		wqed = list_remove_head(&wq->wqe_desc_list);
		mutex_exit(&wq->wqed_list_lock);
		if (wqed == NULL) {
			oce_log(dev, CE_NOTE, MOD_CONFIG, "%s",
			    "oce_process_tx_compl: wqed list empty");
			break;
		}
		atomic_dec_32(&wq->wqe_pending);

		wqe_freed += wqed->wqe_cnt;
		list_insert_tail(&wqe_desc_list, wqed);
		/* clear the valid bit and progress cqe */
		WQ_CQE_INVALIDATE(cqe);
		RING_GET(cq->ring, 1);

		cqe = RING_GET_CONSUMER_ITEM_VA(cq->ring,
		    struct oce_nic_tx_cqe);
		num_cqe++;
	} /* for all valid CQE */

	if (num_cqe == 0 && wq->wqe_pending > 0) {
		mutex_exit(&wq->txc_lock);
		return (0);
	}

	DBUF_SYNC(cq->ring->dbuf, 0, 0, DDI_DMA_SYNC_FORDEV);
	oce_arm_cq(wq->parent, cq->cq_id, num_cqe, rearm);

	RING_GET(wq->ring, wqe_freed);
	atomic_add_32(&wq->wq_free, wqe_freed);
	if (wq->resched && wq->wq_free >= OCE_MAX_TX_HDL) {
		wq->resched = B_FALSE;
		mac_tx_ring_update(dev->mac_handle, wq->handle);
	}
	wq->last_compl = ddi_get_lbolt();
	mutex_exit(&wq->txc_lock);
	while (wqed = list_remove_head(&wqe_desc_list)) {
		oce_free_wqed(wq, wqed);
	}
	list_destroy(&wqe_desc_list);
	return (num_cqe);
} /* oce_process_tx_completion */

/*
 * function to drain a TxCQ and process its CQEs
 *
 * dev - software handle to the device
 * cq - pointer to the cq to drain
 *
 * return the number of CQEs processed
 */
void *
oce_drain_wq_cq(void *arg, int arg2, int arg3)
{
	struct oce_dev *dev;
	struct oce_wq *wq;

	_NOTE(ARGUNUSED(arg2));
	_NOTE(ARGUNUSED(arg3));

	wq = (struct oce_wq *)arg;
	dev = wq->parent;
	wq->last_intr = ddi_get_lbolt();
	/* do while we do not reach a cqe that is not valid */
	(void) oce_process_tx_compl(wq, B_FALSE);
	(void) atomic_cas_uint(&wq->qmode, OCE_MODE_INTR, OCE_MODE_POLL);
	if ((wq->wq_free > OCE_MAX_TX_HDL) && wq->resched) {
		wq->resched = B_FALSE;
		mac_tx_ring_update(dev->mac_handle, wq->handle);
	}
	return (NULL);

} /* oce_process_wq_cqe */


boolean_t
oce_tx_stall_check(struct oce_dev *dev)
{
	struct oce_wq *wq;
	int ring = 0;
	boolean_t is_stalled = B_FALSE;

	if (!(dev->state & STATE_MAC_STARTED) ||
	    (dev->link_status != LINK_STATE_UP)) {
		return (B_FALSE);
	}

	for (ring = 0; ring < dev->tx_rings; ring++) {
		wq = &dev->wq[ring];

		if (wq->resched) {
			if (wq->wq_free > OCE_MAX_TX_HDL) {
				mac_tx_ring_update(dev->mac_handle, wq->handle);
			} else {
				/* enable the interrupts only once */
				if (atomic_cas_uint(&wq->qmode, OCE_MODE_POLL,
				    OCE_MODE_INTR) == OCE_MODE_POLL) {
					oce_arm_cq(dev, wq->cq->cq_id, 0,
					    B_TRUE);
				}
			}
		}
	}
	return (is_stalled);
}
/*
 * Function to check whether TX stall
 * can occur for an IPV6 packet for
 * some versions of BE cards
 *
 * dev - software handle to the device
 * mp - Pointer to packet chain
 * ipoffset - ip header offset in mp chain
 *
 * return B_TRUE or B_FALSE
 */

static inline int
oce_check_ipv6_tx_stall(struct oce_dev *dev,
	mblk_t *mp, uint32_t ip_offset) {

	_NOTE(ARGUNUSED(dev));
	ip6_t *ipv6_hdr;
	struct ip6_opt *v6_op;
	ipv6_hdr =  (ip6_t *)(void *)
		(mp->b_rptr + ip_offset);
	v6_op = (struct ip6_opt *)(ipv6_hdr+1);
	if (ipv6_hdr->ip6_nxt  != IPPROTO_TCP &&
	    ipv6_hdr->ip6_nxt  != IPPROTO_UDP &&
	    v6_op->ip6o_len == 0xFF) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}
/*
 * Function to insert VLAN Tag to
 * mp cahin
 *
 * dev - software handle to the device
 * mblk_haad - Pointer holding packet chain
 *
 * return DDI_FAILURE or DDI_SUCCESS
 */

static int
oce_ipv6_tx_stall_workaround(struct oce_dev *dev,
	mblk_t **mblk_head) {

	mblk_t *mp;
	struct ether_vlan_header *evh;
	mp = allocb(OCE_HDR_LEN, BPRI_HI);
	if (mp == NULL) {
		return (DDI_FAILURE);
	}
	/* copy ether header */
	(void) memcpy(mp->b_rptr, (*mblk_head)->b_rptr, 2 * ETHERADDRL);
	evh = (struct ether_vlan_header *)(void *)mp->b_rptr;
	evh->ether_tpid = htons(VLAN_TPID);
	evh->ether_tci = ((dev->pvid > 0) ? LE_16(dev->pvid) :
	    htons(dev->QnQ_tag));
	mp->b_wptr = mp->b_rptr + (2 * ETHERADDRL) + VTAG_SIZE;
	(*mblk_head)->b_rptr += 2 * ETHERADDRL;

	if (MBLKL(*mblk_head) > 0) {
		mp->b_cont = *mblk_head;
	} else {
		mp->b_cont = (*mblk_head)->b_cont;
		freeb(*mblk_head);
	}
	*mblk_head = mp;
	return (DDI_SUCCESS);
}

/*
 * function to xmit  Single packet over the wire
 *
 * wq - pointer to WQ
 * mp - Pointer to packet chain
 *
 * return pointer to the packet
 */
mblk_t *
oce_send_packet(struct oce_wq *wq, mblk_t *mp)
{
	struct oce_nic_hdr_wqe *wqeh;
	struct oce_dev *dev;
	struct ether_header *eh;
	struct ether_vlan_header *evh;
	int32_t num_wqes;
	uint16_t etype;
	uint32_t ip_offset;
	uint32_t csum_flags = 0;
	boolean_t use_copy = B_FALSE;
	boolean_t tagged   = B_FALSE;
	boolean_t ipv6_stall   = B_FALSE;
	uint32_t  reg_value = 0;
	oce_wqe_desc_t *wqed = NULL;
	mblk_t *nmp = NULL;
	mblk_t *tmp = NULL;
	uint32_t pkt_len = 0;
	int num_mblks = 0;
	int ret = 0;
	uint32_t mss = 0;
	uint32_t flags = 0;
	int len = 0;

	/* retrieve the adap priv struct ptr */
	dev = wq->parent;

	/* check if we have enough free slots */
	if (wq->wq_free < dev->tx_reclaim_threshold) {
		(void) oce_process_tx_compl(wq, B_FALSE);
	}
	if (wq->wq_free < OCE_MAX_TX_HDL) {
		wq->resched = B_TRUE;
		wq->last_defered = ddi_get_lbolt();
		atomic_inc_32(&wq->tx_deferd);
		return (mp);
	}

	/* check if we should copy */
	for (tmp = mp; tmp != NULL; tmp = tmp->b_cont) {
		pkt_len += MBLKL(tmp);
		num_mblks++;
	}

	if (pkt_len == 0 || num_mblks == 0) {
		freemsg(mp);
		return (NULL);
	}

	/* retrieve LSO information */
	mac_lso_get(mp, &mss, &flags);

	/* get the offload flags */
	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &csum_flags);

	/* restrict the mapped segment to wat we support */
	if (num_mblks  > OCE_MAX_TX_HDL) {
		nmp = msgpullup(mp, -1);
		if (nmp == NULL) {
			atomic_inc_32(&wq->pkt_drops);
			freemsg(mp);
			return (NULL);
		}
		/* Reset it to new collapsed mp */
		freemsg(mp);
		mp = nmp;
		/* restore the flags on new mp */
		if (flags & HW_LSO) {
			DB_CKSUMFLAGS(mp) |= HW_LSO;
			DB_LSOMSS(mp) = (uint16_t)mss;
		}
		if (csum_flags != 0) {
			DB_CKSUMFLAGS(mp) |= csum_flags;
		}
	}

	/* Get the packet descriptor for Tx */
	wqed = kmem_cache_alloc(wq->wqed_cache, KM_NOSLEEP);
	if (wqed == NULL) {
		atomic_inc_32(&wq->pkt_drops);
		freemsg(mp);
		return (NULL);
	}

	/* Save the WQ pointer */
	wqed->wq = wq;
	wqed->frag_idx = 1; /* index zero is always header */
	wqed->frag_cnt = 0;
	wqed->nhdl = 0;
	wqed->mp = NULL;

	eh = (struct ether_header *)(void *)mp->b_rptr;
	if (ntohs(eh->ether_type) == VLAN_TPID) {
		evh = (struct ether_vlan_header *)(void *)mp->b_rptr;
		tagged = B_TRUE;
		etype = ntohs(evh->ether_type);
		ip_offset = sizeof (struct ether_vlan_header);

	} else {
		etype = ntohs(eh->ether_type);
		ip_offset = sizeof (struct ether_header);
	}
	/* Check Workaround required for IPV6 TX stall */
	if (BE3_A1(dev) && (etype == ETHERTYPE_IPV6) &&
	    ((dev->QnQ_valid) || (!tagged && dev->pvid != 0))) {
		len = ip_offset + sizeof (ip6_t) + sizeof (struct ip6_opt);
		if (MBLKL(mp) < len) {
			nmp = msgpullup(mp, len);
			if (nmp == NULL) {
				oce_free_wqed(wq, wqed);
				atomic_inc_32(&wq->pkt_drops);
				freemsg(mp);
				return (NULL);
			}
			freemsg(mp);
			mp = nmp;
		}
		ipv6_stall = oce_check_ipv6_tx_stall(dev, mp, ip_offset);
		if (ipv6_stall) {
			if (dev->QnQ_queried)
				ret = oce_ipv6_tx_stall_workaround(dev, &mp);
			else {
				/* FW Workaround not available */
				ret = DDI_FAILURE;
			}
			if (ret) {
				oce_free_wqed(wq, wqed);
				atomic_inc_32(&wq->pkt_drops);
				freemsg(mp);
				return (NULL);
			}
			pkt_len += VTAG_SIZE;
		}
	}

	/* If entire packet is less than the copy limit  just do copy */
	if (pkt_len < dev->tx_bcopy_limit) {
		use_copy = B_TRUE;
		ret = oce_bcopy_wqe(wq, wqed, mp, pkt_len);
	} else {
		/* copy or dma map the individual fragments */
		for (nmp = mp; nmp != NULL; nmp = nmp->b_cont) {
			len = MBLKL(nmp);
			if (len == 0) {
				continue;
			}
			if (len < dev->tx_bcopy_limit) {
				ret = oce_bcopy_wqe(wq, wqed, nmp, len);
			} else {
				ret = oce_map_wqe(wq, wqed, nmp, len);
			}
			if (ret != 0)
				break;
		}
	}

	/*
	 * Any failure other than insufficient Q entries
	 * drop the packet
	 */
	if (ret != 0) {
		oce_free_wqed(wq, wqed);
		atomic_inc_32(&wq->pkt_drops);
		freemsg(mp);
		return (NULL);
	}

	wqeh = (struct oce_nic_hdr_wqe *)&wqed->frag[0];
	bzero(wqeh, sizeof (struct oce_nic_hdr_wqe));

	/* fill rest of wqe header fields based on packet */
	if (flags & HW_LSO) {
		wqeh->u0.s.lso = B_TRUE;
		wqeh->u0.s.lso_mss = mss;
	}
	if (csum_flags & HCK_FULLCKSUM) {
		uint8_t *proto;
		if (etype == ETHERTYPE_IP) {
			proto = (uint8_t *)(void *)
			    (mp->b_rptr + ip_offset);
			if (proto[9] == 6)
				/* IPPROTO_TCP */
				wqeh->u0.s.tcpcs = B_TRUE;
			else if (proto[9] == 17)
				/* IPPROTO_UDP */
				wqeh->u0.s.udpcs = B_TRUE;
		}
	}

	if (csum_flags & HCK_IPV4_HDRCKSUM)
		wqeh->u0.s.ipcs = B_TRUE;
	if (ipv6_stall) {
		wqeh->u0.s.complete = B_FALSE;
		wqeh->u0.s.event = B_TRUE;
	} else {

		wqeh->u0.s.complete = B_TRUE;
		wqeh->u0.s.event = B_TRUE;
	}
	wqeh->u0.s.crc = B_TRUE;
	wqeh->u0.s.total_length = pkt_len;

	num_wqes = wqed->frag_cnt + 1;

	/* h/w expects even no. of WQEs */
	if ((num_wqes & 0x1) && !(LANCER_CHIP(dev))) {
		bzero(&wqed->frag[num_wqes], sizeof (struct oce_nic_frag_wqe));
		num_wqes++;
	}
	wqed->wqe_cnt = (uint16_t)num_wqes;
	wqeh->u0.s.num_wqe = num_wqes;
	DW_SWAP(u32ptr(&wqed->frag[0]), (wqed->wqe_cnt * NIC_WQE_SIZE));

	mutex_enter(&wq->tx_lock);
	if (num_wqes > wq->wq_free - 2) {
		atomic_inc_32(&wq->tx_deferd);
		mutex_exit(&wq->tx_lock);
		goto wqe_fail;
	}
	atomic_add_32(&wq->wq_free, -num_wqes);

	/* fill the wq for adapter */
	oce_fill_ring_descs(wq, wqed);

	/* Set the mp pointer in the wqe descriptor */
	if (use_copy == B_FALSE) {
		wqed->mp = mp;
	}
	/* Add the packet desc to list to be retrieved during cmpl */
	mutex_enter(&wq->wqed_list_lock);
	list_insert_tail(&wq->wqe_desc_list,  wqed);
	mutex_exit(&wq->wqed_list_lock);
	atomic_inc_32(&wq->wqe_pending);
	DBUF_SYNC(wq->ring->dbuf, 0, 0, DDI_DMA_SYNC_FORDEV);

	/* ring tx doorbell */
	reg_value = (num_wqes << 16) | wq->wq_id;
	/* Ring the door bell  */
	OCE_DB_WRITE32(dev, PD_TXULP_DB, reg_value);

	/* update the ring stats */
	wq->stat_bytes += pkt_len;
	wq->stat_pkts++;

	mutex_exit(&wq->tx_lock);
	if (oce_fm_check_acc_handle(dev, dev->db_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(dev->dip, DDI_SERVICE_DEGRADED);
	}

	/* free mp if copied or packet chain collapsed */
	if (use_copy == B_TRUE) {
		freemsg(mp);
	}
	return (NULL);

wqe_fail:

	oce_free_wqed(wq, wqed);
	wq->resched = B_TRUE;
	wq->last_defered = ddi_get_lbolt();
	return (mp);
} /* oce_send_packet */

/*
 * function to free the WQE descriptor
 *
 * wq - pointer to WQ
 * wqed - Pointer to WQE descriptor
 *
 * return none
 */
#pragma inline(oce_free_wqed)
static void
oce_free_wqed(struct oce_wq *wq, oce_wqe_desc_t *wqed)
{
	int i = 0;
	if (wqed == NULL) {
		return;
	}

	for (i = 0; i < wqed->nhdl; i++) {
		if (wqed->hdesc[i].type == COPY_WQE) {
		oce_wqb_free(wq, wqed->hdesc[i].hdl);
		} else 	if (wqed->hdesc[i].type == MAPPED_WQE) {
			oce_wqmd_free(wq, wqed->hdesc[i].hdl);
		}
	}
	if (wqed->mp)
		freemsg(wqed->mp);
	kmem_cache_free(wq->wqed_cache, wqed);
} /* oce_free_wqed */

/*
 * function to start the WQ
 *
 * wq - pointer to WQ
 *
 * return DDI_SUCCESS
 */

int
oce_start_wq(struct oce_wq *wq)
{
	_NOTE(ARGUNUSED(wq));
	return (DDI_SUCCESS);
} /* oce_start_wq */

/*
 * function to stop  the WQ
 *
 * wq - pointer to WQ
 *
 * return none
 */
void
oce_clean_wq(struct oce_wq *wq)
{
	oce_wqe_desc_t *wqed;
	int ti;

	/* Wait for already posted Tx to complete */

	for (ti = 0; ti < DEFAULT_DRAIN_TIME; ti++) {
		(void) oce_process_tx_compl(wq, B_FALSE);
		OCE_MSDELAY(1);
	}

	/* Free the remaining descriptors */
	mutex_enter(&wq->wqed_list_lock);
	while ((wqed = list_remove_head(&wq->wqe_desc_list)) != NULL) {
		atomic_add_32(&wq->wq_free, wqed->wqe_cnt);
		oce_free_wqed(wq, wqed);
	}
	mutex_exit(&wq->wqed_list_lock);
	oce_drain_eq(wq->cq->eq);
} /* oce_stop_wq */
