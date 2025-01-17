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
 * Source file containing the implementation of the driver statistics
 * and related helper functions
 */

#include <oce_impl.h>
#include <oce_stat.h>
#include <oce_buf.h>


static int
oce_update_lancer_stats(struct oce_dev *dev, struct oce_stat *stats)
{
	struct mbx_get_pport_stats *hw_stats;
	int ret;

	hw_stats = (struct mbx_get_pport_stats *)DBUF_VA(dev->stats_dbuf);
	ret = oce_get_pport_stats(dev, MBX_ASYNC_MQ);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Failed to get stats:%d", ret);
		return (EIO);
	}

	/* update the stats */
	stats->rx_bytes_lo.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_bytes_lo;
	stats->rx_bytes_hi.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_bytes_hi;

	stats->rx_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_packets_lo;
	stats->rx_errors.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_crc_errors_lo +
	    hw_stats->params.rsp.pport_stats.rx_alignment_errors_lo +
	    hw_stats->params.rsp.pport_stats.rx_symbol_errors_lo +
	    hw_stats->params.rsp.pport_stats.rx_in_range_errors +
	    hw_stats->params.rsp.pport_stats.rx_out_of_range_errors +
	    hw_stats->params.rsp.pport_stats.rx_frames_too_long_lo +
	    hw_stats->params.rsp.pport_stats.rx_ip_checksum_errors +
	    hw_stats->params.rsp.pport_stats.rx_tcp_checksum_errors +
	    hw_stats->params.rsp.pport_stats.rx_udp_checksum_errors;

	stats->rx_drops.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_dropped_too_small +
	    hw_stats->params.rsp.pport_stats.rx_dropped_too_short +
	    hw_stats->params.rsp.pport_stats.rx_dropped_header_too_small +
	    hw_stats->params.rsp.pport_stats.rx_dropped_invalid_tcp_length +
	    hw_stats->params.rsp.pport_stats.rx_dropped_runt;

	stats->tx_bytes_lo.value.ul =
	    hw_stats->params.rsp.pport_stats.tx_packets_lo;
	stats->tx_bytes_hi.value.ul =
	    hw_stats->params.rsp.pport_stats.tx_packets_hi;

	stats->tx_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.tx_unicast_packets_lo +
	    hw_stats->params.rsp.pport_stats.tx_multicast_packets_lo +
	    hw_stats->params.rsp.pport_stats.tx_broadcast_packets_lo +
	    hw_stats->params.rsp.pport_stats.tx_pause_frames_lo +
	    hw_stats->params.rsp.pport_stats.tx_control_frames_lo;

	/* Update all Wq errors */
	stats->tx_errors.value.ul = dev->tx_errors;

	stats->rx_unicast_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_unicast_packets_lo;
	stats->rx_multicast_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_multicast_packets_lo;
	stats->rx_broadcast_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_broadcast_packets_lo;
	stats->rx_crc_errors.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_crc_errors_lo;

	stats->rx_alignment_symbol_errors.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_alignment_errors_lo +
	    hw_stats->params.rsp.pport_stats.rx_symbol_errors_lo;
	stats->rx_in_range_errors.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_in_range_errors;
	stats->rx_out_range_errors.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_out_of_range_errors;
	stats->rx_frame_too_long.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_frames_too_long_lo;
	stats->rx_address_match_errors.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_address_match_errors;

	stats->rx_pause_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_pause_frames_lo;
	stats->rx_control_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_control_frames_lo;
	stats->rx_ip_checksum_errs.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_ip_checksum_errors;
	stats->rx_tcp_checksum_errs.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_tcp_checksum_errors;
	stats->rx_udp_checksum_errs.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_udp_checksum_errors;
	stats->rx_fifo_overflow.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_fifo_overflow;
	stats->rx_input_fifo_overflow.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_input_fifo_overflow;

	stats->tx_unicast_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.tx_unicast_packets_lo;
	stats->tx_multicast_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.tx_multicast_packets_lo;
	stats->tx_broadcast_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.tx_broadcast_packets_lo;
	stats->tx_pause_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.tx_pause_frames_lo;
	stats->tx_control_frames.value.ul =
	    hw_stats->params.rsp.pport_stats.tx_control_frames_lo;


	stats->rx_drops_too_many_frags.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_drops_too_many_frags_lo;
	stats->rx_drops_invalid_ring.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_drops_invalid_queue;
	stats->rx_drops_mtu.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_drops_mtu_lo;

	stats->rx_dropped_too_small.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_dropped_too_small;
	stats->rx_dropped_too_short.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_dropped_too_short;
	stats->rx_dropped_header_too_small.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_dropped_header_too_small;
	stats->rx_dropped_tcp_length.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_dropped_invalid_tcp_length;
	stats->rx_dropped_runt.value.ul =
	    hw_stats->params.rsp.pport_stats.rx_dropped_runt;

	return (DDI_SUCCESS);
}

/*
 * function called by kstat to update the stats counters
 *
 * ksp - pointer to the kstats structure
 * rw - flags defining read/write
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
static int
oce_update_be_stats(struct oce_dev *dev, struct oce_stat *stats)
{
	struct mbx_get_nic_stats *fwcmd;
	int i, ret;

	ret = oce_get_hw_stats(dev, MBX_ASYNC_MQ);
	if (ret != DDI_SUCCESS) {
		return (EIO);
	}

	/* update the stats */
	fwcmd = (struct mbx_get_nic_stats *)DBUF_VA(dev->stats_dbuf);
	if (dev->chip_rev == OC_CNA_GEN2) {
		struct be_hw_stats_v0 *hw_stats = &fwcmd->params.rsp.v0;
		struct rx_stats_v0 *rx_stats = &hw_stats->rx;
		struct rx_port_stats_v0 *port_stats =
		    &rx_stats->port[dev->port_id];
		struct rx_err_stats_v0 *err_stats = &hw_stats->err_rx;

		stats->rx_bytes_lo.value.ul = port_stats->rx_bytes_lsd;
		stats->rx_bytes_hi.value.ul = port_stats->rx_bytes_msd;
		stats->rx_frames.value.ul = port_stats->rx_total_frames;
		stats->rx_errors.value.ul = port_stats->rx_crc_errors +
		    port_stats->rx_alignment_symbol_errors +
		    port_stats->rx_in_range_errors +
		    port_stats->rx_out_range_errors +
		    port_stats->rx_frame_too_long +
		    port_stats->rx_ip_checksum_errs +
		    port_stats->rx_tcp_checksum_errs +
		    port_stats->rx_udp_checksum_errs;

		stats->rx_drops.value.ul = port_stats->rx_dropped_too_small +
		    port_stats->rx_dropped_too_short +
		    port_stats->rx_dropped_header_too_small +
		    port_stats->rx_dropped_tcp_length +
		    port_stats->rx_dropped_runt;

		stats->tx_bytes_lo.value.ul = port_stats->tx_bytes_lsd;
		stats->tx_bytes_hi.value.ul = port_stats->tx_bytes_msd;

		stats->tx_frames.value.ul = port_stats->tx_unicast_frames +
		    port_stats->tx_multicast_frames +
		    port_stats->tx_broadcast_frames +
		    port_stats->tx_pause_frames +
		    port_stats->tx_control_frames;
		stats->tx_errors.value.ul = dev->tx_errors;

		stats->rx_unicast_frames.value.ul =
		    port_stats->rx_unicast_frames;
		stats->rx_multicast_frames.value.ul =
		    port_stats->rx_multicast_frames;
		stats->rx_broadcast_frames.value.ul =
		    port_stats->rx_broadcast_frames;
		stats->rx_crc_errors.value.ul =
		    port_stats->rx_crc_errors;

		stats->rx_alignment_symbol_errors.value.ul =
		    port_stats->rx_alignment_symbol_errors;
		stats->rx_in_range_errors.value.ul =
		    port_stats->rx_in_range_errors;
		stats->rx_out_range_errors.value.ul =
		    port_stats->rx_out_range_errors;
		stats->rx_frame_too_long.value.ul =
		    port_stats->rx_frame_too_long;
		stats->rx_address_match_errors.value.ul =
		    port_stats->rx_address_match_errors;

		stats->rx_pause_frames.value.ul =
		    port_stats->rx_pause_frames;
		stats->rx_control_frames.value.ul =
		    port_stats->rx_control_frames;
		stats->rx_ip_checksum_errs.value.ul =
		    port_stats->rx_ip_checksum_errs;
		stats->rx_tcp_checksum_errs.value.ul =
		    port_stats->rx_tcp_checksum_errs;
		stats->rx_udp_checksum_errs.value.ul =
		    port_stats->rx_udp_checksum_errs;
		stats->rx_fifo_overflow.value.ul = port_stats->rx_fifo_overflow;
		stats->rx_input_fifo_overflow.value.ul =
		    port_stats->rx_input_fifo_overflow;

		stats->tx_unicast_frames.value.ul =
		    port_stats->tx_unicast_frames;
		stats->tx_multicast_frames.value.ul =
		    port_stats->tx_multicast_frames;
		stats->tx_broadcast_frames.value.ul =
		    port_stats->tx_broadcast_frames;
		stats->tx_pause_frames.value.ul =
		    port_stats->tx_pause_frames;
		stats->tx_control_frames.value.ul =
		    port_stats->tx_control_frames;


		stats->rx_drops_no_pbuf.value.ul =
		    rx_stats->rx_drops_no_pbuf;
		stats->rx_drops_no_txpb.value.ul =
		    rx_stats->rx_drops_no_txpb;
		stats->rx_drops_no_erx_descr.value.ul =
		    rx_stats->rx_drops_no_erx_descr;
		stats->rx_drops_no_tpre_descr.value.ul =
		    rx_stats->rx_drops_no_tpre_descr;
		stats->rx_drops_too_many_frags.value.ul =
		    rx_stats->rx_drops_too_many_frags;
		stats->rx_drops_invalid_ring.value.ul =
		    rx_stats->rx_drops_invalid_ring;
		stats->rx_drops_mtu.value.ul =
		    rx_stats->rx_drops_mtu;

		stats->rx_dropped_too_small.value.ul =
		    port_stats->rx_dropped_too_small;
		stats->rx_dropped_too_short.value.ul =
		    port_stats->rx_dropped_too_short;
		stats->rx_dropped_header_too_small.value.ul =
		    port_stats->rx_dropped_header_too_small;
		stats->rx_dropped_tcp_length.value.ul =
		    port_stats->rx_dropped_tcp_length;
		stats->rx_dropped_runt.value.ul =
		    port_stats->rx_dropped_runt;

		stats->rx_drops_no_fragments.value.ul = 0;
		for (i = 0; i < dev->nrqs; i++) {
			stats->rx_drops_no_fragments.value.ul +=
			    err_stats->rx_drops_no_fragments[dev->rq[i].rq_id];
		}

		stats->rx_priority_pause_frames.value.ul = 0;
		stats->pmem_fifo_overflow_drop.value.ul = 0;
		if (dev->port_id) {
			stats->jabber_events.value.ul =
			    rx_stats->port1_jabber_events;
		} else {
			stats->jabber_events.value.ul =
			    rx_stats->port0_jabber_events;
		}
		stats->forwarded_packets.value.ul = rx_stats->forwarded_packets;

	} else {
		struct be_hw_stats_v1 *hw_stats = &fwcmd->params.rsp.v1;
		struct rx_stats_v1 *rx_stats = &hw_stats->rx;
		struct rx_port_stats_v1 *port_stats =
		    &rx_stats->port[dev->port_id];
		struct rx_err_stats_v1 *err_stats = &hw_stats->err_rx;

		stats->rx_bytes_lo.value.ul = port_stats->rx_bytes_lsd;
		stats->rx_bytes_hi.value.ul = port_stats->rx_bytes_msd;
		stats->rx_frames.value.ul = port_stats->rx_total_frames;
		stats->rx_errors.value.ul = port_stats->rx_crc_errors +
		    port_stats->rx_alignment_symbol_errors +
		    port_stats->rx_in_range_errors +
		    port_stats->rx_out_range_errors +
		    port_stats->rx_frame_too_long +
		    port_stats->rx_ip_checksum_errs +
		    port_stats->rx_tcp_checksum_errs +
		    port_stats->rx_udp_checksum_errs;

		stats->rx_drops.value.ul = port_stats->rx_dropped_too_small +
		    port_stats->rx_dropped_too_short +
		    port_stats->rx_dropped_header_too_small +
		    port_stats->rx_dropped_tcp_length +
		    port_stats->rx_dropped_runt;

		stats->tx_bytes_lo.value.ul = port_stats->tx_bytes_lsd;
		stats->tx_bytes_hi.value.ul = port_stats->tx_bytes_msd;

		stats->tx_frames.value.ul = port_stats->tx_unicast_frames +
		    port_stats->tx_multicast_frames +
		    port_stats->tx_broadcast_frames +
		    port_stats->tx_pause_frames +
		    port_stats->tx_control_frames;
		stats->tx_errors.value.ul = dev->tx_errors;

		stats->rx_unicast_frames.value.ul =
		    port_stats->rx_non_switched_unicast_frames +
		    port_stats->rx_switched_unicast_packets;
		stats->rx_multicast_frames.value.ul =
		    port_stats->rx_non_switched_multicast_frames +
		    port_stats->rx_switched_multicast_packets;
		stats->rx_broadcast_frames.value.ul =
		    port_stats->rx_non_switched_broadcast_frames +
		    port_stats->rx_switched_broadcast_packets;
		stats->rx_crc_errors.value.ul =
		    port_stats->rx_crc_errors;

		stats->rx_alignment_symbol_errors.value.ul =
		    port_stats->rx_alignment_symbol_errors;
		stats->rx_in_range_errors.value.ul =
		    port_stats->rx_in_range_errors;
		stats->rx_out_range_errors.value.ul =
		    port_stats->rx_out_range_errors;
		stats->rx_frame_too_long.value.ul =
		    port_stats->rx_frame_too_long;
		stats->rx_address_match_errors.value.ul =
		    port_stats->rx_address_match_errors;

		stats->rx_pause_frames.value.ul =
		    port_stats->rx_pause_frames;
		stats->rx_control_frames.value.ul =
		    port_stats->rx_control_frames;
		stats->rx_ip_checksum_errs.value.ul =
		    port_stats->rx_ip_checksum_errs;
		stats->rx_tcp_checksum_errs.value.ul =
		    port_stats->rx_tcp_checksum_errs;
		stats->rx_udp_checksum_errs.value.ul =
		    port_stats->rx_udp_checksum_errs;
		stats->rx_fifo_overflow.value.ul =
		    port_stats->rxpp_fifo_overflow_drop;
		stats->rx_input_fifo_overflow.value.ul =
		    port_stats->rx_input_fifo_overflow_drop;

		stats->tx_unicast_frames.value.ul =
		    port_stats->tx_unicast_frames;
		stats->tx_multicast_frames.value.ul =
		    port_stats->tx_multicast_frames;
		stats->tx_broadcast_frames.value.ul =
		    port_stats->tx_broadcast_frames;
		stats->tx_pause_frames.value.ul =
		    port_stats->tx_pause_frames;
		stats->tx_control_frames.value.ul =
		    port_stats->tx_control_frames;


		stats->rx_drops_no_pbuf.value.ul =
		    rx_stats->rx_drops_no_pbuf;
		stats->rx_drops_no_txpb.value.ul =
		    rx_stats->rx_drops_no_txpb;
		stats->rx_drops_no_erx_descr.value.ul =
		    rx_stats->rx_drops_no_erx_descr;
		stats->rx_drops_no_tpre_descr.value.ul =
		    rx_stats->rx_drops_no_tpre_descr;
		stats->rx_drops_too_many_frags.value.ul =
		    rx_stats->rx_drops_too_many_frags;
		stats->rx_drops_invalid_ring.value.ul =
		    rx_stats->rx_drops_invalid_ring;
		stats->rx_drops_mtu.value.ul =
		    rx_stats->rx_drops_mtu;

		stats->rx_dropped_too_small.value.ul =
		    port_stats->rx_dropped_too_small;
		stats->rx_dropped_too_short.value.ul =
		    port_stats->rx_dropped_too_short;
		stats->rx_dropped_header_too_small.value.ul =
		    port_stats->rx_dropped_header_too_small;
		stats->rx_dropped_tcp_length.value.ul =
		    port_stats->rx_dropped_tcp_length;
		stats->rx_dropped_runt.value.ul =
		    port_stats->rx_dropped_runt;

		stats->rx_drops_no_fragments.value.ul = 0;
		for (i = 0; i < dev->nrqs; i++) {
			stats->rx_drops_no_fragments.value.ul +=
			    err_stats->rx_drops_no_fragments[dev->rq[i].rq_id];
		}

		stats->rx_priority_pause_frames.value.ul =
		    port_stats->rx_priority_pause_frames;
		stats->pmem_fifo_overflow_drop.value.ul =
		    port_stats->pmem_fifo_overflow_drop;
		stats->jabber_events.value.ul = port_stats->jabber_events;
		stats->forwarded_packets.value.ul = rx_stats->forwarded_packets;

	}

	return (DDI_SUCCESS);
} /* oce_update_be_stats */

/*
 * function called by kstat to update the stats counters
 *
 * ksp - pointer to the kstats structure
 * rw - flags defining read/write
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
static int
oce_update_stats(kstat_t *ksp, int rw)
{
	struct oce_dev *dev;
	struct oce_stat *stats;
	int ret;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	dev = ksp->ks_private;
	stats = (struct oce_stat *)ksp->ks_data;
	mutex_enter(&dev->dev_lock);
	if (dev->suspended) {
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}
	mutex_exit(&dev->dev_lock);
	mutex_enter(&dev->stat_lock);
	if (LANCER_CHIP(dev)) {
		ret = oce_update_lancer_stats(dev, stats);
	} else {
		ret = oce_update_be_stats(dev, stats);
	}
	mutex_exit(&dev->stat_lock);
	return (ret);
} /* oce_update_stats */

/*
 * function to setup the kstat_t structure for the device and install it
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
int
oce_stat_init(struct oce_dev *dev)
{
	int ret;
	struct oce_stat *stats;
	uint32_t hw_stat_size = 0;
	uint32_t num_stats = sizeof (struct oce_stat) /
	    sizeof (kstat_named_t);

	/* allocate the kstat */
	dev->oce_kstats = kstat_create(OCE_MOD_NAME, dev->dev_id, "stats",
	    "net", KSTAT_TYPE_NAMED,
	    num_stats, 0);
	if (dev->oce_kstats == NULL) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "kstat creation failed: 0x%p",
		    (void *)dev->oce_kstats);
		return (DDI_FAILURE);
	}

	if (LANCER_CHIP(dev))
		hw_stat_size = sizeof (struct mbx_get_pport_stats);
	else
		hw_stat_size = sizeof (struct mbx_get_nic_stats);

	/* allocate the device copy of the stats */
	ret = oce_alloc_dma_buffer(dev, &dev->stats_dbuf,
	    hw_stat_size, NULL, DDI_DMA_CONSISTENT|DDI_DMA_RDWR);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Could not allocate stats_dbuf 0x%x", ret);
		kstat_delete(dev->oce_kstats);
		return (DDI_FAILURE);
	}

	/* initialize the counters */
	stats = (struct oce_stat *)dev->oce_kstats->ks_data;
	kstat_named_init(&stats->rx_bytes_hi, "rx bytes msd", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_bytes_lo, "rx bytes lsd", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_frames, "rx frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_errors, "rx errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_drops, "rx drops", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->tx_bytes_hi, "tx bytes msd", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_bytes_lo, "tx bytes lsd", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->tx_frames, "tx frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_errors, "tx errors", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_unicast_frames,
	    "rx unicast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_multicast_frames,
	    "rx multicast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_broadcast_frames,
	    "rx broadcast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_crc_errors,
	    "rx crc errors", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_alignment_symbol_errors,
	    "rx alignment symbol errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_in_range_errors,
	    "rx in range errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_out_range_errors,
	    "rx out range errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_frame_too_long,
	    "rx frame too long", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_address_match_errors,
	    "rx address match errors", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_pause_frames,
	    "rx pause frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_control_frames,
	    "rx control frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_ip_checksum_errs,
	    "rx ip checksum errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_tcp_checksum_errs,
	    "rx tcp checksum errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_udp_checksum_errs,
	    "rx udp checksum errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_fifo_overflow,
	    "rx fifo overflow", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_input_fifo_overflow,
	    "rx input fifo overflow", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->tx_unicast_frames,
	    "tx unicast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_multicast_frames,
	    "tx multicast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_broadcast_frames,
	    "tx broadcast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_pause_frames,
	    "tx pause frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_control_frames,
	    "tx control frames", KSTAT_DATA_ULONG);


	kstat_named_init(&stats->rx_drops_no_pbuf,
	    "rx_drops_no_pbuf", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_drops_no_txpb,
	    "rx_drops_no_txpb", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_drops_no_erx_descr,
	    "rx_drops_no_erx_descr", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_drops_no_tpre_descr,
	    "rx_drops_no_tpre_descr", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_drops_too_many_frags,
	    "rx_drops_too_many_frags", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_drops_invalid_ring,
	    "rx_drops_invalid_ring", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_drops_mtu,
	    "rx_drops_mtu", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_dropped_too_small,
	    "rx_dropped_too_small", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_dropped_too_short,
	    "rx_dropped_too_short", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_dropped_header_too_small,
	    "rx_dropped_header_too_small", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_dropped_tcp_length,
	    "rx_dropped_tcp_length", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_dropped_runt,
	    "rx_dropped_runt", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_drops_no_fragments,
	    "rx_drop_no_frag", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_priority_pause_frames,
	    "rx_priority_pause_frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->pmem_fifo_overflow_drop,
	    "pmem_fifo_overflow_drop", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->jabber_events,
	    "jabber_events", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->forwarded_packets,
	    "forwarded_packets", KSTAT_DATA_ULONG);

	dev->oce_kstats->ks_update = oce_update_stats;
	dev->oce_kstats->ks_private = (void *)dev;
	kstat_install(dev->oce_kstats);

	return (DDI_SUCCESS);
} /* oce_stat_init */

/*
 * function to undo initialization done in oce_stat_init
 *
 * dev - software handle to the device
 *
 * return none
 */
void
oce_stat_fini(struct oce_dev *dev)
{
	oce_free_dma_buffer(dev, &dev->stats_dbuf);
	kstat_delete(dev->oce_kstats);
	dev->oce_kstats = NULL;
} /* oce_stat_fini */

/*
 * GLDv3 entry for statistic query
 */
int
oce_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct oce_dev *dev = arg;
	struct oce_stat *stats;
	int ret;

	stats = (struct oce_stat *)dev->oce_kstats->ks_data;
	mutex_enter(&dev->dev_lock);

	if (dev->suspended ||
	    (dev->state & STATE_MAC_STOPPING) ||
	    !(dev->state & STATE_MAC_STARTED)) {
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}
	mutex_exit(&dev->dev_lock);
	mutex_enter(&dev->stat_lock);

	if (LANCER_CHIP(dev)) {
		ret = oce_update_lancer_stats(dev, stats);
	} else {
		ret = oce_update_be_stats(dev, stats);
	}
	if (ret != DDI_SUCCESS) {
		mutex_exit(&dev->stat_lock);
		return (EIO);
	}
	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = dev->link_speed * 1000000ull;
	break;

	case MAC_STAT_RBYTES:
		*val = (uint64_t)stats->rx_bytes_hi.value.ul << 32 |
		    (uint64_t)stats->rx_bytes_lo.value.ul;
	break;

	case MAC_STAT_IPACKETS:
		*val = stats->rx_frames.value.ul;
	break;

	case MAC_STAT_OBYTES:
		*val = (uint64_t)stats->tx_bytes_hi.value.ul << 32 |
		    (uint64_t)stats->tx_bytes_lo.value.ul;
	break;

	case MAC_STAT_OPACKETS:
		*val = stats->tx_frames.value.ul;
	break;

	case MAC_STAT_BRDCSTRCV:
		*val = stats->rx_broadcast_frames.value.ul;
	break;

	case MAC_STAT_MULTIRCV:
		*val = stats->rx_multicast_frames.value.ul;
	break;

	case MAC_STAT_MULTIXMT:
		*val = stats->tx_multicast_frames.value.ul;
	break;

	case MAC_STAT_BRDCSTXMT:
		*val = stats->tx_broadcast_frames.value.ul;
	break;

	case MAC_STAT_NORCVBUF:
		*val = stats->rx_fifo_overflow.value.ul;
	break;

	case MAC_STAT_IERRORS:
		*val = stats->rx_errors.value.ul;
	break;

	case MAC_STAT_NOXMTBUF:
		*val = dev->tx_noxmtbuf;
	break;

	case MAC_STAT_OERRORS:
		*val = stats->tx_errors.value.ul;
	break;

	case ETHER_STAT_LINK_DUPLEX:
		if (dev->state & STATE_MAC_STARTED)
			*val = LINK_DUPLEX_FULL;
		else
			*val = LINK_DUPLEX_UNKNOWN;
	break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = stats->rx_alignment_symbol_errors.value.ul;
	break;

	case ETHER_STAT_FCS_ERRORS:
		*val = stats->rx_crc_errors.value.ul;
	break;

	case ETHER_STAT_MACRCV_ERRORS:
		*val = stats->rx_errors.value.ul;
	break;

	case ETHER_STAT_MACXMT_ERRORS:
		*val = stats->tx_errors.value.ul;
	break;

	case ETHER_STAT_TOOLONG_ERRORS:
		*val = stats->rx_frame_too_long.value.ul;
	break;

	case ETHER_STAT_CAP_PAUSE:
	case ETHER_STAT_LINK_PAUSE:
		if (dev->flow_control & OCE_FC_TX &&
		    dev->flow_control & OCE_FC_RX)
			*val = LINK_FLOWCTRL_BI;
		else if (dev->flow_control == OCE_FC_TX)
			*val = LINK_FLOWCTRL_TX;
		else if (dev->flow_control == OCE_FC_RX)
			*val = LINK_FLOWCTRL_RX;
		else if (dev->flow_control == 0)
			*val = LINK_FLOWCTRL_NONE;
	break;

	default:
		mutex_exit(&dev->stat_lock);
		return (ENOTSUP);
	}
	mutex_exit(&dev->stat_lock);
	return (0);
} /* oce_m_stat */
