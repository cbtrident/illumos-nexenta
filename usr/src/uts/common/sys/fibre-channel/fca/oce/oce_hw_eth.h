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
 * header file containing the data structure definitions for the NIC
 * subsystetm
 */

#ifndef _OCE_HW_ETH_H_
#define	_OCE_HW_ETH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <oce_hw.h>

#define	NIC_WQE_SIZE	16
/* NIC packet type */
#define	NIC_UNICAST	0x00
#define	NIC_MULTICAST	0x01
#define	NIC_BROADCAST	0x02

/* HDS type */
#define	NIC_HDS_NO_SPLIT	0x00
#define	NIC_HDS_SPLIT_L3PL	0x01
#define	NIC_HDS_SPLIT_L4PL	0x02

/* NIC WQ types */
#define	NIC_WQ_TYPE_FORWARDING		0x01
#define	NIC_WQ_TYPE_STANDARD		0x02
#define	NIC_WQ_TYPE_LOW_LATENCY		0x04

#define	INVALID_PMAC_ID		0xffffffff

#pragma pack(1)
enum {
	OPCODE_CONFIG_NIC_RSS = 1,
	OPCODE_CONFIG_NIC_ACPI = 2,
	OPCODE_CONFIG_NIC_PROMISCUOUS = 3,
	OPCODE_GET_NIC_STATS = 4,
	OPCODE_CREATE_NIC_WQ = 7,
	OPCODE_CREATE_NIC_RQ = 8,
	OPCODE_DELETE_NIC_WQ = 9,
	OPCODE_DELETE_NIC_RQ = 10,
	OPCODE_CREATE_NIC_RSS_CQ = 11,
	OPCODE_DELETE_NIC_RSS_CQ = 12,
	OPCODE_SET_RSS_EQ_MSI = 13,
	OPCODE_CREATE_NIC_HDS_RQ = 14,
	OPCODE_DELETE_NIC_HDS_RQ = 15,
	OPCODE_CONFIG_NIC_RSS_ADVANCED = 16,
	OPCODE_NIC_GET_PPORT_STATS = 18
};

enum {
	RSS_ENABLE_NONE		= 0x0, /* (No RSS) */
	RSS_ENABLE_IPV4		= 0x1, /* (IPV4 HASH enabled ) */
	RSS_ENABLE_TCP_IPV4	= 0x2, /* (TCP IPV4 Hash enabled) */
	RSS_ENABLE_IPV6		= 0x4, /* (IPV6 HASH enabled) */
	RSS_ENABLE_TCP_IPV6	= 0x8  /* (TCP IPV6 HASH */

};
/* NIC header WQE */
struct oce_nic_hdr_wqe {
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw0 */
			uint32_t rsvd0;

			/* dw1 */
			uint32_t last_seg_udp_len:14;
			uint32_t rsvd1:18;

			/* dw2 */
			uint32_t lso_mss:14;
			uint32_t num_wqe:5;
			uint32_t rsvd4:2;
			uint32_t vlan:1;
			uint32_t lso:1;
			uint32_t tcpcs:1;
			uint32_t udpcs:1;
			uint32_t ipcs:1;
			uint32_t rsvd3:1;
			uint32_t rsvd2:1;
			uint32_t forward:1;
			uint32_t crc:1;
			uint32_t event:1;
			uint32_t complete:1;

			/* dw3 */
			uint32_t vlan_tag:16;
			uint32_t total_length:16;
#else
			/* dw0 */
			uint32_t rsvd0;

			/* dw1 */
			uint32_t rsvd1:18;
			uint32_t last_seg_udp_len:14;

			/* dw2 */
			uint32_t complete:1;
			uint32_t event:1;
			uint32_t crc:1;
			uint32_t forward:1;
			uint32_t rsvd2:1;
			uint32_t rsvd3:1;
			uint32_t ipcs:1;
			uint32_t udpcs:1;
			uint32_t tcpcs:1;
			uint32_t lso:1;
			uint32_t vlan:1;
			uint32_t rsvd4:2;
			uint32_t num_wqe:5;
			uint32_t lso_mss:14;

			/* dw3 */
			uint32_t total_length:16;
			uint32_t vlan_tag:16;
#endif
		}s;
		uint32_t dw[4];
	}u0;
};

/* NIC fragment WQE */
struct oce_nic_frag_wqe {
	union {
		struct {
			/* dw0 */
			uint32_t frag_pa_hi;
			/* dw1 */
			uint32_t frag_pa_lo;
			/* dw2 */
			uint32_t rsvd0;
			uint32_t frag_len;
		}s;
		uint32_t dw[4];
	}u0;
};

/* Ethernet Tx Completion Descriptor */
struct oce_nic_tx_cqe {
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw 0 */
			uint32_t status:4;
			uint32_t rsvd0:8;
			uint32_t port:2;
			uint32_t ct:2;
			uint32_t wqe_index:16;

			/* dw 1 */
			uint32_t rsvd1:5;
			uint32_t cast_enc:2;
			uint32_t lso:1;
			uint32_t nwh_bytes:8;
			uint32_t user_bytes:16;

			/* dw 2 */
			uint32_t rsvd2;


			/* dw 3 */
			uint32_t valid:1;
			uint32_t rsvd3:4;
			uint32_t wq_id:11;
			uint32_t num_pkts:16;
#else
			/* dw 0 */
			uint32_t wqe_index:16;
			uint32_t ct:2;
			uint32_t port:2;
			uint32_t rsvd0:8;
			uint32_t status:4;

			/* dw 1 */
			uint32_t user_bytes:16;
			uint32_t nwh_bytes:8;
			uint32_t lso:1;
			uint32_t cast_enc:2;
			uint32_t rsvd1:5;
			/* dw 2 */
			uint32_t rsvd2;

			/* dw 3 */
			uint32_t num_pkts:16;
			uint32_t wq_id:11;
			uint32_t rsvd3:4;
			uint32_t valid:1;
#endif
		}s;
		uint32_t dw[4];
	}u0;
};
#define	WQ_CQE_VALID(_cqe)  (_cqe->u0.dw[3])
#define	WQ_CQE_INVALIDATE(_cqe)  (_cqe->u0.dw[3] = 0)

/* Receive Queue Entry (RQE) */
struct oce_nic_rqe {
	union {
		struct {
			uint32_t frag_pa_hi;
			uint32_t frag_pa_lo;
		}s;
		uint32_t dw[2];
	}u0;
};

/* NIC Receive CQE */
struct oce_nic_rx_cqe {
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw 0 */
			uint32_t ip_options:1;
			uint32_t vlan_tag_present:1;
			uint32_t pkt_size:14;
			uint32_t vlan_tag:16;

			/* dw 1 */
			uint32_t num_fragments:3;
			uint32_t switched:1;
			uint32_t ct:2;
			uint32_t frag_index:10;
			uint32_t rsvd0:1;
			uint32_t mac_dst:7;
			uint32_t ip_ver:1;
			uint32_t l4_cksum_pass:1;
			uint32_t ip_cksum_pass:1;
			uint32_t udpframe:1;
			uint32_t tcpframe:1;
			uint32_t ipframe:1;
			uint32_t rss_hp:1;
			uint32_t error:1;

			/* dw 2 */
			uint32_t valid:1;
			uint32_t rsvd2:13;
			uint32_t hds_type:2;
			uint32_t hds_hdr_size:8;
			uint32_t vntagp:1;
			uint32_t port:2;
			uint32_t rss_bank:1;
			uint32_t qnq:1;
			uint32_t pkt_type:2;
			uint32_t rss_flush:1;

			/* dw 3 */
			uint32_t rss_hash_value;
#else
			/* dw 0 */
			uint32_t vlan_tag:16;
			uint32_t pkt_size:14;
			uint32_t vlan_tag_present:1;
			uint32_t ip_options:1;
			/* dw 1 */
			uint32_t error:1;
			uint32_t rss_hp:1;
			uint32_t ipframe:1;
			uint32_t tcpframe:1;
			uint32_t udpframe:1;
			uint32_t ip_cksum_pass:1;
			uint32_t l4_cksum_pass:1;
			uint32_t ip_ver:1;
			uint32_t mac_dst:7;
			uint32_t rsvd0:1;
			uint32_t frag_index:10;
			uint32_t ct:2;
			uint32_t switched:1;
			uint32_t num_fragments:3;

			/* dw 2 */
			uint32_t rss_flush:1;
			uint32_t pkt_type:2;
			uint32_t qnq:1;
			uint32_t rss_bank:1;
			uint32_t port:2;
			uint32_t vntagp:1;
			uint32_t hds_hdr_size:8;
			uint32_t hds_type:2;
			uint32_t rsvd2:13;
			uint32_t valid:1;

			/* dw 3 */
			uint32_t rss_hash_value;
#endif
		}s;	/* native mode(BE3) */
		struct {
#ifdef _BIG_ENDIAN
			/* dw 0 */
			uint32_t ip_options:1;
			uint32_t port:1;
			uint32_t pkt_size:14;
			uint32_t vlan_tag:16;

			/* dw 1 */
			uint32_t num_fragments:3;
			uint32_t switched:1;
			uint32_t ct:2;
			uint32_t frag_index:10;
			uint32_t rsvd0:1;
			uint32_t vlan_tag_present:1;
			uint32_t mac_dst:6;
			uint32_t ip_ver:1;
			uint32_t l4_cksum_pass:1;
			uint32_t ip_cksum_pass:1;
			uint32_t udpframe:1;
			uint32_t tcpframe:1;
			uint32_t ipframe:1;
			uint32_t rss_hp:1;
			uint32_t error:1;

			/* dw 2 */
			uint32_t valid:1;
			uint32_t rsvd2:2;
			uint32_t lro_pkt:1;
			uint32_t rsvd1:23;
			uint32_t rss_bank:1;
			uint32_t qnq:1;
			uint32_t pkt_type:2;
			uint32_t rss_flush:1;

			/* dw 3 */
			uint32_t rss_hash_value;
#else
			/* dw 0 */
			uint32_t vlan_tag:16;
			uint32_t pkt_size:14;
			uint32_t port:1;
			uint32_t ip_options:1;
			/* dw 1 */
			uint32_t error:1;
			uint32_t rss_hp:1;
			uint32_t ipframe:1;
			uint32_t tcpframe:1;
			uint32_t udpframe:1;
			uint32_t ip_cksum_pass:1;
			uint32_t l4_cksum_pass:1;
			uint32_t ip_ver:1;
			uint32_t mac_dst:6;
			uint32_t vlan_tag_present:1;
			uint32_t rsvd0:1;
			uint32_t frag_index:10;
			uint32_t ct:2;
			uint32_t switched:1;
			uint32_t num_fragments:3;

			/* dw 2 */
			uint32_t rss_flush:1;
			uint32_t pkt_type:2;
			uint32_t qnq:1;
			uint32_t rss_bank:1;
			uint32_t rsvd1:23;
			uint32_t lro_pkt:1;
			uint32_t rsvd2:2;
			uint32_t valid:1;
			/* dw 3 */
			uint32_t rss_hash_value;
#endif
		}v0;	/* Legacy(BE2) */
		uint32_t dw[4];
	}u0;
};
#define	RQ_CQE_VALID_MASK  0x80
#define	RQ_CQE_VALID(_cqe) (_cqe->u0.dw[2])
#define	RQ_CQE_INVALIDATE(_cqe) (_cqe->u0.dw[2] = 0)

struct mbx_config_nic_promiscuous {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint16_t rsvd0;
			uint8_t port1_promisc;
			uint8_t port0_promisc;
#else
			uint8_t port0_promisc;
			uint8_t port1_promisc;
			uint16_t rsvd0;
#endif
		}req;

		struct {
			uint32_t rsvd0;
		}rsp;
	}params;
};

struct oce_tx_ctx {
#ifdef _BIG_ENDIAN
	/* dw0 */
	uint32_t rsvd0:12;
	uint32_t wq_size:4;
	uint32_t if_id:16;
	/* dw1 */
	uint32_t valid:1;
	uint32_t pd_id:9;
	uint32_t pci_function_id:8;
	uint32_t rsvd1:14;
	/* dw2 */
	uint32_t rsvd2_1:1;
	uint32_t no_rem_allowed:1;
	uint32_t rsvd2:14;
	uint32_t cq_id:16;
	/* dw3 */
	uint32_t rsvd3;
	/* dw4 */
	uint32_t rsvd4_1:10;
	uint32_t cofe:1;
	uint32_t rsvd4:21;
#else
	/* dw0 */
	uint32_t if_id:16;
	uint32_t wq_size:4;
	uint32_t rsvd0:12;
	/* dw1 */
	uint32_t rsvd1:14;
	uint32_t pci_function_id:8;
	uint32_t pd_id:9;
	uint32_t valid:1;
	/* dw2 */
	uint32_t cq_id:16;
	uint32_t rsvd2:14;
	uint32_t no_rem_allowed:1;
	uint32_t rsvd2_1:1;
	/*  dw3 */
	uint32_t rsvd3;
	/* dw4 */
	uint32_t rsvd4:21;
	uint32_t cofe:1;
	uint32_t rsvd4_1:10;
#endif
	/* dw5 - dw15 */
	uint32_t rsvd5[11];
};

/* [07] OPCODE_CREATE_NIC_WQ */
struct mbx_create_nic_wq {

	/* dw0 - dw3 */
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw4 */
			uint8_t	port;
			uint8_t	type;
			uint8_t	ulp_num;
			uint8_t	num_pages;
#else
			/* dw4 */
			uint8_t	num_pages;
			uint8_t	ulp_num;
			uint8_t	type;
			uint8_t	port;
#endif
			/* dw5 - dw20 */
			struct oce_tx_ctx ctx;
			/* dw21 - dw36 */
			struct phys_addr	pages[8];
		}req;

		struct {
			uint16_t	wq_id;
			uint16_t	rsvd0;
		}rsp;
	}params;
};

/* [09] OPCODE_DELETE_NIC_WQ */
struct mbx_delete_nic_wq {
	/* dw0 - dw3 */
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw4 */
			uint16_t	rsvd0;
			uint16_t	wq_id;
#else
			/* dw4 */
			uint16_t	wq_id;
			uint16_t	rsvd0;
#endif
		}req;
		struct {
			uint32_t	rsvd0;
		}rsp;
	}params;
};

/* [08] OPCODE_CREATE_NIC_RQ */
struct mbx_create_nic_rq {
	/* dw0 - dw3 */
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw4 */
			uint8_t	num_pages;
			uint8_t	frag_size;
			uint16_t cq_id;
#else
			/* dw4 */
			uint16_t cq_id;
			uint8_t	frag_size;
			uint8_t	num_pages;
#endif
			/* dw5 - dw8 */
			struct phys_addr pages[2];
			/* dw9 */
			uint32_t if_id;
#ifdef _BIG_ENDIAN
			/* dw10 */
			uint16_t rsvd0;
			uint16_t max_frame_size;
#else
			/* dw10 */
			uint16_t max_frame_size;
			uint16_t rsvd0;
#endif
			/* dw11 */
			uint32_t is_rss_queue;
		}req;

		struct {
			/* dw4 */
			union {
				struct {
					uint16_t rq_id;
					uint8_t rss_cpuid;
					uint8_t rsvd0;
				} s;
				uint32_t dw4;
			}u0;
		}rsp;
	}params;
};

/* [10] OPCODE_DELETE_NIC_RQ */
struct mbx_delete_nic_rq {
	/* dw0 - dw3 */
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			/* dw4 */
			uint16_t	bypass_flush;
			uint16_t	rq_id;
#else
			/* dw4 */
			uint16_t	rq_id;
			uint16_t	bypass_flush;
#endif
		}req;

		struct {
			/* dw4 */
			uint32_t	rsvd0;
		}rsp;
	}params;
};

struct rx_port_stats_v0 {
	uint32_t rx_bytes_lsd;
	uint32_t rx_bytes_msd;
	uint32_t rx_total_frames;
	uint32_t rx_unicast_frames;
	uint32_t rx_multicast_frames;
	uint32_t rx_broadcast_frames;
	uint32_t rx_crc_errors;
	uint32_t rx_alignment_symbol_errors;
	uint32_t rx_pause_frames;
	uint32_t rx_control_frames;
	uint32_t rx_in_range_errors;
	uint32_t rx_out_range_errors;
	uint32_t rx_frame_too_long;
	uint32_t rx_address_match_errors;
	uint32_t rx_vlan_mismatch;
	uint32_t rx_dropped_too_small;
	uint32_t rx_dropped_too_short;
	uint32_t rx_dropped_header_too_small;
	uint32_t rx_dropped_tcp_length;
	uint32_t rx_dropped_runt;
	uint32_t rx_64_byte_packets;
	uint32_t rx_65_127_byte_packets;
	uint32_t rx_128_256_byte_packets;
	uint32_t rx_256_511_byte_packets;
	uint32_t rx_512_1023_byte_packets;
	uint32_t rx_1024_1518_byte_packets;
	uint32_t rx_1519_2047_byte_packets;
	uint32_t rx_2048_4095_byte_packets;
	uint32_t rx_4096_8191_byte_packets;
	uint32_t rx_8192_9216_byte_packets;
	uint32_t rx_ip_checksum_errs;
	uint32_t rx_tcp_checksum_errs;
	uint32_t rx_udp_checksum_errs;
	uint32_t rx_non_rss_packets;
	uint32_t rx_ipv4_packets;
	uint32_t rx_ipv6_packets;
	uint32_t rx_ipv4_bytes_lsd;
	uint32_t rx_ipv4_bytes_msd;
	uint32_t rx_ipv6_bytes_lsd;
	uint32_t rx_ipv6_bytes_msd;
	uint32_t rx_chute1_packets;
	uint32_t rx_chute2_packets;
	uint32_t rx_chute3_packets;
	uint32_t rx_management_packets;
	uint32_t rx_switched_unicast_packets;
	uint32_t rx_switched_multicast_packets;
	uint32_t rx_switched_broadcast_packets;
	uint32_t tx_bytes_lsd;
	uint32_t tx_bytes_msd;
	uint32_t tx_unicast_frames;
	uint32_t tx_multicast_frames;
	uint32_t tx_broadcast_frames;
	uint32_t tx_pause_frames;
	uint32_t tx_control_frames;
	uint32_t tx_64_byte_packets;
	uint32_t tx_65_127_byte_packets;
	uint32_t tx_128_256_byte_packets;
	uint32_t tx_256_511_byte_packets;
	uint32_t tx_512_1023_byte_packets;
	uint32_t tx_1024_1518_byte_packets;
	uint32_t tx_1519_2047_byte_packets;
	uint32_t tx_2048_4095_byte_packets;
	uint32_t tx_4096_8191_byte_packets;
	uint32_t tx_8192_9216_byte_packets;
	uint32_t rx_fifo_overflow;
	uint32_t rx_input_fifo_overflow;
};


struct rx_port_stats_v1 {
	uint32_t rx_bytes_lsd;
	uint32_t rx_bytes_msd;
	uint32_t rx_ipv4_bytes_lsd;
	uint32_t rx_ipv4_bytes_msd;
	uint32_t rx_ipv6_bytes_lsd;
	uint32_t rx_ipv6_bytes_msd;
	uint32_t tx_bytes_lsd;
	uint32_t tx_bytes_msd;
	uint32_t rx_total_frames;
	uint32_t rx_non_switched_unicast_frames;
	uint32_t rx_non_switched_multicast_frames;
	uint32_t rx_non_switched_broadcast_frames;
	uint32_t rx_crc_errors;
	uint32_t rx_alignment_symbol_errors;
	uint32_t rx_pause_frames;
	uint32_t rx_priority_pause_frames;
	uint32_t rx_control_frames;
	uint32_t rx_in_range_errors;
	uint32_t rx_out_range_errors;
	uint32_t rx_frame_too_long;
	uint32_t rx_address_match_errors;
	uint32_t rx_dropped_too_small;
	uint32_t rx_dropped_too_short;
	uint32_t rx_dropped_header_too_small;
	uint32_t rx_dropped_tcp_length;
	uint32_t rx_dropped_runt;
	uint32_t rx_64_byte_packets;
	uint32_t rx_65_127_byte_packets;
	uint32_t rx_128_256_byte_packets;
	uint32_t rx_256_511_byte_packets;
	uint32_t rx_512_1023_byte_packets;
	uint32_t rx_1024_1518_byte_packets;
	uint32_t rx_1519_2047_byte_packets;
	uint32_t rx_2048_4095_byte_packets;
	uint32_t rx_4096_8191_byte_packets;
	uint32_t rx_8192_9216_byte_packets;
	uint32_t rx_ip_checksum_errs;
	uint32_t rx_tcp_checksum_errs;
	uint32_t rx_udp_checksum_errs;
	uint32_t rx_non_rss_packets;
	uint32_t rx_ipv4_packets;
	uint32_t rx_ipv6_packets;
	uint32_t rx_chute1_packets;
	uint32_t rx_chute2_packets;
	uint32_t rx_chute3_packets;
	uint32_t rx_management_packets;
	uint32_t rx_switched_unicast_packets;
	uint32_t rx_switched_multicast_packets;
	uint32_t rx_switched_broadcast_packets;
	uint32_t tx_unicast_frames;
	uint32_t tx_multicast_frames;
	uint32_t tx_broadcast_frames;
	uint32_t tx_pause_frames;
	uint32_t tx_priority_pause_frames;
	uint32_t tx_control_frames;
	uint32_t tx_64_byte_packets;
	uint32_t tx_65_127_byte_packets;
	uint32_t tx_128_256_byte_packets;
	uint32_t tx_256_511_byte_packets;
	uint32_t tx_512_1023_byte_packets;
	uint32_t tx_1024_1518_byte_packets;
	uint32_t tx_1519_2047_byte_packets;
	uint32_t tx_2048_4095_byte_packets;
	uint32_t tx_4096_8191_byte_packets;
	uint32_t tx_8192_9216_byte_packets;
	uint32_t rxpp_fifo_overflow_drop;
	uint32_t rx_input_fifo_overflow_drop;
	uint32_t pmem_fifo_overflow_drop;
	uint32_t jabber_events;
	uint32_t rsvd2[3];
};


struct rx_stats_v0 {
	struct rx_port_stats_v0 port[2];
	uint32_t rx_drops_no_pbuf;
	uint32_t rx_drops_no_txpb;
	uint32_t rx_drops_no_erx_descr;
	uint32_t rx_drops_no_tpre_descr;
	uint32_t management_rx_port_packets;
	uint32_t management_rx_port_bytes;
	uint32_t management_rx_port_pause_frames;
	uint32_t management_rx_port_errors;
	uint32_t management_tx_port_packets;
	uint32_t management_tx_port_bytes;
	uint32_t management_tx_port_pause;
	uint32_t management_rx_port_rxfifo_overflow;
	uint32_t rx_drops_too_many_frags;
	uint32_t rx_drops_invalid_ring;
	uint32_t forwarded_packets;
	uint32_t rx_drops_mtu;
	uint32_t rsvd0[7];		/* fcoe is not relevent */
	uint32_t port0_jabber_events;
	uint32_t port1_jabber_events;
	uint32_t rsvd1[6];
};

struct rx_stats_v1 {
	struct rx_port_stats_v1 port[4];
	uint32_t rsvd0[2];
	uint32_t rx_drops_no_pbuf;
	uint32_t rx_drops_no_txpb;
	uint32_t rx_drops_no_erx_descr;
	uint32_t rx_drops_no_tpre_descr;
	uint32_t management_rx_port_packets;
	uint32_t management_rx_port_pause_frames;
	uint32_t management_rx_port_errors;
	uint32_t management_tx_port_packets;
	uint32_t management_tx_port_pause;
	uint32_t management_rx_port_rxfifo_overflow;
	uint32_t rx_drops_too_many_frags;
	uint32_t rx_drops_invalid_ring;
	uint32_t forwarded_packets;
	uint32_t rx_drops_mtu;
	uint32_t rsvd1[14];	/* fcoe is not relevent */
};

struct tx_counter {
	uint32_t pkts;
	uint32_t lsd;
	uint32_t msd;
};

struct tx_stats {
	struct tx_counter ct1pt0_xmt_ipv4_ctrs;
	struct tx_counter ct1pt0_xmt_ipv6_ctrs;
	struct tx_counter ct1pt0_rexmt_ipv4_ctrs;
	struct tx_counter ct1pt0_rexmt_ipv6_ctrs;
	struct tx_counter ct1pt1_xmt_ipv4_ctrs;
	struct tx_counter ct1pt1_xmt_ipv6_ctrs;
	struct tx_counter ct1pt1_rexmt_ipv4_ctrs;
	struct tx_counter ct1pt1_rexmt_ipv6_ctrs;
	struct tx_counter ct2pt0_xmt_ipv4_ctrs;
	struct tx_counter ct2pt0_xmt_ipv6_ctrs;
	struct tx_counter ct2pt0_rexmt_ipv4_ctrs;
	struct tx_counter ct2pt0_rexmt_ipv6_ctrs;
	struct tx_counter ct2pt1_xmt_ipv4_ctrs;
	struct tx_counter ct2pt1_xmt_ipv6_ctrs;
	struct tx_counter ct2pt1_rexmt_ipv4_ctrs;
	struct tx_counter ct2pt1_rexmt_ipv6_ctrs;
};

struct rx_err_stats_v0 {
	uint32_t rx_drops_no_fragments[44];
	uint32_t debug_wdma_sent_hold;
	uint32_t debug_wdma_pbfree_sent_hold;
	uint32_t debug_wdma_zerobyte_pbfree_sent_hold;
	uint32_t debug_pmem_pbuf_dealloc;
};

struct rx_err_stats_v1 {
	uint32_t rx_drops_no_fragments[68];
	uint32_t debug_wdma_sent_hold;
	uint32_t debug_wdma_pbfree_sent_hold;
	uint32_t debug_wdma_zerobyte_pbfree_sent_hold;
	uint32_t debug_pmem_pbuf_dealloc;
};

struct mem_stats {
	uint32_t eth_red_drops;
	uint32_t lro_red_drops;
	uint32_t ulp0_red_drops;
	uint32_t ulp1_red_drops;
	uint32_t rsvd;
	uint32_t global_red_drops;
};


struct be_hw_stats_v0 {
	struct rx_stats_v0 rx;
	struct tx_stats tx;
	struct rx_err_stats_v0 err_rx;
	struct mem_stats mem;
};

struct be_hw_stats_v1 {
	struct rx_stats_v1 rx;
	struct tx_stats tx;
	struct rx_err_stats_v1 err_rx;
	struct mem_stats mem;
	uint32_t rsvd1[18];
};


/* [04] OPCODE_GET_NIC_STATS */
struct mbx_get_nic_stats {
	/* dw0 - dw3 */
	struct mbx_hdr hdr;
	union {
		struct {
			uint32_t rsvd0;
		}req;

		union {
			struct be_hw_stats_v0 v0;
			struct be_hw_stats_v1 v1;
		}rsp;
	}params;
};

/* Lancer Stats */
struct lancer_cmd_pport_stats {
	uint32_t tx_packets_lo;
	uint32_t tx_packets_hi;
	uint32_t tx_unicast_packets_lo;
	uint32_t tx_unicast_packets_hi;
	uint32_t tx_multicast_packets_lo;
	uint32_t tx_multicast_packets_hi;
	uint32_t tx_broadcast_packets_lo;
	uint32_t tx_broadcast_packets_hi;
	uint32_t tx_bytes_lo;
	uint32_t tx_bytes_hi;
	uint32_t tx_unicast_bytes_lo;
	uint32_t tx_unicast_bytes_hi;
	uint32_t tx_multicast_bytes_lo;
	uint32_t tx_multicast_bytes_hi;
	uint32_t tx_broadcast_bytes_lo;
	uint32_t tx_broadcast_bytes_hi;
	uint32_t tx_discards_lo;
	uint32_t tx_discards_hi;
	uint32_t tx_errors_lo;
	uint32_t tx_errors_hi;
	uint32_t tx_pause_frames_lo;
	uint32_t tx_pause_frames_hi;
	uint32_t tx_pause_on_frames_lo;
	uint32_t tx_pause_on_frames_hi;
	uint32_t tx_pause_off_frames_lo;
	uint32_t tx_pause_off_frames_hi;
	uint32_t tx_internal_mac_errors_lo;
	uint32_t tx_internal_mac_errors_hi;
	uint32_t tx_control_frames_lo;
	uint32_t tx_control_frames_hi;
	uint32_t tx_packets_64_bytes_lo;
	uint32_t tx_packets_64_bytes_hi;
	uint32_t tx_packets_65_to_127_bytes_lo;
	uint32_t tx_packets_65_to_127_bytes_hi;
	uint32_t tx_packets_128_to_255_bytes_lo;
	uint32_t tx_packets_128_to_255_bytes_hi;
	uint32_t tx_packets_256_to_511_bytes_lo;
	uint32_t tx_packets_256_to_511_bytes_hi;
	uint32_t tx_packets_512_to_1023_bytes_lo;
	uint32_t tx_packets_512_to_1023_bytes_hi;
	uint32_t tx_packets_1024_to_1518_bytes_lo;
	uint32_t tx_packets_1024_to_1518_bytes_hi;
	uint32_t tx_packets_1519_to_2047_bytes_lo;
	uint32_t tx_packets_1519_to_2047_bytes_hi;
	uint32_t tx_packets_2048_to_4095_bytes_lo;
	uint32_t tx_packets_2048_to_4095_bytes_hi;
	uint32_t tx_packets_4096_to_8191_bytes_lo;
	uint32_t tx_packets_4096_to_8191_bytes_hi;
	uint32_t tx_packets_8192_to_9216_bytes_lo;
	uint32_t tx_packets_8192_to_9216_bytes_hi;
	uint32_t tx_lso_packets_lo;
	uint32_t tx_lso_packets_hi;
	uint32_t rx_packets_lo;
	uint32_t rx_packets_hi;
	uint32_t rx_unicast_packets_lo;
	uint32_t rx_unicast_packets_hi;
	uint32_t rx_multicast_packets_lo;
	uint32_t rx_multicast_packets_hi;
	uint32_t rx_broadcast_packets_lo;
	uint32_t rx_broadcast_packets_hi;
	uint32_t rx_bytes_lo;
	uint32_t rx_bytes_hi;
	uint32_t rx_unicast_bytes_lo;
	uint32_t rx_unicast_bytes_hi;
	uint32_t rx_multicast_bytes_lo;
	uint32_t rx_multicast_bytes_hi;
	uint32_t rx_broadcast_bytes_lo;
	uint32_t rx_broadcast_bytes_hi;
	uint32_t rx_unknown_protos;
	uint32_t rsvd_69;
	uint32_t rx_discards_lo;
	uint32_t rx_discards_hi;
	uint32_t rx_errors_lo;
	uint32_t rx_errors_hi;
	uint32_t rx_crc_errors_lo;
	uint32_t rx_crc_errors_hi;
	uint32_t rx_alignment_errors_lo;
	uint32_t rx_alignment_errors_hi;
	uint32_t rx_symbol_errors_lo;
	uint32_t rx_symbol_errors_hi;
	uint32_t rx_pause_frames_lo;
	uint32_t rx_pause_frames_hi;
	uint32_t rx_pause_on_frames_lo;
	uint32_t rx_pause_on_frames_hi;
	uint32_t rx_pause_off_frames_lo;
	uint32_t rx_pause_off_frames_hi;
	uint32_t rx_frames_too_long_lo;
	uint32_t rx_frames_too_long_hi;
	uint32_t rx_internal_mac_errors_lo;
	uint32_t rx_internal_mac_errors_hi;
	uint32_t rx_undersize_packets;
	uint32_t rx_oversize_packets;
	uint32_t rx_fragment_packets;
	uint32_t rx_jabbers;
	uint32_t rx_control_frames_lo;
	uint32_t rx_control_frames_hi;
	uint32_t rx_control_frames_unknown_opcode_lo;
	uint32_t rx_control_frames_unknown_opcode_hi;
	uint32_t rx_in_range_errors;
	uint32_t rx_out_of_range_errors;
	uint32_t rx_address_match_errors;
	uint32_t rx_vlan_mismatch_errors;
	uint32_t rx_dropped_too_small;
	uint32_t rx_dropped_too_short;
	uint32_t rx_dropped_header_too_small;
	uint32_t rx_dropped_invalid_tcp_length;
	uint32_t rx_dropped_runt;
	uint32_t rx_ip_checksum_errors;
	uint32_t rx_tcp_checksum_errors;
	uint32_t rx_udp_checksum_errors;
	uint32_t rx_non_rss_packets;
	uint32_t rsvd_111;
	uint32_t rx_ipv4_packets_lo;
	uint32_t rx_ipv4_packets_hi;
	uint32_t rx_ipv6_packets_lo;
	uint32_t rx_ipv6_packets_hi;
	uint32_t rx_ipv4_bytes_lo;
	uint32_t rx_ipv4_bytes_hi;
	uint32_t rx_ipv6_bytes_lo;
	uint32_t rx_ipv6_bytes_hi;
	uint32_t rx_nic_packets_lo;
	uint32_t rx_nic_packets_hi;
	uint32_t rx_tcp_packets_lo;
	uint32_t rx_tcp_packets_hi;
	uint32_t rx_iscsi_packets_lo;
	uint32_t rx_iscsi_packets_hi;
	uint32_t rx_management_packets_lo;
	uint32_t rx_management_packets_hi;
	uint32_t rx_switched_unicast_packets_lo;
	uint32_t rx_switched_unicast_packets_hi;
	uint32_t rx_switched_multicast_packets_lo;
	uint32_t rx_switched_multicast_packets_hi;
	uint32_t rx_switched_broadcast_packets_lo;
	uint32_t rx_switched_broadcast_packets_hi;
	uint32_t num_forwards_lo;
	uint32_t num_forwards_hi;
	uint32_t rx_fifo_overflow;
	uint32_t rx_input_fifo_overflow;
	uint32_t rx_drops_too_many_frags_lo;
	uint32_t rx_drops_too_many_frags_hi;
	uint32_t rx_drops_invalid_queue;
	uint32_t rsvd_141;
	uint32_t rx_drops_mtu_lo;
	uint32_t rx_drops_mtu_hi;
	uint32_t rx_packets_64_bytes_lo;
	uint32_t rx_packets_64_bytes_hi;
	uint32_t rx_packets_65_to_127_bytes_lo;
	uint32_t rx_packets_65_to_127_bytes_hi;
	uint32_t rx_packets_128_to_255_bytes_lo;
	uint32_t rx_packets_128_to_255_bytes_hi;
	uint32_t rx_packets_256_to_511_bytes_lo;
	uint32_t rx_packets_256_to_511_bytes_hi;
	uint32_t rx_packets_512_to_1023_bytes_lo;
	uint32_t rx_packets_512_to_1023_bytes_hi;
	uint32_t rx_packets_1024_to_1518_bytes_lo;
	uint32_t rx_packets_1024_to_1518_bytes_hi;
	uint32_t rx_packets_1519_to_2047_bytes_lo;
	uint32_t rx_packets_1519_to_2047_bytes_hi;
	uint32_t rx_packets_2048_to_4095_bytes_lo;
	uint32_t rx_packets_2048_to_4095_bytes_hi;
	uint32_t rx_packets_4096_to_8191_bytes_lo;
	uint32_t rx_packets_4096_to_8191_bytes_hi;
	uint32_t rx_packets_8192_to_9216_bytes_lo;
	uint32_t rx_packets_8192_to_9216_bytes_hi;
};

struct pport_stats_params {
	uint16_t pport_num;
	uint8_t rsvd;
	uint8_t reset_stats;
};

/* [18] OPCODE_NIC_GET_PPORT_STATS */
struct mbx_get_pport_stats {
	/* dw0 - dw3 */
	struct mbx_hdr hdr;
	union {
		struct {
			struct pport_stats_params arg;
		}req;

		struct {
			struct lancer_cmd_pport_stats pport_stats;
		}rsp;
	}params;
};

/* [01] OPCODE_CONFIG_NIC_RSS */
struct mbx_config_nic_rss {
	struct mbx_hdr hdr;
	union {
		struct {
#ifdef _BIG_ENDIAN
			uint32_t if_id;
			uint16_t cpu_tbl_sz_log2;
			uint16_t enable_rss;
			uint32_t hash[10];
			uint8_t cputable[128];
			uint8_t rsvd[3];
			uint8_t flush;
#else
			uint32_t if_id;
			uint16_t enable_rss;
			uint16_t cpu_tbl_sz_log2;
			uint32_t hash[10];
			uint8_t cputable[128];
			uint8_t flush;
			uint8_t rsvd[3];
#endif
		}req;
		struct {
			uint8_t rsvd[3];
			uint8_t rss_bank;
		}rsp;
	}params;
};

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* _OCE_HW_ETH_H_ */
