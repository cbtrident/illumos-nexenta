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

#ifndef _VIOSCSI_H_
#define _VIOSCSI_H_

#ifdef __cplusplus
extern "C" {
#endif
	
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>

#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/stddef.h>

#include <virtio.h>

#define VIRTIO_SCSI_CDB_SIZE	32
#define	VIRTIO_SCSI_SENSE_SIZE	96

/* Feature bits */
#define VIRTIO_SCSI_F_INOUT	(0x1 << 0)
#define VIRTIO_SCSI_F_HOTPLUG	(0x1 << 1)
#define	VIRTIO_SCSI_F_CHANGE	(0x1 << 2)
#define VIRTIO_SCSI_F_T10_PI	(0x1 << 3)

/* registers offset in bytes */
#define VIRTIO_SCSI_CFG_NUM_QUEUES	0
#define VIRTIO_SCSI_CFG_SEG_MAX		4
#define VIRTIO_SCSI_CFG_MAX_SECTORS	8
#define VIRTIO_SCSI_CFG_CMD_PER_LUN	12
#define VIRTIO_SCSI_CFG_EVI_SIZE	16
#define VIRTIO_SCSI_CFG_SENSE_SIZE	20
#define VIRTIO_SCSI_CFG_CDB_SIZE	24
#define VIRTIO_SCSI_CFG_MAX_CHANNEL	28
#define VIRTIO_SCSI_CFG_MAX_TARGET	30
#define VIRTIO_SCSI_CFG_MAX_LUN		32

/* response codes */
#define VIRTIO_SCSI_S_OK			0
#define VIRTIO_SCSI_S_FUNCTION_COMPLETED	0
#define VIRTIO_SCSI_S_OVERRUN			1
#define VIRTIO_SCSI_S_ABORTED			2
#define VIRTIO_SCSI_S_BAD_TARGET		3
#define VIRTIO_SCSI_S_RESET			4
#define VIRTIO_SCSI_S_BUSY			5
#define VIRTIO_SCSI_S_TRANSPORT_FAILURE		6
#define VIRTIO_SCSI_S_TARGET_FAILURE		7
#define VIRTIO_SCSI_S_NEXUS_FAILURE		8
#define VIRTIO_SCSI_S_FAILURE			9
#define VIRTIO_SCSI_S_FUNCTION_SUCCEEDED	10
#define VIRTIO_SCSI_S_FUNCTION_REJECTED		11
#define VIRTIO_SCSI_S_INCORRECT_LUN		12

/* Controlq type codes */
#define VIRTIO_SCSI_T_TMF			0
#define VIRTIO_SCSI_T_AN_QUERY			1
#define VIRTIO_SCSI_T_AN_SUBSCRIBE		2

/* events */
#define VIRTIO_SCSI_T_EVENTS_MISSED		0x80000000
#define VIRTIO_SCSI_T_NO_EVENT			0
#define VIRTIO_SCSI_T_TRANSPORT_RESET		1
#define VIRTIO_SCSI_T_ASYNC_NOTIFY		2

#define VIOSCSI_MAX_TARGET     			256
#define VIOSCSI_MAX_LUN				16 // KVM supports a lot more
#define VIOSCSI_MIN_SEGS			3

/*reasons of reset event */
#define VIRTIO_SCSI_EVT_RESET_HARD		0
#define VIRTIO_SCSI_EVT_RESET_RESCAN		1
#define VIRTIO_SCSI_EVT_RESET_REMOVED		2

#define MAX_NAME_PROP_SIZE                      256
#define LUN_PROP                                "lun"
#define LUN64_PROP                              "lun64"
#define TARGET_PROP                             "target"
#define LUN_PROP                                "lun"
#define COMPAT_PROP                             "compatible"

#define	VIRTIO_SCSI_WANTED_FEATURES	(VIRTIO_SCSI_F_INOUT |		\
					VIRTIO_SCSI_F_HOTPLUG |		\
					VIRTIO_SCSI_F_CHANGE |		\
					VIRTIO_SCSI_F_T10_PI)
/* Data structures */

#pragma pack(1)
/* virtio SCSI command request */
struct virtio_scsi_cmd_req {
	uint8_t lun[8];
	uint64_t tag;
	uint8_t	task_attr;
	uint8_t	prio;
	uint8_t crn;
	uint8_t cdb[VIRTIO_SCSI_CDB_SIZE];
};

/* virtio SCSI response */
struct virtio_scsi_cmd_resp {
	uint32_t sense_len;
	uint32_t res_id;
	uint16_t status_qualifier;
	uint8_t	status;
	uint8_t response;
	uint8_t sense[VIRTIO_SCSI_SENSE_SIZE];
};

/*Task managment request */
struct virtio_scsi_ctrl_tmf_req {
	uint32_t type;
	uint32_t subtype;
	uint8_t  lun[8];
	uint64_t tag;
};

struct virtio_scsi_ctrl_tmf_resp {
	uint8_t response;
};

/* asynchronous notification query/subscription */
struct virtio_scsi_ctrl_an_req {
	uint32_t type;
	uint8_t lun[8];
	uint32_t event_requested;
};

struct virtio_scsi_ctrl_an_resp {
	uint32_t event_actual;
	uint8_t	response;
};

struct virtio_scsi_event {
	
	uint32_t event;
	uint8_t lun[8];
	uint32_t reason;
};
#pragma pack()

#define VIOSCSI_BUFFER_ALLOCATED  0x1
#define VIOSCSI_BUFFER_FREE       0x2

typedef struct vioscsi_buffer {
	uint8_t			vb_state; /* state of the buffer - allocated/free */
	caddr_t			vb_virt; /* virtual address of the buffer */
	ddi_dma_handle_t	vb_dmah; /*  DMA handle */
	ddi_dma_cookie_t	vb_dmac; /* first cookie in the chain */
	ddi_acc_handle_t	vb_acch;  /* access handle for DMA buffer memory */
	uint32_t		vb_ncookies; /* number of cookies */
	uint32_t		vb_nwins; /* number of DMA windows NOTUSED */
} vioscsi_buffer_t;

typedef struct vioscsi_request {
	
	struct scsi_pkt		*vr_req_pkt; /* SCSA packet we are servicing */
	struct vq_entry		*vr_ve; /* Set for debug only */
	
	/*
	 * first buffer is for virtio scsi headers/stuff
	 * second one - for data payload
	 */
	struct vioscsi_buffer	vr_headers_buf;
} vioscsi_request_t;

typedef struct vioscsi_dev {
	list_node_t		vd_node;
	dev_info_t		*vd_dip;
	uint8_t			vd_target;
	uint16_t		vd_lun;
} vioscsi_dev_t;

typedef struct vioscsi_softc {
	dev_info_t		*vs_dip; /* mirrors virtio_softc->vs_dip */
	virtio_t		*vs_virtio;
	uint64_t		vs_features;
	
	virtio_queue_t		*vs_ctrl_vq;
	virtio_queue_t		*vs_event_vq;
	virtio_queue_t		*vs_rqst_vq;
	
	scsi_hba_tran_t		*vs_hba_tran;
	boolean_t		vs_poll_done; /* true if the request is completed */
	uint32_t		vs_max_target;
	uint32_t		vs_max_lun;
	uint32_t		vs_cdb_size;
	uint32_t		vs_max_seg;
	
	/* ---- maximal number of requests ---- */
	kmutex_t		vs_devs_mutex;
	list_t			vs_devs;
	struct vioscsi_buffer	vs_events[4];	/* NOTUSED */
} vioscsi_softc_t;

#ifdef __cplusplus
}
#endif

#endif /* _VIOSCSI_H_ */
