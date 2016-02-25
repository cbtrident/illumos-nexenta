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

/*
 * See special.c for details on the theory of operation
 */

#ifndef _SYS_SPECIAL_IMPL_H
#define	_SYS_SPECIAL_IMPL_H

#include <sys/special.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	SPA_SPECIAL_SELECTION_MIN,
	SPA_SPECIAL_SELECTION_LATENCY,
	SPA_SPECIAL_SELECTION_UTILIZATION,
	SPA_SPECIAL_SELECTION_QUEUE,
	SPA_SPECIAL_SELECTION_MAX
} spa_special_selection_t;

#define	SPA_SPECIAL_SELECTION_VALID(sel)	\
	(((sel) > SPA_SPECIAL_SELECTION_MIN) &&	\
	((sel) < SPA_SPECIAL_SELECTION_MAX))

/*
 * class cumulative statistics:
 *
 * utilization:  utilization, measured as the percentage of time
 *               for which the device was busy servicing I/O requests
 *               during the sample interval
 * throughput:   throughput for read and write in kilobytes per second
 * iops:         input/output operations per second
 * run_len:      number of commands being processed in the active
 *               queue that the class is working on simultaneously
 * wait_len:     number of commands waiting in the queues that
 *               have not been sent to the class yet
 * queue_len:    total number of commands in the queues
 * run_time:     time in microseconds for an operation to complete
 *               after it has been dequeued from the wait queue
 * wait_time:    time in microseconds for which operations are
 *               queued before they are run
 * service_time: time in microseconds to queue and complete an I/O operation
 * count:        number of vdev's per class
 */
typedef struct cos_acc_stat {
	uint64_t utilization;
	uint64_t throughput;
	uint64_t iops;
	uint64_t run_len;
	uint64_t wait_len;
	uint64_t queue_len;
	uint64_t run_time;
	uint64_t wait_time;
	uint64_t service_time;
	uint64_t count;
} cos_acc_stat_t;

/*
 * spa cumulative statistics:
 *
 * utilization, %
 * latency,     microseconds
 * throughput,  KB/s
 * count:       number of accumulated statistics
 */
typedef struct spa_acc_stat {
	uint64_t spa_utilization;
	uint64_t special_utilization;
	uint64_t normal_utilization;
	uint64_t special_latency;
	uint64_t normal_latency;
	uint64_t special_throughput;
	uint64_t normal_throughput;
	uint64_t count;
} spa_acc_stat_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SPECIAL_IMPL_H */
