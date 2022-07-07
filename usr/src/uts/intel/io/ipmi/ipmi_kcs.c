/*
 * Copyright (c) 2006 IronPort Systems Inc. <ambrisko@ironport.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2013, Joyent, Inc.  All rights reserved.
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/disp.h>
#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ipmi.h>

#include "ipmivars.h"

static int	kcs_clear_obf(struct ipmi_softc *, int);
static int	kcs_abort(struct ipmi_softc *);
static int	kcs_wait_for_ibf(struct ipmi_softc *, int, int);
static int	kcs_wait_for_obf(struct ipmi_softc *, int, int);

#define	BUSY_RETRY_USECS	200	/* Busy wait interval, microsec */
#define	BUSY_RETRY_MIN_USECS	4	/* Waits are 2-3 microsecs on typical */
					/* systems */
#define	IDLE_RETRY_USECS	5000	/* Idle wait interval, microsec */
#define	BUSY_WAIT_USECS		600	/* Number of microsec to busy wait */

/*
 * Althought the default values work quite well for SuperMicro X8/X9
 * it might be useful to allow fine tuning if necessary.
 */
int ipmikcs_busywait_interval = BUSY_RETRY_USECS;
int ipmikcs_busywait_interval_min = BUSY_RETRY_MIN_USECS;
int ipmikcs_idlewait_interval = IDLE_RETRY_USECS;
int ipmikcs_busywait_usec = BUSY_WAIT_USECS;

/*
 * Variables to enable us to tweek the read_byte timeouts in milliseconds.
 * One for the first read of a command and another for everything else.
 */
uint32_t ipmikcs_first_read_to = 3000;
uint32_t ipmikcs_def_read_to = 1000;

/*
 * Table of descriptions for returned codes, first phases, use KCSTO_PHASE()
 * on values. Followed by reasons, use KCS_REASON().
 */
static char *kcs_phases[] = {
	/* 0  */ "Pre Write", "Write Address", "Write Command", "Write Data",
	/* 4  */ "Read NetFn/LUN", "Read NetFn/LUN (KS)", "Read Command",
	/* 7  */ "Read Completion", "Read Data", "Abort"
};

static char *kcs_reasons[] = {
	/* 0  */ "", "Success (Idle)", "Success (Underrun)",
	/* 3  */ "Success (Overrun)", "Success", "IBF Stuck high",
	/* 6  */ "OBF stuck high before write state",
	/* 7  */ "Did not enter WRITE state",
	/* 8  */ "OBF stuck high after write state",
	/* 9  */ "IBF stays high after write byte",
	/* 10 */ "Exited write state after write byte",
	/* 11 */ "OBF stuck high after write byte",
	/* 12 */ "IBF stays high after write last byte",
	/* 13 */ "Exited write state after write last byte",
	/* 14 */ "OBF stuck high after write last byte",
	/* 15 */ "IBF stays high after write state finished",
	/* 16 */ "No transition to read state",
	/* 17 */ "IBF stuck high before read byte",
	/* 18 */ "No OBF for read", "No OBF for idle",
	/* 20 */ "Unexpected state for read byte",
	/* 21 */ "Reply address mismatch", "Reply command mismatch",
	/* 23 */ "IBF stays high after get status abort",
	/* 24 */ "OBF stuck high after get status abort",
	/* 25 */ "IBF stuck high before sending abort 00",
	/* 26 */ "IBF stuck high after abort read",
	/* 27 */ "No idle state during abort",
	/* 28 */ "OBF stuck high after abort idle",
	/* 29 */ "Unexpected Idle state during read",
	/* 30 */ "Unexpected Idle state after read kick start"
};

#ifdef KCS_LOG
struct kcs_log {
	hrtime_t	kcsl_tstamp;
	uint8_t		kcsl_reg;
	uint8_t		kcsl_value;
	uint8_t		kcsl_dir;
	uint8_t		kcsl_repcount;
	uint32_t	kcsl_marker;
};

/*
 * Use two buffers, one is always active, the other gets a copy of the data
 * at suitable times so we can actually see the previous activity at
 * points of interest.
 */
static struct kcs_log	kcs_active_log[256];
static struct kcs_log	kcs_error_log[256];
static int kcs_seen_SMS_ATN = 0;

static uint8_t
kcs_inb(struct ipmi_softc *sc, uint8_t reg)
{
	uint8_t		val;
	struct kcs_log	*klog;
	uint32_t	mval = 0;

	klog = &kcs_active_log[sc->ipmi_kcsl_index];
	val = inb(sc->ipmi_io_address + (sc->ipmi_io_spacing * reg));
	if (reg == 1 && (val & KCS_STATUS_SMS_ATN)) {
		if (!kcs_seen_SMS_ATN) {
			cmn_err(CE_WARN, "KCS SMS_ATN seen");
			kcs_seen_SMS_ATN = 1;
		}
		mval = 0xcafecafe;
	}
	if (val == klog->kcsl_value && reg == klog->kcsl_reg &&
	    klog->kcsl_dir == 0) {
		if (mval)
			klog->kcsl_marker = mval;
		klog->kcsl_repcount++;
	} else {
		klog = &kcs_active_log[++(sc->ipmi_kcsl_index)];
		klog->kcsl_tstamp = gethrtime() -
		    sc->ipmi_kcsl_ctstamp;
		klog->kcsl_reg = reg;
		klog->kcsl_dir = 0;
		klog->kcsl_marker = mval;
		klog->kcsl_value = val;
		klog->kcsl_repcount = 0;
	}
	if (mval) {
		bcopy(kcs_active_log, kcs_error_log, sizeof (kcs_active_log));
	}
	return (val);
}

static void
kcs_outb(struct ipmi_softc *sc, uint8_t reg, uint8_t value)
{
	struct kcs_log	*klog;

	klog = &kcs_active_log[++(sc->ipmi_kcsl_index)];
	klog->kcsl_tstamp = gethrtime() - sc->ipmi_kcsl_ctstamp;
	klog->kcsl_reg = reg;
	klog->kcsl_dir = 1;
	klog->kcsl_marker = 0;
	klog->kcsl_value = value;
	klog->kcsl_repcount = 0;
	outb(sc->ipmi_io_address + (sc->ipmi_io_spacing * reg), value);
}

static void
kcs_log_entry(struct ipmi_softc *sc, uint8_t reg, uint8_t value, uint8_t dir,
    uint8_t rcount, uint32_t mark)
{
	struct kcs_log	*klog;

	klog = &kcs_active_log[++(sc->ipmi_kcsl_index)];

	klog->kcsl_reg = reg;
	klog->kcsl_value = value;
	klog->kcsl_dir = dir;
	klog->kcsl_repcount = rcount;
	klog->kcsl_marker = mark;
	if (mark == 0x1110cd) { /* Begining of cmd */
		sc->ipmi_kcsl_ctstamp = gethrtime();
		klog->kcsl_tstamp = sc->ipmi_kcsl_ctstamp;
	} else {
		klog->kcsl_tstamp = gethrtime() -
		    sc->ipmi_kcsl_ctstamp;
	}
}

#endif /* KCS_LOG */

/*
 * Wait for the requested buffer flags in the requested state.
 */
static int
kcs_wait_for_bf(struct ipmi_softc *sc, int state, uint8_t bflag, int mstimeout)
{
	int		status;
	hrtime_t	now = gethrtime();
	hrtime_t	nsto = now + MSEC2NSEC(mstimeout);
	hrtime_t	nsbsyto = now + USEC2NSEC(ipmikcs_busywait_usec);
	int		busy_wait_usecs = ipmikcs_busywait_interval_min;
	uint8_t		bfcmp;

	if (state == 0)
		/* WAIT FOR BF = 0 */
		bfcmp = 0;
	else
		/* WAIT FOR BF = 1 */
		bfcmp = bflag;

	/*
	 * Because this is usually where we are when we need to wait
	 * for the BMC to go get the data in order to respond to a
	 * command do this in 2 stages, first busy wait, then do non
	 * busy wait via delay().
	 * Note that we can get pinned by interrupt threads but
	 * we are really just interested in the time since we started
	 * to wait. Provided we always test status after any period of
	 * waiting we should be ok.
	 */
	while (((status = INB(sc, KCS_CTL_STS)) & bflag) != bfcmp) {
		now = gethrtime();
		if (now > nsto)
			break;
		if (now > nsbsyto) {
			delay(drv_usectohz(ipmikcs_idlewait_interval));
		} else {
			drv_usecwait(busy_wait_usecs);
			busy_wait_usecs *= 2;
		}
	}
	return (status);
}

static int
kcs_wait_for_ibf(struct ipmi_softc *sc, int state, int mstimeout)
{
	return (kcs_wait_for_bf(sc, state, KCS_STATUS_IBF, mstimeout));
}

static int
kcs_wait_for_obf(struct ipmi_softc *sc, int state, int mstimeout)
{
	return (kcs_wait_for_bf(sc, state, KCS_STATUS_OBF, mstimeout));
}

static int
kcs_clear_obf(struct ipmi_softc *sc, int status)
{
	/* Clear OBF */
	if (status & KCS_STATUS_OBF) {
		(void) INB(sc, KCS_DATA);
		status = kcs_wait_for_obf(sc, 0, 500);
	}

	return (status);
}

static int
kcs_abort(struct ipmi_softc *sc)
{
	int retry, status, entry_status, rval;
	uchar_t istat = 0;

#ifdef KCS_LOG
	/* Add unique entry to log */
	kcs_log_entry(sc, 0, 0, 0, 0, 0x1110ab);
#endif
	entry_status = INB(sc, KCS_CTL_STS);

	for (retry = 0; retry < 2; retry++) {

		if (retry != 0) {
			delay(drv_usectohz(10000));
		}

		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0, 200);
		if (status & KCS_STATUS_IBF) {
			rval = KCSTO_IBF_STUCK_HIGH | KCSPH_ABORT;
			continue;
		}

		/* ABORT */
		OUTB(sc, KCS_CTL_STS, KCS_CONTROL_GET_STATUS_ABORT);

		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0, 200);
		if (status & KCS_STATUS_IBF) {
			rval = KCSTO_IBF_STAYS_HIGH_AFTER_GSA | KCSPH_ABORT;
			continue;
		}

		/* Clear OBF */
		status = kcs_clear_obf(sc, status);

		if (status & KCS_STATUS_OBF) {
			rval = KCSTO_OBF_STUCK_HIGH_BEFORE_00 | KCSPH_ABORT;
			continue;
		}

		/* 0x00 to DATA_IN */
		OUTB(sc, KCS_DATA, 0x00);

		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0, 200);

		/* Need READ state next */
		if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_READ) {
			rval = KCSTO_NO_READ_STATE | KCSPH_ABORT;
			continue;
		}

		/* Wait for OBF = 1 */
		status = kcs_wait_for_obf(sc, 1, 200);
		if (!(status & KCS_STATUS_OBF)) {
			rval = KCSTO_NO_OBF_FOR_READ | KCSPH_ABORT;
			continue;
		}

		/* Read error status */
		istat = INB(sc, KCS_DATA);
#if 0
		if (istat != 0) {
			int ce_level = CE_WARN;
			/*
			 * 1 is a transfer abort commonly associated
			 * with a read transaction happening too
			 * quickly after the transfer phase changes to
			 * KCS_STATUS_STATE_READ.
			 * Treat it as a noteworthy event rather than
			 * an error event and avoid polluting the
			 * console with many warnings.
			 */
			if (istat == 1) {
				ce_level = CE_NOTE;
			}
			cmn_err(ce_level,
			    "KCS error: 0x%02x, status on entry 0x%02x",
			    istat, entry_status);
		}
#endif

		/* Write READ into Data_in */
		OUTB(sc, KCS_DATA, KCS_DATA_IN_READ);

		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0, 200);
		if (status & KCS_STATUS_IBF) {
			rval = KCSTO_IBF_STAYS_HIGH_AFTER_ABT_READ |
			    KCSPH_ABORT;
			continue;
		}

		/* IDLE STATE */
		if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_IDLE) {
			rval = KCSTO_NO_IDLE_STATE | KCSPH_ABORT;
			continue;
		}

		/* Wait for OBF = 1 */
		status = kcs_wait_for_obf(sc, 1, 200);
		if (!(status & KCS_STATUS_OBF)) {
			rval = KCSTO_NO_OBF_FOR_IDLE | KCSPH_ABORT;
			continue;
		}

		/* Clear OBF */
		status = kcs_clear_obf(sc, status);
		if (status & KCS_STATUS_OBF) {
			rval = KCSTO_OBF_STUCK_HIGH_AFTER_IDLE | KCSPH_ABORT;
			continue;
		}
#ifdef KCS_LOG
		/* Add unique entry to log */
		kcs_log_entry(sc, 0, istat, 0, (uint8_t)retry, 0x2220ab);
		bcopy(kcs_active_log, kcs_error_log,
		    sizeof (kcs_active_log));
#endif
		return (KCS_SUCCESS);
	}
#ifdef KCS_LOG
	/* Add unique entry to log */
	kcs_log_entry(sc, 0, istat, 0, (uint8_t)retry, 0xbad0ab);
	bcopy(kcs_active_log, kcs_error_log, sizeof (kcs_active_log));
#endif
	cmn_err(CE_WARN, "KCS Abort: Retry exhausted, %s, Ph: %s (0x%x),"
	    "  CtlStatus (On Entry) 0x%x, Error Code 0x%x",
	    kcs_reasons[KCS_REASON(rval)], kcs_phases[KCS_PHASE(rval)],
	    rval, entry_status, istat);
	return (rval);
}

/*
 * Start to write a request.  Waits for IBF to clear and then sends the
 * WR_START command.
 */
static int
kcs_start_write(struct ipmi_softc *sc)
{
	int status;

	/* Wait for IBF = 0 */
	status = kcs_wait_for_ibf(sc, 0, 200);
	if (status & KCS_STATUS_IBF) {
		return (KCSTO_IBF_STUCK_HIGH);
	}

	/* Clear OBF */
	status = kcs_clear_obf(sc, status);
	if (status & KCS_STATUS_OBF) {
		return (KCSTO_OBF_STUCK_HIGH_BEFORE_WS);
	}

	/* Write start to command */
	OUTB(sc, KCS_CTL_STS, KCS_CONTROL_WRITE_START);

	/* Wait for IBF = 0 */
	status = kcs_wait_for_ibf(sc, 0, 200);

	if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_WRITE) {
		/* error state */
		return (KCSTO_NO_WRITE_STATE);
	}

	/* Clear OBF */
	status = kcs_clear_obf(sc, status);
	if (status & KCS_STATUS_OBF) {
		return (KCSTO_OBF_STUCK_HIGH_AFTER_WS);
	}

	return (KCS_SUCCESS);
}

/*
 * Write a byte of the request message, excluding the last byte of the
 * message which requires special handling.
 */
static int
kcs_write_byte(struct ipmi_softc *sc, uchar_t data)
{
	int status;

	/* Data to Data */
	OUTB(sc, KCS_DATA, data);

	/* Wait for IBF = 0 */
	status = kcs_wait_for_ibf(sc, 0, 100);
	if (status & KCS_STATUS_IBF) {
		return (KCSTO_IBF_STAYS_HIGH_AFTER_WB);
	}

	if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_WRITE) {
		return (KCSTO_EXITED_WRITE_STATE_AFTER_WB);
	}

	/* Clear OBF */
	status = kcs_clear_obf(sc, status);
	if (status & KCS_STATUS_OBF) {
		return (KCSTO_OBF_STUCK_HIGH_AFTER_WB);
	}
	return (KCS_SUCCESS);
}

/*
 * Write the last byte of a request message.
 */
static int
kcs_write_last_byte(struct ipmi_softc *sc, uchar_t data)
{
	int status;

	/* Write end to command */
	OUTB(sc, KCS_CTL_STS, KCS_CONTROL_WRITE_END);

	/* Wait for IBF = 0 */
	status = kcs_wait_for_ibf(sc, 0, 100);
	if (status & KCS_STATUS_IBF) {
		return (KCSTO_IBF_STAYS_HIGH_AFTER_WLB);
	}

	if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_WRITE) {
		/* error state */
		return (KCSTO_EXITED_WRITE_STATE_AFTER_WLB);
	}

	/* Clear OBF */
	status = kcs_clear_obf(sc, status);
	if (status & KCS_STATUS_OBF) {
		return (KCSTO_OBF_STUCK_HIGH_AFTER_WLB);
	}

	/* Send data byte to DATA. */
	OUTB(sc, KCS_DATA, data);

	return (KCS_SUCCESS);
}

/*
 * Read one byte of the reply message.
 */
static int
kcs_read_byte(struct ipmi_softc *sc, uchar_t *data, uint32_t timeout)
{
	int status;

	/* Wait for IBF = 0 */
	status = kcs_wait_for_ibf(sc, 0, 100);
	if (status & KCS_STATUS_IBF) {
		return (KCSTO_IBF_STUCK_HIGH_BEFORE_RB);
	}

	/* Read State */
	if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_READ) {

		/* Wait for OBF = 1 */
		status = kcs_wait_for_obf(sc, 1, timeout);
		if (!(status & KCS_STATUS_OBF)) {
			return (KCSTO_NO_OBF_FOR_READ);
		}

		/* Read Data_out */
		*data = INB(sc, KCS_DATA);

		/* Write READ into Data_in */
		OUTB(sc, KCS_DATA, KCS_DATA_IN_READ);
		return (KCS_SUCCESS);
	}

	/* Idle State */
	if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_IDLE) {

		/* Wait for OBF = 1 */
		status = kcs_wait_for_obf(sc, 1, 500);
		if (!(status & KCS_STATUS_OBF)) {
			return (KCSTO_NO_OBF_FOR_IDLE);
		}

		/* Read Dummy */
		(void) INB(sc, KCS_DATA);

		return (KCS_SUCCESS_IDLE);
	}

	/* Error State */
	return (KCSTO_UNEXPECTED_STATE_FOR_RB);
}

static int
kcs_write_message(struct ipmi_softc *sc, struct ipmi_request *req)
{
	uchar_t *cp;
	int	i, rval;

	/* Send the request. */
	rval = kcs_start_write(sc);
	if (rval != KCS_SUCCESS) {
		goto fail;
	}

	rval = kcs_write_byte(sc, req->ir_addr);
	if (rval != KCS_SUCCESS) {
		rval |= KCSPH_WRITE_ADDRESS;
		goto fail;
	}

	if (req->ir_requestlen == 0) {
		rval = kcs_write_last_byte(sc, req->ir_command);
		if (rval != KCS_SUCCESS) {
			rval |= KCSPH_WRITE_COMMAND;
			goto fail;
		}
	} else {
		rval = kcs_write_byte(sc, req->ir_command);
		if (rval != KCS_SUCCESS) {
			rval |= KCSPH_WRITE_COMMAND;
			goto fail;
		}

		cp = req->ir_request;
		for (i = 0; i < req->ir_requestlen - 1; i++) {
			rval = kcs_write_byte(sc, *cp++);
			if (rval != KCS_SUCCESS) {
				rval |= KCSPH_WRITE_DATA | ((i + 1)<<16);
				goto fail;
			}
		}

		rval = kcs_write_last_byte(sc, *cp);
		if (rval != KCS_SUCCESS) {
			rval |= KCSPH_WRITE_DATA;
			goto fail;
		}
	}

	return (KCS_SUCCESS);
fail:
	return (rval);
}

static int
kcs_read_response(struct ipmi_softc *sc, struct ipmi_request *req)
{
	uchar_t data;
	int i = 0;
	int status, rval;

	/* Read the reply.  First, read the NetFn/LUN. */
	rval = kcs_read_byte(sc, &data, ipmikcs_first_read_to);
	if (rval != KCS_SUCCESS) {
		if (rval == KCS_SUCCESS_IDLE) {
			rval = KCSTO_UNEXPECTED_IDLE_STATE |
			    KCSPH_READ_NFNLUN_KS;
			goto fail;
		}
		status = INB(sc, KCS_CTL_STS);
		if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_READ) {
			/*
			 * Kick start a read in case the status shows
			 * KCS_STATUS_STATE_READ but no flags set. It
			 * may be that the OBF flag has been prematurely
			 * cleared.  If so then maybe there is still data.
			 */
			OUTB(sc, KCS_DATA, KCS_DATA_IN_READ);
			rval = kcs_read_byte(sc, &data, ipmikcs_def_read_to);
			if (rval != KCS_SUCCESS) {
				if (rval == KCS_SUCCESS_IDLE) {
					rval = KCSTO_UNEXPECTED_IDLE_STATE_KS;
				}
				rval |= KCSPH_READ_NFNLUN_KS;
				goto fail;
			}
		} else {
			rval |= KCSPH_READ_NFNLUN;
			goto fail;
		}
	}

	if (data != IPMI_REPLY_ADDR(req->ir_addr)) {
		rval = KCSTO_REPLY_ADDRESS_MISMATCH;
		goto fail;
	}

	/* Next we read the command. */
	rval = kcs_read_byte(sc, &data, ipmikcs_def_read_to);
	if (rval != KCS_SUCCESS) {
		if (rval == KCS_SUCCESS_IDLE) {
			rval = KCSTO_UNEXPECTED_IDLE_STATE;
		}
		rval |= KCSPH_READ_COMMAND;
		goto fail;
	}
	if (data != req->ir_command) {
		rval = KCSTO_REPLY_COMMAND_MISMATCH | (data<<16);
		goto fail;
	}

	/* Next we read the completion code. */
	rval = kcs_read_byte(sc, &req->ir_compcode, ipmikcs_def_read_to);
	if (rval != KCS_SUCCESS) {
		if (rval == KCS_SUCCESS_IDLE) {
			rval = KCSTO_UNEXPECTED_IDLE_STATE;
		}
		rval |= KCSPH_READ_COMPLETION;
		goto fail;
	}

	/*
	 * Finally, read the reply from the BMC.
	 * The IPMI spec says that KCS replies can be no longer than
	 * 40 bytes. So put a limit on the number of times we read a byte
	 * even if it claims to work.
	 */
	i = 0;
	while (i < 100) {
		rval = kcs_read_byte(sc, &data, ipmikcs_def_read_to);
		if (rval == KCS_SUCCESS_IDLE) {
			break;
		}
		if (rval != KCS_SUCCESS) {
			rval |= (KCSPH_READ_DATA | (i<<16));
			goto fail;
		}

		if (i < req->ir_replybuflen) {
			req->ir_reply[i] = data;
		}
		i++;
	}
	if (rval != KCS_SUCCESS_IDLE) {
		rval = KCSTO_NO_IDLE_STATE | KCSPH_READ_DATA;
		goto fail;
	}
	req->ir_replylen = i;
	if (i < req->ir_replybuflen) {
		rval = KCS_SUCCESS_UNDERRUN;
	}
	if (req->ir_replybuflen < i && req->ir_replybuflen != 0) {
		rval = KCS_SUCCESS_OVERRUN;
	}
fail:
	return (rval);
}

static void
kcs_report_error(struct ipmi_request *req, int eval)
{
	char	tmpbuf[256];
	int	i;

	(void) sprintf(tmpbuf, "Addr:%02x, Cmd:%02x ", req->ir_addr,
	    req->ir_command);
	for (i = 0; i < req->ir_requestlen; i++) {
		(void) sprintf(tmpbuf + strlen(tmpbuf), "%02x",
		    req->ir_request[i]);
	}
	cmn_err(CE_CONT, "!BMC KCS command failed: %s, %s, Ph: %s (0x%x)",
	    tmpbuf, kcs_reasons[KCS_REASON(eval)], kcs_phases[KCS_PHASE(eval)],
	    eval);
}

/*
 * Send a request message and collect the reply.  Returns true if we
 * succeed.
 */
static int
kcs_polled_request(struct ipmi_softc *sc, struct ipmi_request *req)
{
	int		status, loop_cnt = 0, rval;
	uint32_t	eltime;

#ifdef KCS_LOG
	/* Add unique entry to log */
	kcs_log_entry(sc, 0, req->ir_command,
	    (uint8_t)((req->ir_replybuflen>>8)&0xff),
	    (uint8_t)(req->ir_replybuflen&0xff),
	    0x1110cd);
#endif
	req->ir_tstamp = gethrtime();
	rval = kcs_write_message(sc, req);
	if (rval != KCS_SUCCESS) {
		goto fail;
	}

	status = INB(sc, KCS_CTL_STS);
	/*
	 *  Wait until interface state is KCS_STATUS_STATE_READ.  This
	 *  should transition automatically at the end of the write phase.
	 *  It may be that we returned from write phase so quickly that
	 *  the bmc hasn't yet transitioned to a read phase.
	 */
	if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_READ) {
		status = kcs_wait_for_ibf(sc, 0, 100);
		if (status & KCS_STATUS_IBF) {
			rval = KCSTO_IBF_STAYS_HIGH_AFTER_WRITE;
			goto fail;
		}
	}
	while ((loop_cnt < 5) && (KCS_STATUS_STATE(status) !=
	    KCS_STATUS_STATE_READ)) {
		drv_usecwait(ipmikcs_busywait_interval);
		status = INB(sc, KCS_CTL_STS);
		loop_cnt++;
	}

	if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_READ) {
		rval = kcs_read_response(sc, req);
		if (rval <= KCS_SUCCESS) {
			goto fail;
		}
	} else {
		rval = KCSTO_NO_READ_STATE;
	}
fail:
#ifdef KCS_LOG
	/* Add unique entry to log */
	kcs_log_entry(sc, 0, (uint8_t)((rval>>8) & 0xff),
	    (uint8_t)(rval & 0xff), (uint8_t)(req->ir_replylen & 0xff),
	    0xeee0cd);
#endif
	/* Calculate elapsed time and record extremes */
	eltime = (uint32_t)((gethrtime() - req->ir_tstamp)/1000);
	if (rval <= KCS_SUCCESS) {
		if (eltime > sc->ipmi_kcsl_maxtime) {
			sc->ipmi_kcsl_maxtime = eltime;
		}
		if (eltime < sc->ipmi_kcsl_mintime) {
			sc->ipmi_kcsl_mintime = eltime;
		}
	} else {
		if (eltime > sc->ipmi_kcsl_maxerrtime) {
			sc->ipmi_kcsl_maxerrtime = eltime;
		}
	}
	return (rval);
}

/*
 * If you put max_retries down to one (i.e. no retries) the abort time is
 * taken outside of the command completion time.
 */
#define	MAX_RETRIES	2
int kcs_max_retries = MAX_RETRIES;

/*
 * After a failure to abort we holdoff trying another command for this
 * length of time (seconds). All commands that arrive in the meantime are
 * errored. This should help with stalled utilities such as the GUI when the
 * BMC is just not playing, or going through restart.
 */
int kcs_errholdoff_time = 60*3;

static void
kcs_loop(void *arg)
{
	struct ipmi_softc *sc = arg;
	struct ipmi_request *req;
	int i, rval = KCS_SUCCESS;

	IPMI_LOCK(sc);
	while ((req = ipmi_dequeue_request(sc)) != NULL) {
		if (gethrtime() < sc->ipmi_kcsl_errtstamp) {
			/*
			 * It's more suitable to return a value in the
			 * ir_compcode field rather than fail the ioctl()
			 * itself. Suitable value might be 0xD5,
			 * EIPMI_UNAVAILABLE?
			 */
			req->ir_error = 0;
			req->ir_compcode = 0xd5; /* EIPMI_UNAVAILABLE */
			sc->ipmi_kcs_neio_aberr++;
			ipmi_complete_request(sc, req);
			continue;
		}
		IPMI_UNLOCK(sc);
		for (i = 0; i < kcs_max_retries; i++) {
			rval = kcs_polled_request(sc, req);
			/*
			 * Because so much time can elapse between loops
			 * check for detaching here so we can abort sooner.
			 */
			if (sc->ipmi_detaching) {
				break;
			}
			if (rval > KCS_SUCCESS && (i + 1) < kcs_max_retries) {
				if (kcs_abort(sc) != KCS_SUCCESS) {
					break;
				}
				delay(drv_usectohz(5000));
			}
		}

		/*
		 * Record stats and set final error based on returned
		 * values from kcs_polled_request().
		 */
		if (rval <= KCS_SUCCESS) {
			req->ir_error = 0;
			switch (rval) {
			case KCS_SUCCESS_UNDERRUN:
				sc->ipmi_kcs_underrun++;
				break;
			case KCS_SUCCESS_OVERRUN:
				sc->ipmi_kcs_overrun++;
				break;
			default:
				break;
			}
		} else {
			for (i = 0; i < NUM_KCS_ERRVALS; i++) {
				if (sc->ipmi_kcs_errstats[i].iks_errval ==
				    rval) {
					sc->ipmi_kcs_errstats[i].iks_count++;
					break;
				} else if (sc->ipmi_kcs_errstats[i].iks_errval
				    == 0) {
					sc->ipmi_kcs_errstats[i].iks_errval =
					    rval;
					sc->ipmi_kcs_errstats[i].iks_count++;
					break;
				}
			}
			if (i == NUM_KCS_ERRVALS) {
				sc->ipmi_kcs_overflowerrs++;
			}
			kcs_report_error(req, rval);

			/*
			 * Nearly all problems here can be attributed to a
			 * timeout waiting for something during the
			 * KCS transactions. Use a suitable completion code
			 * rather than base error the command with EIO.
			 */
			req->ir_error = 0;
			req->ir_compcode = 0xc3; /* EIPMI_COMMAND_TIMEOUT */
		}
		IPMI_LOCK(sc);
		ipmi_complete_request(sc, req);
		if (rval > KCS_SUCCESS) {
			IPMI_UNLOCK(sc);
			rval = kcs_abort(sc);
			if (rval != KCS_SUCCESS) {
				sc->ipmi_kcsl_errtstamp = gethrtime() +
				    (((hrtime_t)kcs_errholdoff_time) * NANOSEC);
			}
			IPMI_LOCK(sc);
		}
	}
	IPMI_UNLOCK(sc);
}

static int
kcs_startup(struct ipmi_softc *sc)
{
	sc->ipmi_kthread = taskq_create_proc("ipmi_kcs", 1, minclsyspri, 1, 1,
	    curzone->zone_zsched, TASKQ_PREPOPULATE);

	if (taskq_dispatch(sc->ipmi_kthread, kcs_loop, (void *) sc,
	    TQ_SLEEP) == (taskqid_t)0) {
		taskq_destroy(sc->ipmi_kthread);
		return (1);
	}

	return (0);
}

int
ipmi_kcs_attach(struct ipmi_softc *sc)
{
	int status, rval;

	/* Setup function pointers. */
	sc->ipmi_startup = kcs_startup;
	sc->ipmi_enqueue_request = ipmi_polled_enqueue_request;

	/* See if we can talk to the controller. */
	status = INB(sc, KCS_CTL_STS);
	if (status == 0xff) {
		cmn_err(CE_WARN, "!KCS: couldn't find this interface.");
		return (ENXIO);
	}

	if (status & KCS_STATUS_OBF ||
	    KCS_STATUS_STATE(status) != KCS_STATUS_STATE_IDLE) {
		cmn_err(CE_NOTE, "BMC state not ready so reset it.");
		rval = kcs_abort(sc);
		if (rval != KCS_SUCCESS) {
			return (ENXIO);
		}
	}
	sc->ipmi_kcsl_mintime = 0xffffffff;

	return (0);
}
