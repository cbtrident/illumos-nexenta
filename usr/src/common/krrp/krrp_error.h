/*
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _KRRP_ERROR_H
#define	_KRRP_ERROR_H

#include <sys/types.h>
#include <sys/nvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	krrp_error_init(error) (void) memset(error, 0, sizeof (krrp_error_t));

typedef enum {
	KRRP_ESRC_COMMON = 1,
	KRRP_ESRC_SESSION,
	KRRP_ESRC_NETWORK,
	KRRP_ESRC_STREAM,
	KRRP_ESRC_SERVER,
	KRRP_ESRC_PDU
} krrp_esrc_t;

typedef enum {
	KRRP_ERRF_REMOTE = 0x1
} krrp_error_flag_t;


#define	KRRP_ERRNO_MAP(X) \
	X(INTR)               \
	X(INVAL)              \
	X(BUSY)               \
	X(NOMEM)              \
	X(SESS)               \
	X(CONN)               \
	X(PDUENGINE)          \
	X(STREAM)             \
	X(SESSID)             \
	X(KSTATID)            \
	X(ADDR)               \
	X(PORT)               \
	X(DBLKSZ)             \
	X(MAXMEMSZ)           \
	X(FAKEDSZ)            \
	X(SRCDS)              \
	X(DSTDS)              \
	X(CMNSNAP)            \
	X(SRCSNAP)            \
	X(BADRESP)            \
	X(BIGPAYLOAD)         \
	X(UNEXPCLOSE)         \
	X(UNEXPEND)           \
	X(ZFSGCTXFAIL)        \
	X(CREATEFAIL)         \
	X(BINDFAIL)           \
	X(LISTENFAIL)         \
	X(CONNFAIL)           \
	X(ACCEPTFAIL)         \
	X(SETSOCKOPTFAIL)     \
	X(SENDFAIL)           \
	X(SENDMBLKFAIL)       \
	X(RECVFAIL)           \
	X(READFAIL)           \
	X(WRITEFAIL)          \
	X(SNAPFAIL)           \
	X(FLCTRLVIOL)         \
	X(ZFSWBCBADMODE)      \
	X(ZFSWBCBADUSE)       \
	X(PINGTIMEOUT)        \
	X(PROTO)              \
	X(AUTH)               \
	X(CFGTYPE)            \
	X(CONNTIMEOUT)        \
	X(THROTTLE)           \
	X(AUTOSNAP)           \
	X(RESUMETOKEN)        \
	X(KEEPSNAPS)          \


#define	KRRP_ERRNO_EXPAND(enum_name) KRRP_ERRNO_##enum_name,
typedef enum {
	KRRP_ERRNO_OK = 0,
	KRRP_ERRNO_UNKNOWN = 1000,
	KRRP_ERRNO_MAP(KRRP_ERRNO_EXPAND)
	KRRP_ERRNO_LAST /* To exclude lint-errors */
} krrp_errno_t;
#undef KRRP_ERRNO_EXPAND

typedef struct krrp_error_s {
	/* Native KRRP ERRNO */
	krrp_errno_t	krrp_errno;

	/*
	 * UNIX ERRNO that is returned by non-krrp functions
	 * for example ksocket_send/ksocket_recv/
	 * dmu_lend_recv_buffer/dmu_lend_send_buffer/...
	 */
	int				unix_errno;

	/* Flags: see krrp_error_flag_t */
	uint32_t		flags;
} krrp_error_t;

#ifdef _KERNEL

void krrp_error_set(krrp_error_t *, krrp_errno_t, int);

void krrp_error_to_nvl(krrp_error_t *, nvlist_t **);

#endif /* _KERNEL */

const char *krrp_error_errno_to_str(krrp_errno_t krrp_errno);

#ifdef __cplusplus
}
#endif

#endif /* _KRRP_ERROR_H */
