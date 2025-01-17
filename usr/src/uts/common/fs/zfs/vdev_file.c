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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, 2015 by Delphix. All rights reserved.
 * Copyright 2019 Nexenta by DDN, Inc. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev_file.h>
#include <sys/vdev_impl.h>
#include <sys/zio.h>
#include <sys/fs/zfs.h>
#include <sys/fm/fs/zfs.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/dkioc_free_util.h>
#include <sys/abd.h>

/*
 * Virtual device vector for files.
 */

static void
vdev_file_hold(vdev_t *vd)
{
	ASSERT(vd->vdev_path != NULL);
}

static void
vdev_file_rele(vdev_t *vd)
{
	ASSERT(vd->vdev_path != NULL);
}

static int
vdev_file_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
	vdev_file_t *vf;
	vnode_t *vp;
	vattr_t vattr;
	int error;

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Reopen the device if it's not currently open.  Otherwise,
	 * just update the physical size of the device.
	 */
	if (vd->vdev_tsd != NULL) {
		ASSERT(vd->vdev_reopening);
		vf = vd->vdev_tsd;
		goto skip_open;
	}

	vf = vd->vdev_tsd = kmem_zalloc(sizeof (vdev_file_t), KM_SLEEP);

	/*
	 * We always open the files from the root of the global zone, even if
	 * we're in a local zone.  If the user has gotten to this point, the
	 * administrator has already decided that the pool should be available
	 * to local zone users, so the underlying devices should be as well.
	 */
	ASSERT(vd->vdev_path != NULL && vd->vdev_path[0] == '/');
	error = vn_openat(vd->vdev_path + 1, UIO_SYSSPACE,
	    spa_mode(vd->vdev_spa) | FOFFMAX, 0, &vp, 0, 0, rootdir, -1);

	if (error) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (error);
	}

	vf->vf_vnode = vp;

#ifdef _KERNEL
	/*
	 * Make sure it's a regular file.
	 */
	if (vp->v_type != VREG) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(ENODEV));
	}
#endif

skip_open:
	/*
	 * Determine the physical size of the file.
	 */
	vattr.va_mask = AT_SIZE;
	error = VOP_GETATTR(vf->vf_vnode, &vattr, 0, kcred, NULL);
	if (error) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (error);
	}

	*max_psize = *psize = vattr.va_size;
	*ashift = MAX(vd->vdev_spa->spa_default_ashift, SPA_MINBLOCKSHIFT);

	return (0);
}

static void
vdev_file_close(vdev_t *vd)
{
	vdev_file_t *vf = vd->vdev_tsd;
	caller_context_t ct = {0};

	if (vd->vdev_reopening || vf == NULL)
		return;

	if (vf->vf_vnode != NULL) {
		(void) VOP_PUTPAGE(vf->vf_vnode, 0, 0, B_INVAL, kcred, NULL);
		/*
		 * We need to supply caller context with PID zero to fop_close
		 * in order to clean properly a share reservation which might
		 * have been created by vdev_file_open if nbmand was "on" for
		 * underlaying filesystem. Mismatched PIDs in create and delete
		 * reservation calls would lead to orphaned reservation.
		 */
		(void) VOP_CLOSE(vf->vf_vnode, spa_mode(vd->vdev_spa), 1, 0,
		    kcred, &ct);
		VN_RELE(vf->vf_vnode);
	}

	vd->vdev_delayed_close = B_FALSE;
	kmem_free(vf, sizeof (vdev_file_t));
	vd->vdev_tsd = NULL;
}

/*
 * Implements the interrupt side for file vdev types. This routine will be
 * called when the I/O completes allowing us to transfer the I/O to the
 * interrupt taskqs. For consistency, the code structure mimics disk vdev
 * types.
 */
static void
vdev_file_io_intr(buf_t *bp)
{
	vdev_buf_t *vb = (vdev_buf_t *)bp;
	zio_t *zio = vb->vb_io;

	zio->io_error = (geterror(bp) != 0 ? EIO : 0);
	if (zio->io_error == 0 && bp->b_resid != 0)
		zio->io_error = SET_ERROR(ENOSPC);

	if (zio->io_type == ZIO_TYPE_READ) {
		abd_return_buf_copy(zio->io_abd, bp->b_un.b_addr, zio->io_size);
	} else {
		abd_return_buf(zio->io_abd, bp->b_un.b_addr, zio->io_size);
	}

	kmem_free(vb, sizeof (vdev_buf_t));
	zio_delay_interrupt(zio);
}

static void
vdev_file_io_strategy(void *arg)
{
	buf_t *bp = arg;
	vnode_t *vp = bp->b_private;
	ssize_t resid;
	int error;

	error = vn_rdwr((bp->b_flags & B_READ) ? UIO_READ : UIO_WRITE,
	    vp, bp->b_un.b_addr, bp->b_bcount, ldbtob(bp->b_lblkno),
	    UIO_SYSSPACE, 0, RLIM64_INFINITY, kcred, &resid);

	if (error == 0) {
		bp->b_resid = resid;
		biodone(bp);
	} else {
		bioerror(bp, error);
		biodone(bp);
	}
}

static void
vdev_file_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_file_t *vf = vd->vdev_tsd;
	vdev_buf_t *vb;
	buf_t *bp;

	if (zio->io_type == ZIO_TYPE_IOCTL) {
		/* XXPOLICY */
		if (!vdev_readable(vd)) {
			zio->io_error = SET_ERROR(ENXIO);
			zio_interrupt(zio);
			return;
		}

		switch (zio->io_cmd) {
		case DKIOCFLUSHWRITECACHE:
			zio->io_error = VOP_FSYNC(vf->vf_vnode, FSYNC | FDSYNC,
			    kcred, NULL);
			break;
		case DKIOCFREE:
		{
			dkioc_free_list_t *dfl = zio->io_private;

			ASSERT(dfl != NULL);
			for (int i = 0; i < dfl->dfl_num_exts; i++) {
				struct flock64 flck;
				int error;

				if (dfl->dfl_exts[i].dfle_length == 0)
					continue;

				bzero(&flck, sizeof (flck));
				flck.l_type = F_FREESP;
				flck.l_start = dfl->dfl_exts[i].dfle_start +
				    dfl->dfl_offset;
				flck.l_len = dfl->dfl_exts[i].dfle_length;

				error = VOP_SPACE(vf->vf_vnode,
				    F_FREESP, &flck, 0, 0, kcred, NULL);
				if (error != 0) {
					zio->io_error = SET_ERROR(error);
					break;
				}
			}
			break;
		}
		default:
			zio->io_error = SET_ERROR(ENOTSUP);
		}

		zio_execute(zio);
		return;
	}

	ASSERT(zio->io_type == ZIO_TYPE_READ || zio->io_type == ZIO_TYPE_WRITE);
	zio->io_target_timestamp = zio_handle_io_delay(zio);

	vb = kmem_alloc(sizeof (vdev_buf_t), KM_SLEEP);

	vb->vb_io = zio;
	bp = &vb->vb_buf;

	bioinit(bp);
	bp->b_flags = (zio->io_type == ZIO_TYPE_READ ? B_READ : B_WRITE);
	bp->b_bcount = zio->io_size;

	if (zio->io_type == ZIO_TYPE_READ) {
		bp->b_un.b_addr =
		    abd_borrow_buf(zio->io_abd, zio->io_size);
	} else {
		bp->b_un.b_addr =
		    abd_borrow_buf_copy(zio->io_abd, zio->io_size);
	}

	bp->b_lblkno = lbtodb(zio->io_offset);
	bp->b_bufsize = zio->io_size;
	bp->b_private = vf->vf_vnode;
	bp->b_iodone = (int (*)())vdev_file_io_intr;

	VERIFY3U(taskq_dispatch(system_taskq, vdev_file_io_strategy, bp,
	    TQ_SLEEP), !=, 0);
}

/* ARGSUSED */
static void
vdev_file_io_done(zio_t *zio)
{
}

vdev_ops_t vdev_file_ops = {
	vdev_file_open,
	vdev_file_close,
	vdev_default_asize,
	vdev_file_io_start,
	vdev_file_io_done,
	NULL,
	vdev_file_hold,
	vdev_file_rele,
	NULL,
	VDEV_TYPE_FILE,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};

/*
 * From userland we access disks just like files.
 */
#ifndef _KERNEL

vdev_ops_t vdev_disk_ops = {
	vdev_file_open,
	vdev_file_close,
	vdev_default_asize,
	vdev_file_io_start,
	vdev_file_io_done,
	NULL,
	vdev_file_hold,
	vdev_file_rele,
	NULL,
	VDEV_TYPE_DISK,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};

#endif
