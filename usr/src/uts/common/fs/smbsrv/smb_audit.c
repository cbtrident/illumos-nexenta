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
 * Copyright 2020 Nexenta by DDN, Inc. All rights reserved.
 */

#include <smbsrv/smb_ktypes.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

#include <c2/audit.h>
#include <c2/audit_kernel.h>

boolean_t
smb_audit_init(smb_request_t *sr)
{
	t_audit_data_t *tad;

	if (!AU_ZONE_AUDITING(NULL) || sr->session->dialect < SMB_VERS_2_BASE)
		return (B_FALSE);

	tad = T2A(curthread);
	tad->tad_sacl_ctrl = SACL_AUDIT_ON;
	tad->tad_sacl_mask.tas_smask = AU_SACL_NOTSET;
	tad->tad_sacl_mask.tas_fmask = AU_SACL_NOTSET;
	return (B_TRUE);
}

void
smb_audit_fini(smb_request_t *sr, uint32_t desired, smb_node_t *node,
    boolean_t success)
{
	char *truepath;
	t_audit_data_t *tad;

	if (!AU_ZONE_AUDITING(NULL))
		return;

	tad = T2A(curthread);

	/*
	 * ACCESS_SYSTEM_SECURITY is the permission used to read/write the SACL.
	 * It is not granted by the DACL, but rather by privileges.
	 * This means there's no normal way to audit SACL changes via the SACL.
	 * Additionally, praudit cannot represent ACCESS_SYSTEM_SECURITY.
	 * Therefore, we map ACCESS_SYSTEM_SECURITY to READ_ACL|WRITE_ACL for
	 * auditing purposes.
	 */
	if ((desired & ACCESS_SYSTEM_SECURITY) != 0)
		desired |= ACE_READ_ACL|ACE_WRITE_ACL;

	if (AU_SACL_MASK_NOTSET(tad->tad_sacl_mask)) {
		/*
		 * ACLs were never checked; try again using READ_DATA to bypass
		 * edge cases where access checks aren't done
		 */
		tad->tad_sacl_ctrl = SACL_AUDIT_ON;
		(void) smb_fsop_access(sr, sr->user_cr, node, ACE_READ_DATA);

		/* If it's STILL not set, assume it was meant to be audited. */
		if (AU_SACL_MASK_NOTSET(tad->tad_sacl_mask)) {
#if DEBUG
			cmn_err(CE_NOTE,
			    "smb_audit_fini: tad_sacl_mask still not set? 0x%x",
			    desired);
#endif
			tad->tad_sacl_mask.tas_smask = 0xffffffff;
			tad->tad_sacl_mask.tas_fmask = 0xffffffff;
		}
	}

	truepath = kmem_alloc(SMB_MAXPATHLEN, KM_SLEEP);
	/* We don't keep the resolved pathname around, so get it from here */
	smb_node_getpath_nofail(node, smb_audit_rootvp(sr), truepath,
	    SMB_MAXPATHLEN);
	audit_sacl(truepath, sr->user_cr, desired, success,
	    &tad->tad_sacl_mask);
	tad->tad_sacl_ctrl = SACL_AUDIT_NONE;
	kmem_free(truepath, SMB_MAXPATHLEN);
}

boolean_t
smb_audit_rename_init(smb_request_t *sr)
{
	t_audit_data_t *tad;

	if (!AU_ZONE_AUDITING(NULL) || sr->session->dialect < SMB_VERS_2_BASE)
		return (B_FALSE);

	tad = T2A(curthread);
	tad->tad_sacl_ctrl = SACL_AUDIT_NO_SRC;
	tad->tad_sacl_mask.tas_smask = AU_SACL_NOTSET;
	tad->tad_sacl_mask.tas_fmask = AU_SACL_NOTSET;
	tad->tad_sacl_mask_src.tas_smask = AU_SACL_NOTSET;
	tad->tad_sacl_mask_src.tas_fmask = AU_SACL_NOTSET;
	tad->tad_sacl_mask_dest.tas_smask = AU_SACL_NOTSET;
	tad->tad_sacl_mask_dest.tas_fmask = AU_SACL_NOTSET;
	return (B_TRUE);
}

void
smb_audit_rename_fini(smb_request_t *sr, char *src, smb_node_t *dir, char *dest,
    boolean_t success, boolean_t isdir)
{
	char *truepath;
	t_audit_data_t *tad;

	if (!AU_ZONE_AUDITING(NULL))
		return;

	tad = T2A(curthread);

	/*
	 * We don't really have a good way to 'recheck' here,
	 * so just assume they're meant to be audited.
	 */

	if (dir != NULL && AU_SACL_MASK_NOTSET(tad->tad_sacl_mask)) {
		tad->tad_sacl_mask.tas_smask = 0xffffffff;
		tad->tad_sacl_mask.tas_fmask = 0xffffffff;
#if DEBUG
		cmn_err(CE_NOTE,
		    "smb_audit_rename_fini: tad_sacl_mask not set?");
#endif
	}
	if (src != NULL && AU_SACL_MASK_NOTSET(tad->tad_sacl_mask_src)) {
		tad->tad_sacl_mask_src.tas_smask = 0xffffffff;
		tad->tad_sacl_mask_src.tas_fmask = 0xffffffff;
#if DEBUG
		cmn_err(CE_NOTE,
		    "smb_audit_rename_fini: tad_sacl_mask_src not set?");
#endif
	}
	if (dest != NULL && AU_SACL_MASK_NOTSET(tad->tad_sacl_mask_dest)) {
		tad->tad_sacl_mask_dest.tas_smask = 0xffffffff;
		tad->tad_sacl_mask_dest.tas_fmask = 0xffffffff;
#if DEBUG
		cmn_err(CE_NOTE,
		    "smb_audit_rename_fini: tad_sacl_mask_dest not set?");
#endif
	}

	if (src != NULL) {
		audit_sacl(src, sr->user_cr, ACE_DELETE, success,
		    &tad->tad_sacl_mask_src);
	}
	if (dest != NULL) {
		audit_sacl(dest, sr->user_cr, ACE_DELETE, success,
		    &tad->tad_sacl_mask_dest);
	}

	truepath = kmem_alloc(SMB_MAXPATHLEN, KM_SLEEP);
	/* We don't keep the resolved pathname around, so get it from here */
	smb_node_getpath_nofail(dir, smb_audit_rootvp(sr), truepath,
	    SMB_MAXPATHLEN);
	audit_sacl(truepath, sr->user_cr,
	    isdir ? ACE_ADD_SUBDIRECTORY : ACE_ADD_FILE,
	    success, &tad->tad_sacl_mask);
	tad->tad_sacl_ctrl = SACL_AUDIT_NONE;
	kmem_free(truepath, SMB_MAXPATHLEN);
}

void
smb_audit_save()
{
	t_audit_data_t *tad;
	if (AU_ZONE_AUDITING(NULL)) {
		tad = T2A(curthread);
		tad->tad_sacl_backup = tad->tad_sacl_ctrl;
		tad->tad_sacl_ctrl = SACL_AUDIT_BACKUP;
	}
}

void
smb_audit_load()
{
	t_audit_data_t *tad = T2A(curthread);
	if (AU_ZONE_AUDITING(NULL) && tad->tad_sacl_backup != SACL_AUDIT_NONE) {
		tad->tad_sacl_ctrl = tad->tad_sacl_backup;
		tad->tad_sacl_backup = SACL_AUDIT_NONE;
	}
}

vnode_t *
smb_audit_rootvp(smb_request_t *sr)
{
	return (AU_AUDIT_PERZONE() ?
	    sr->sr_server->si_root_smb_node->vp : rootdir);
}
