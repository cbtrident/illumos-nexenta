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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Example using the "smb" dtrace provider.
 * Traces all SMB commands.
 *
 * All these probes provide:
 *	args[0]  conninfo_t
 *	args[1]  smbopinfo_t
 * Some also provide one of: (not used here)
 *	args[2]  smb_name_args_t
 *	args[2]  smb_open_args_t
 *	args[2]  smb_rw_args_t
 */

/*
 * Unfortunately, trying to write this as:
 *	smb:::op-*-start {}
 *	smb:::op-*-done {}
 * fails to compile with this complaint:
 *	dtrace: failed to compile script smb-trace.d: line 42:
 *	args[ ] may not be referenced because probe description
 *	smb:::op-*-start matches an unstable set of probes
 *
 * Not clear why listing them all is necessary,
 * but that works.
 */

smb:::op-CheckDirectory-start,
smb:::op-Close-start,
smb:::op-CloseAndTreeDisconnect-start,
smb:::op-ClosePrintFile-start,
smb:::op-Create-start,
smb:::op-CreateDirectory-start,
smb:::op-CreateNew-start,
smb:::op-CreateTemporary-start,
smb:::op-Delete-start,
smb:::op-DeleteDirectory-start,
smb:::op-Echo-start,
smb:::op-Find-start,
smb:::op-FindClose-start,
smb:::op-FindClose2-start,
smb:::op-FindUnique-start,
smb:::op-Flush-start,
smb:::op-GetPrintQueue-start,
smb:::op-Invalid-start,
smb:::op-Ioctl-start,
smb:::op-LockAndRead-start,
smb:::op-LockByteRange-start,
smb:::op-LockingX-start,
smb:::op-LogoffX-start,
smb:::op-Negotiate-start,
smb:::op-NtCancel-start,
smb:::op-NtCreateX-start,
smb:::op-NtRename-start,
smb:::op-NtTransact-start,
smb:::op-NtTransactCreate-start,
smb:::op-NtTransactSecondary-start,
smb:::op-Open-start,
smb:::op-OpenPrintFile-start,
smb:::op-OpenX-start,
smb:::op-ProcessExit-start,
smb:::op-QueryInformation-start,
smb:::op-QueryInformation2-start,
smb:::op-QueryInformationDisk-start,
smb:::op-Read-start,
smb:::op-ReadRaw-start,
smb:::op-ReadX-start,
smb:::op-Rename-start,
smb:::op-Search-start,
smb:::op-Seek-start,
smb:::op-SessionSetupX-start,
smb:::op-SetInformation-start,
smb:::op-SetInformation2-start,
smb:::op-Transaction-start,
smb:::op-Transaction2-start,
smb:::op-Transaction2Secondary-start,
smb:::op-TransactionSecondary-start,
smb:::op-TreeConnect-start,
smb:::op-TreeConnectX-start,
smb:::op-TreeDisconnect-start,
smb:::op-UnlockByteRange-start,
smb:::op-Write-start,
smb:::op-WriteAndClose-start,
smb:::op-WriteAndUnlock-start,
smb:::op-WritePrintFile-start,
smb:::op-WriteRaw-start,
smb:::op-WriteX-start
{
	printf("clnt=%s mid=0x%x uid=0x%x tid=0x%x\n",
	       args[0]->ci_remote,
	       args[1]->soi_mid,
	       args[1]->soi_uid,
	       args[1]->soi_tid);
}
	

smb:::op-CheckDirectory-done,
smb:::op-Close-done,
smb:::op-CloseAndTreeDisconnect-done,
smb:::op-ClosePrintFile-done,
smb:::op-Create-done,
smb:::op-CreateDirectory-done,
smb:::op-CreateNew-done,
smb:::op-CreateTemporary-done,
smb:::op-Delete-done,
smb:::op-DeleteDirectory-done,
smb:::op-Echo-done,
smb:::op-Find-done,
smb:::op-FindClose-done,
smb:::op-FindClose2-done,
smb:::op-FindUnique-done,
smb:::op-Flush-done,
smb:::op-GetPrintQueue-done,
smb:::op-Invalid-done,
smb:::op-Ioctl-done,
smb:::op-LockAndRead-done,
smb:::op-LockByteRange-done,
smb:::op-LockingX-done,
smb:::op-LogoffX-done,
smb:::op-Negotiate-done,
smb:::op-NtCancel-done,
smb:::op-NtCreateX-done,
smb:::op-NtRename-done,
smb:::op-NtTransact-done,
smb:::op-NtTransactCreate-done,
smb:::op-NtTransactSecondary-done,
smb:::op-Open-done,
smb:::op-OpenPrintFile-done,
smb:::op-OpenX-done,
smb:::op-ProcessExit-done,
smb:::op-QueryInformation-done,
smb:::op-QueryInformation2-done,
smb:::op-QueryInformationDisk-done,
smb:::op-Read-done,
smb:::op-ReadRaw-done,
smb:::op-ReadX-done,
smb:::op-Rename-done,
smb:::op-Search-done,
smb:::op-Seek-done,
smb:::op-SessionSetupX-done,
smb:::op-SetInformation-done,
smb:::op-SetInformation2-done,
smb:::op-Transaction-done,
smb:::op-Transaction2-done,
smb:::op-Transaction2Secondary-done,
smb:::op-TransactionSecondary-done,
smb:::op-TreeConnect-done,
smb:::op-TreeConnectX-done,
smb:::op-TreeDisconnect-done,
smb:::op-UnlockByteRange-done,
smb:::op-Write-done,
smb:::op-WriteAndClose-done,
smb:::op-WriteAndUnlock-done,
smb:::op-WritePrintFile-done,
smb:::op-WriteRaw-done,
smb:::op-WriteX-done
{
	printf("clnt=%s mid=0x%x status=0x%x\n",
	       args[0]->ci_remote,
	       args[1]->soi_mid,
	       args[1]->soi_status);
}
