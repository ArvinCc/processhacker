/*
 * KProcessHacker
 *
 * Copyright (C) 2010-2016 wj32
 *
 * This file is part of Process Hacker.
 *
 * Process Hacker is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Process Hacker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Process Hacker.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <kph.h>

ULONG KphpGetCopyExceptionInfo(
    _In_ PEXCEPTION_POINTERS ExceptionInfo,
    _Out_ PBOOLEAN HaveBadAddress,
    _Out_ PULONG_PTR BadAddress
    );

VOID TransactionCommitIpi(TransactionCommitCallback callback, void *context);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KphCopyVirtualMemory)
#pragma alloc_text(PAGE, KpiReadVirtualMemoryUnsafe)
#pragma alloc_text(PAGE, KpiQueryVirtualMemory)
#endif

#define KPH_STACK_COPY_BYTES 0x200
#define KPH_POOL_COPY_BYTES 0x10000
#define KPH_MAPPED_COPY_PAGES 14
#define KPH_POOL_COPY_THRESHOLD 0x3ff

ULONG KphpGetCopyExceptionInfo(
    _In_ PEXCEPTION_POINTERS ExceptionInfo,
    _Out_ PBOOLEAN HaveBadAddress,
    _Out_ PULONG_PTR BadAddress
    )
{
    PEXCEPTION_RECORD exceptionRecord;

    *HaveBadAddress = FALSE;
    exceptionRecord = ExceptionInfo->ExceptionRecord;

    if ((exceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) ||
        (exceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) ||
        (exceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR))
    {
        if (exceptionRecord->NumberParameters > 1)
        {
            /* We have the address. */
            *HaveBadAddress = TRUE;
            *BadAddress = exceptionRecord->ExceptionInformation[1];
        }
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

/**
 * Copies memory from one process to another.
 *
 * \param FromProcess The source process.
 * \param FromAddress The source address.
 * \param ToProcess The target process.
 * \param ToAddress The target address.
 * \param BufferLength The number of bytes to copy.
 * \param AccessMode The mode in which to perform access checks.
 * \param ReturnLength A variable which receives the number of bytes copied.
 */
NTSTATUS KphCopyVirtualMemory(
    _In_ PEPROCESS FromProcess,
    _In_ PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _In_ PVOID ToAddress,
    _In_ SIZE_T BufferLength,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PSIZE_T ReturnLength
    )
{
    UCHAR stackBuffer[KPH_STACK_COPY_BYTES];
    PVOID buffer;
    PFN_NUMBER mdlBuffer[(sizeof(MDL) / sizeof(PFN_NUMBER)) + KPH_MAPPED_COPY_PAGES + 1];
    PMDL mdl = (PMDL)mdlBuffer;
    PVOID mappedAddress;
    SIZE_T mappedTotalSize;
    SIZE_T blockSize;
    SIZE_T stillToCopy;
    KAPC_STATE apcState;
    PVOID sourceAddress;
    PVOID targetAddress;
    BOOLEAN doMappedCopy;
    BOOLEAN pagesLocked;
    BOOLEAN copyingToTarget = FALSE;
    BOOLEAN probing = FALSE;
    BOOLEAN mapping = FALSE;
    BOOLEAN haveBadAddress;
    ULONG_PTR badAddress;

    PAGED_CODE();

    sourceAddress = FromAddress;
    targetAddress = ToAddress;

    // We don't check if buffer == NULL when freeing. If buffer doesn't need to be freed, set to
    // stackBuffer, not NULL.
    buffer = stackBuffer;

    mappedTotalSize = (KPH_MAPPED_COPY_PAGES - 2) * PAGE_SIZE;

    if (mappedTotalSize > BufferLength)
        mappedTotalSize = BufferLength;

    stillToCopy = BufferLength;
    blockSize = mappedTotalSize;

    while (stillToCopy)
    {
        // If we're at the last copy block, copy the remaining bytes instead of the whole block
        // size.
        if (blockSize > stillToCopy)
            blockSize = stillToCopy;

        // Choose the best method based on the number of bytes left to copy.
        if (blockSize > KPH_POOL_COPY_THRESHOLD)
        {
            doMappedCopy = TRUE;
        }
        else
        {
            doMappedCopy = FALSE;

            if (blockSize <= KPH_STACK_COPY_BYTES)
            {
                if (buffer != stackBuffer)
                    ExFreePoolWithTag(buffer, 'ChpK');

                buffer = stackBuffer;
            }
            else
            {
                // Don't allocate the buffer if we've done so already. Note that the block size
                // never increases, so this allocation will always be OK.
                if (buffer == stackBuffer)
                {
                    // Keep trying to allocate a buffer.

                    while (TRUE)
                    {
                        buffer = ExAllocatePoolWithTag(NonPagedPool, blockSize, 'ChpK');

                        // Stop trying if we got a buffer.
                        if (buffer)
                            break;

                        blockSize /= 2;

                        // Use the stack buffer if we can.
                        if (blockSize <= KPH_STACK_COPY_BYTES)
                        {
                            buffer = stackBuffer;
                            break;
                        }
                    }
                }
            }
        }

        // Reset state.
        mappedAddress = NULL;
        pagesLocked = FALSE;
        copyingToTarget = FALSE;

        KeStackAttachProcess(FromProcess, &apcState);

        __try
        {
            // Probe only if this is the first time.
            if (sourceAddress == FromAddress && AccessMode != KernelMode)
            {
                probing = TRUE;
                ProbeForRead(sourceAddress, BufferLength, sizeof(UCHAR));
                probing = FALSE;
            }

            if (doMappedCopy)
            {
                // Initialize the MDL.
                MmInitializeMdl(mdl, sourceAddress, blockSize);
                MmProbeAndLockPages(mdl, AccessMode, IoReadAccess);
                pagesLocked = TRUE;

                // Map the pages.
                mappedAddress = MmMapLockedPagesSpecifyCache(
                    mdl,
                    KernelMode,
                    MmCached,
                    NULL,
                    FALSE,
                    HighPagePriority
                    );

                if (!mappedAddress)
                {
                    // Insufficient resources; exit.
                    mapping = TRUE;
                    ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
                }
            }
            else
            {
                memcpy(buffer, sourceAddress, blockSize);
            }

            KeUnstackDetachProcess(&apcState);

            // Attach to the target process and copy the contents out.
            KeStackAttachProcess(ToProcess, &apcState);

            // Probe only if this is the first time.
            if (targetAddress == ToAddress && AccessMode != KernelMode)
            {
                probing = TRUE;
                ProbeForWrite(targetAddress, BufferLength, sizeof(UCHAR));
                probing = FALSE;
            }

            // Copy the data.
            copyingToTarget = TRUE;

            if (doMappedCopy)
                memcpy(targetAddress, mappedAddress, blockSize);
            else
                memcpy(targetAddress, buffer, blockSize);
        }
        __except (KphpGetCopyExceptionInfo(
            GetExceptionInformation(),
            &haveBadAddress,
            &badAddress
            ))
        {
            KeUnstackDetachProcess(&apcState);

            // If we mapped the pages, unmap them.
            if (mappedAddress)
                MmUnmapLockedPages(mappedAddress, mdl);

            // If we locked the pages, unlock them.
            if (pagesLocked)
                MmUnlockPages(mdl);

            // If we allocated pool storage, free it.
            if (buffer != stackBuffer)
                ExFreePoolWithTag(buffer, 'ChpK');

            // If we failed when probing or mapping, return the error status.
            if (probing || mapping)
                return GetExceptionCode();

            // Determine which copy failed.
            if (copyingToTarget && haveBadAddress)
            {
                *ReturnLength = (ULONG)(badAddress - (ULONG_PTR)sourceAddress);
            }
            else
            {
                *ReturnLength = BufferLength - stillToCopy;
            }

            return STATUS_PARTIAL_COPY;
        }

        KeUnstackDetachProcess(&apcState);

        if (doMappedCopy)
        {
            MmUnmapLockedPages(mappedAddress, mdl);
            MmUnlockPages(mdl);
        }

        stillToCopy -= blockSize;
        sourceAddress = (PVOID)((ULONG_PTR)sourceAddress + blockSize);
        targetAddress = (PVOID)((ULONG_PTR)targetAddress + blockSize);
    }

    if (buffer != stackBuffer)
        ExFreePoolWithTag(buffer, 'ChpK');

    *ReturnLength = BufferLength;

    return STATUS_SUCCESS;
}

NTSTATUS ReadKernelMemory(PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy, PSIZE_T ActuallyCopy)
{
	PVOID InVA = PAGE_ALIGN(pSourceAddress);
	ULONG_PTR OffsetVA = (ULONG_PTR)pSourceAddress - (ULONG_PTR)InVA;
	PVOID OutVA = pDestination;
	SIZE_T CopySize = min(PAGE_SIZE - OffsetVA, SizeOfCopy);
	SIZE_T TotalReadBytes = 0;
	SIZE_T ActuallyRead = 0;
	BOOLEAN bRead = FALSE;
	while (TotalReadBytes < SizeOfCopy)
	{
		if (MmIsAddressValid(InVA))
		{
			PHYSICAL_ADDRESS InPA = MmGetPhysicalAddress(InVA);
			if (!UtilIsDeviceMemory(InPA.QuadPart))
			{
				RtlCopyMemory(OutVA, (PVOID)((ULONG_PTR)InVA + OffsetVA), CopySize);
				ActuallyRead += CopySize;
				bRead = TRUE;
			}
		}
		if (!bRead) {
			RtlZeroMemory(OutVA, CopySize);
		}
		OffsetVA = 0;
		OutVA = (PVOID)((ULONG_PTR)OutVA + CopySize);
		InVA = (PVOID)((ULONG_PTR)InVA + PAGE_SIZE);
		TotalReadBytes += CopySize;
		CopySize = min(PAGE_SIZE, SizeOfCopy - TotalReadBytes);
	}
	if (ActuallyCopy)
		*ActuallyCopy = ActuallyRead;

	if (!ActuallyRead)
		return STATUS_ACCESS_VIOLATION;

	if (ActuallyRead < TotalReadBytes)
		return STATUS_PARTIAL_COPY;

	return STATUS_SUCCESS;
}

typedef struct
{
	PVOID SrcAddress;
	PVOID DstAddress;
	SIZE_T SizeOfCopy;
	PSIZE_T ActuallyCopy;
	NTSTATUS status;
}SafeReadKernelMemoryContext;

void SafeReadKernelMemoryProxy(void *context)
{
	SafeReadKernelMemoryContext *ctx = (SafeReadKernelMemoryContext *)context;
	ctx->status = ReadKernelMemory(ctx->DstAddress, ctx->SrcAddress, ctx->SizeOfCopy, ctx->ActuallyCopy);
}

NTSTATUS SafeReadKernelMemory(PVOID Destination, PVOID SourceAddress, SIZE_T SizeOfCopy, PSIZE_T ActuallyCopy)
{
	SafeReadKernelMemoryContext ctx;
	ctx.SrcAddress = SourceAddress;
	ctx.DstAddress = Destination;
	ctx.SizeOfCopy = SizeOfCopy;
	ctx.ActuallyCopy = ActuallyCopy;
	ctx.status = STATUS_UNSUCCESSFUL;

	TransactionCommitIpi(SafeReadKernelMemoryProxy, &ctx);

	return ctx.status;
}

/**
 * Copies process or kernel memory into the current process.
 *
 * \param ProcessHandle A handle to a process. The handle must have PROCESS_VM_READ access. This
 * parameter may be NULL if \a BaseAddress lies above the user-mode range.
 * \param BaseAddress The address from which memory is to be copied.
 * \param Buffer A buffer which receives the copied memory.
 * \param BufferSize The number of bytes to copy.
 * \param NumberOfBytesRead A variable which receives the number of bytes copied to the buffer.
 * \param Key An access key. If no valid L2 key is provided, the function fails.
 * \param Client The client that initiated the request.
 * \param AccessMode The mode in which to perform access checks.
 */
NTSTATUS KpiReadVirtualMemoryUnsafe(
    _In_opt_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead,
    _In_opt_ KPH_KEY Key,
    _In_ PKPH_CLIENT Client,
    _In_ KPROCESSOR_MODE AccessMode
    )
{
    NTSTATUS status;
    PEPROCESS process;
    SIZE_T numberOfBytesRead = 0;

    PAGED_CODE();

    if (!NT_SUCCESS(status = KphValidateKey(KphKeyLevel2, Key, Client, AccessMode)))
        return status;

    if (AccessMode != KernelMode)
    {
        if (
            (ULONG_PTR)BaseAddress + BufferSize < (ULONG_PTR)BaseAddress ||
            (ULONG_PTR)Buffer + BufferSize < (ULONG_PTR)Buffer ||
            (ULONG_PTR)Buffer + BufferSize > (ULONG_PTR)MmHighestUserAddress
            )
        {
            return STATUS_ACCESS_VIOLATION;
        }

        if (NumberOfBytesRead)
        {
            __try
            {
                ProbeForWrite(NumberOfBytesRead, sizeof(SIZE_T), sizeof(SIZE_T));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return GetExceptionCode();
            }
        }
    }

    if (BufferSize != 0)
    {
        // Select the appropriate copy method.
        if ((ULONG_PTR)BaseAddress > (ULONG_PTR)MmHighestUserAddress)
        {
			if (AccessMode == UserMode)
			{
				PVOID LockedBuffer, LockedMdl;
				status = ExLockUserBuffer(Buffer, (ULONG)BufferSize, KernelMode, IoWriteAccess, &LockedBuffer, &LockedMdl);
				if (status == STATUS_SUCCESS) {
					status = SafeReadKernelMemory(LockedBuffer, BaseAddress, BufferSize, &numberOfBytesRead);
					ExUnlockUserBuffer(LockedMdl);
				}
			}
			else
			{
				status = SafeReadKernelMemory(Buffer, BaseAddress, BufferSize, &numberOfBytesRead);
			}
        }
        else
        {
            // User memory copy (safe)

            status = ObReferenceObjectByHandle(
                ProcessHandle,
                PROCESS_VM_READ,
                *PsProcessType,
                AccessMode,
                &process,
                NULL
                );

            if (NT_SUCCESS(status))
            {
                status = KphCopyVirtualMemory(
                    process,
                    BaseAddress,
                    PsGetCurrentProcess(),
                    Buffer,
                    BufferSize,
                    AccessMode,
                    &numberOfBytesRead
                    );
                ObDereferenceObject(process);
            }
        }
    }
    else
    {
        numberOfBytesRead = 0;
        status = STATUS_SUCCESS;
    }

    if (NumberOfBytesRead)
    {
        if (AccessMode != KernelMode)
        {
            __try
            {
                *NumberOfBytesRead = numberOfBytesRead;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Don't mess with the status.
                NOTHING;
            }
        }
        else
        {
            *NumberOfBytesRead = numberOfBytesRead;
        }
    }

    return status;
}

NTSTATUS KpiQueryVirtualMemory(
	_In_opt_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength,
	_In_opt_ KPH_KEY Key,
	_In_ PKPH_CLIENT Client,
	_In_ KPROCESSOR_MODE AccessMode
)
{
	NTSTATUS status;
	PEPROCESS process;
	SIZE_T numberOfBytesRead = 0;

	PAGED_CODE();

	if (!NT_SUCCESS(status = KphValidateKey(KphKeyLevel1, Key, Client, AccessMode)))
		return status;

	if (AccessMode != KernelMode)
	{
		if ((ULONG_PTR)MemoryInformation + MemoryInformationLength >(ULONG_PTR)MmHighestUserAddress)
		{
			return STATUS_ACCESS_VIOLATION;
		}

		if (ReturnLength)
		{
			__try
			{
				ProbeForWrite(ReturnLength, sizeof(SIZE_T), sizeof(SIZE_T));
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}
	}

	if (MemoryInformationLength != 0)
	{
		status = ObReferenceObjectByHandle(
			ProcessHandle,
			PROCESS_QUERY_LIMITED_INFORMATION,
			*PsProcessType,
			AccessMode,
			&process,
			NULL
		);

		if (NT_SUCCESS(status))
		{
			if (AccessMode != KernelMode)
			{
				PVOID LockedBuffer = NULL;
				PVOID LockMdl = NULL;
				status = ExLockUserBuffer(MemoryInformation, (ULONG)MemoryInformationLength, ExGetPreviousMode(), IoWriteAccess, &LockedBuffer, &LockMdl);
				if (status == STATUS_SUCCESS)
				{
					KAPC_STATE apcState;
					KeStackAttachProcess(process, &apcState);

					status = ZwQueryVirtualMemory(
						NtCurrentProcess(),
						BaseAddress,
						MemoryInformationClass,
						LockedBuffer,
						MemoryInformationLength,
						&numberOfBytesRead
					);

					KeUnstackDetachProcess(&apcState);

					//fix unicode string buffer
					if (MemoryInformationClass == MemoryMappedFilenameInformation && numberOfBytesRead >= sizeof(UNICODE_STRING))
					{
						PUNICODE_STRING ustr = (PUNICODE_STRING)LockedBuffer;
						ULONG_PTR BufferRva = (PUCHAR)ustr->Buffer - (PUCHAR)LockedBuffer;
						ustr->Buffer = (PWCH)((PUCHAR)MemoryInformation + BufferRva);
					}

					ExUnlockUserBuffer(LockMdl);
				}
			}
			else
			{
				KAPC_STATE apcState;
				KeStackAttachProcess(process, &apcState);

				status = ZwQueryVirtualMemory(
					NtCurrentProcess(),
					BaseAddress,
					MemoryInformationClass,
					MemoryInformation,
					MemoryInformationLength,
					&numberOfBytesRead
				);

				KeUnstackDetachProcess(&apcState);
			}

			ObDereferenceObject(process);
		}
	}
	else
	{
		numberOfBytesRead = 0;
		status = STATUS_SUCCESS;
	}

	if (ReturnLength)
	{
		if (AccessMode != KernelMode)
		{
			__try
			{
				*ReturnLength = numberOfBytesRead;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				// Don't mess with the status.
				NOTHING;
			}
		}
		else
		{
			*ReturnLength = numberOfBytesRead;
		}
	}

	return status;
}
