/*
 * KProcessHacker
 *
 * Copyright (C) 2016 wj32
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

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KphFreeCapturedUnicodeString)
#pragma alloc_text(PAGE, KphCaptureUnicodeString)
#pragma alloc_text(PAGE, KphEnumerateSystemModules)
#pragma alloc_text(PAGE, KphValidateAddressForSystemModules)
#pragma alloc_text(PAGE, KphGetProcessMappedFileName)
#endif

static PhysicalMemoryDescriptor *g_utilp_physical_memory_ranges;

VOID KphFreeCapturedUnicodeString(
    _In_ PUNICODE_STRING CapturedUnicodeString
    )
{
    PAGED_CODE();

    if (CapturedUnicodeString->Buffer)
        ExFreePoolWithTag(CapturedUnicodeString->Buffer, 'UhpK');
}

NTSTATUS KphCaptureUnicodeString(
    _In_ PUNICODE_STRING UnicodeString,
    _Out_ PUNICODE_STRING CapturedUnicodeString
    )
{
    UNICODE_STRING unicodeString;
    PWCHAR userBuffer;

    PAGED_CODE();

    __try
    {
        ProbeForRead(UnicodeString, sizeof(UNICODE_STRING), sizeof(ULONG));
        unicodeString.Length = UnicodeString->Length;
        unicodeString.MaximumLength = unicodeString.Length;
        unicodeString.Buffer = NULL;

        userBuffer = UnicodeString->Buffer;
        ProbeForRead(userBuffer, unicodeString.Length, sizeof(WCHAR));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }

    if (unicodeString.Length & 1)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (unicodeString.Length != 0)
    {
        unicodeString.Buffer = ExAllocatePoolWithTag(
            PagedPool,
            unicodeString.Length,
            'UhpK'
            );

        if (!unicodeString.Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        __try
        {
            memcpy(
                unicodeString.Buffer,
                userBuffer,
                unicodeString.Length
                );
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            KphFreeCapturedUnicodeString(&unicodeString);
            return GetExceptionCode();
        }
    }

    *CapturedUnicodeString = unicodeString;

    return STATUS_SUCCESS;
}

/**
 * Enumerates the modules loaded by the kernel.
 *
 * \param Modules A variable which receives a pointer to a structure containing information about
 * the kernel modules. The structure must be freed with the tag 'ThpK'.
 */
NTSTATUS KphEnumerateSystemModules(
    _Out_ PRTL_PROCESS_MODULES *Modules
    )
{
    NTSTATUS status;
    PVOID buffer;
    ULONG bufferSize;
    ULONG attempts;

    PAGED_CODE();

    bufferSize = 2048;
    attempts = 8;

    do
    {
        buffer = ExAllocatePoolWithTag(PagedPool, bufferSize, 'ThpK');

        if (!buffer)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        status = ZwQuerySystemInformation(
            SystemModuleInformation,
            buffer,
            bufferSize,
            &bufferSize
            );

        if (NT_SUCCESS(status))
        {
            *Modules = buffer;

            return status;
        }

        ExFreePoolWithTag(buffer, 'ThpK');

        if (status != STATUS_INFO_LENGTH_MISMATCH)
        {
            break;
        }
    } while (--attempts);

    return status;
}

/**
 * Checks if an address range lies within a kernel module.
 *
 * \param Address The beginning of the address range.
 * \param Length The number of bytes in the address range.
 */
NTSTATUS KphValidateAddressForSystemModules(
    _In_ PVOID Address,
    _In_ SIZE_T Length
    )
{
    NTSTATUS status;
    PRTL_PROCESS_MODULES modules;
    ULONG i;
    BOOLEAN valid;

    PAGED_CODE();

    status = KphEnumerateSystemModules(&modules);

    if (!NT_SUCCESS(status))
        return status;

    valid = FALSE;

    for (i = 0; i < modules->NumberOfModules; i++)
    {
        if (
            (ULONG_PTR)Address + Length >= (ULONG_PTR)Address &&
            (ULONG_PTR)Address >= (ULONG_PTR)modules->Modules[i].ImageBase &&
            (ULONG_PTR)Address + Length <= (ULONG_PTR)modules->Modules[i].ImageBase + modules->Modules[i].ImageSize
            )
        {
            dprintf("Validated address 0x%Ix in %s\n", Address, modules->Modules[i].FullPathName);
            valid = TRUE;
            break;
        }
    }

    ExFreePoolWithTag(modules, 'ThpK');

    if (valid)
        status = STATUS_SUCCESS;
    else
        status = STATUS_ACCESS_VIOLATION;

    return status;
}

/**
 * Gets the file name of a mapped section.
 *
 * \param ProcessHandle A handle to a process. The handle must have PROCESS_QUERY_INFORMATION
 * access.
 * \param BaseAddress The base address of the section view.
 * \param Modules A variable which receives a pointer to a string containing the file name of the
 * section. The structure must be freed with the tag 'ThpK'.
 */
NTSTATUS KphGetProcessMappedFileName(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PUNICODE_STRING *FileName
    )
{
    NTSTATUS status;
    PVOID buffer;
    SIZE_T bufferSize;
    SIZE_T returnLength;

    PAGED_CODE();

    bufferSize = 0x100;
    buffer = ExAllocatePoolWithTag(PagedPool, bufferSize, 'ThpK');

    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQueryVirtualMemory(
        ProcessHandle,
        BaseAddress,
        MemoryMappedFilenameInformation,
        buffer,
        bufferSize,
        &returnLength
        );

    if (status == STATUS_BUFFER_OVERFLOW)
    {
        ExFreePoolWithTag(buffer, 'ThpK');
        bufferSize = returnLength;
        buffer = ExAllocatePoolWithTag(PagedPool, bufferSize, 'ThpK');

        if (!buffer)
            return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQueryVirtualMemory(
            ProcessHandle,
            BaseAddress,
            MemoryMappedFilenameInformation,
            buffer,
            bufferSize,
            &returnLength
            );
    }

    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(buffer, 'ThpK');
        return status;
    }

    *FileName = buffer;

    return status;
}

typedef struct _KIPICALL_CONTEXT
{
	ULONG		   ProcessorId;
	volatile LONG  RunningProcessor;
	volatile LONG  ProcessorsToResume;
	ULONG		   Done;
	TransactionCommitCallback Callback;
	PVOID		   Params;
}KIPICALL_CONTEXT, *PKIPICALL_CONTEXT;

ULONG_PTR TransactionCommitIpiCaster(ULONG_PTR Argument)
{
	PKIPICALL_CONTEXT context = (PKIPICALL_CONTEXT)Argument;
	if (KeGetCurrentProcessorNumber() != context->ProcessorId)
	{
		InterlockedDecrement(&context->RunningProcessor);
		while (context->Done == FALSE)
			YieldProcessor();
		InterlockedDecrement(&context->ProcessorsToResume);
	}
	else
	{
		while (context->RunningProcessor != 0)
			YieldProcessor();

		context->Callback(context->Params);

		context->Done = TRUE;

		while (context->ProcessorsToResume != 0)
			YieldProcessor();
	}
	return 0;
}

VOID TransactionCommitIpi(TransactionCommitCallback callback, void *context)
{
	PKIPICALL_CONTEXT ctx = (PKIPICALL_CONTEXT)ExAllocatePool(NonPagedPool, sizeof(KIPICALL_CONTEXT));

	ctx->ProcessorId = KeGetCurrentProcessorNumber();
	ctx->RunningProcessor = KeQueryActiveProcessorCount(NULL) - 1;
	ctx->ProcessorsToResume = KeQueryActiveProcessorCount(NULL) - 1;
	ctx->Callback = callback;
	ctx->Params = context;
	ctx->Done = FALSE;

	KeIpiGenericCall(TransactionCommitIpiCaster, (ULONG_PTR)ctx);

	ExFreePool(ctx);
}

// VA -> PA
_Use_decl_annotations_ ULONG64 UtilPaFromVa(void *va) {
	const PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(va);
	return pa.QuadPart;
}

// PA -> PFN
_Use_decl_annotations_ PFN_NUMBER UtilPfnFromPa(ULONG64 pa) {
	return (PFN_NUMBER)(pa >> PAGE_SHIFT);
}

// VA -> PFN
_Use_decl_annotations_ PFN_NUMBER UtilPfnFromVa(void *va) {
	return UtilPfnFromPa(UtilPaFromVa(va));
}

// PA -> VA
_Use_decl_annotations_ void *UtilVaFromPa(ULONG64 pa) {
	PHYSICAL_ADDRESS pa2 = {0};
	pa2.QuadPart = pa;
	return MmGetVirtualForPhysical(pa2);
}

// PNF -> PA
_Use_decl_annotations_ ULONG64 UtilPaFromPfn(PFN_NUMBER pfn) {
	return pfn << PAGE_SHIFT;
}

// PFN -> VA
_Use_decl_annotations_ void *UtilVaFromPfn(PFN_NUMBER pfn) {
	return UtilVaFromPa(UtilPaFromPfn(pfn));
}

// Builds the physical memory ranges
_Use_decl_annotations_ PhysicalMemoryDescriptor *
UtilpBuildPhysicalMemoryRanges() {
	PAGED_CODE();

	PPHYSICAL_MEMORY_RANGE pm_ranges = MmGetPhysicalMemoryRanges();
	if (!pm_ranges) {
		return NULL;
	}

	PFN_COUNT number_of_runs = 0;
	PFN_NUMBER number_of_pages = 0;
	for (/**/; /**/; ++number_of_runs) {
		const PPHYSICAL_MEMORY_RANGE range = &pm_ranges[number_of_runs];
		if (!range->BaseAddress.QuadPart && !range->NumberOfBytes.QuadPart) {
			break;
		}
		number_of_pages += (PFN_NUMBER)(BYTES_TO_PAGES(range->NumberOfBytes.QuadPart));
	}
	if (number_of_runs == 0) {
		ExFreePoolWithTag(pm_ranges, 'hPmM');
		return NULL;
	}

	int memory_block_size =
		sizeof(PhysicalMemoryDescriptor) +
		sizeof(PhysicalMemoryRun) * (number_of_runs - 1);
	
	PhysicalMemoryDescriptor * pm_block = (PhysicalMemoryDescriptor *)(ExAllocatePool(
			NonPagedPool, memory_block_size));
	if (!pm_block) {
		ExFreePoolWithTag(pm_ranges, 'hPmM');
		return NULL;
	}
	RtlZeroMemory(pm_block, memory_block_size);

	pm_block->number_of_runs = number_of_runs;
	pm_block->number_of_pages = number_of_pages;

	for (ULONG_PTR run_index = 0ul; run_index < number_of_runs; run_index++) {
		PhysicalMemoryRun *current_run = &pm_block->run[run_index];
		PPHYSICAL_MEMORY_RANGE current_block = &pm_ranges[run_index];
		current_run->base_page = (ULONG_PTR)(UtilPfnFromPa(current_block->BaseAddress.QuadPart));
		current_run->page_count = (ULONG_PTR)(BYTES_TO_PAGES(current_block->NumberOfBytes.QuadPart));
	}

	ExFreePoolWithTag(pm_ranges, 'hPmM');
	return pm_block;
}

// Returns the physical memory ranges
/*_Use_decl_annotations_*/ const PhysicalMemoryDescriptor *
UtilGetPhysicalMemoryRanges() {
	return g_utilp_physical_memory_ranges;
}

BOOLEAN UtilIsInBounds(_In_ const ULONG64 value, _In_ const ULONG64 min,
	_In_ const ULONG64 max) {
	return (min <= value) && (value <= max);
}

// Returns if the physical_address is device memory (which could not have a
// corresponding PFN entry)
_Use_decl_annotations_ BOOLEAN UtilIsDeviceMemory(
	ULONG64 physical_address) {
	const PhysicalMemoryDescriptor *pm_ranges = UtilGetPhysicalMemoryRanges();
	for (ULONG_PTR i = 0ul; i < pm_ranges->number_of_runs; ++i) {
		const PhysicalMemoryRun *current_run = &pm_ranges->run[i];
		ULONG64 base_addr = (ULONG64)(current_run->base_page) * PAGE_SIZE;
		ULONG64 endAddr = base_addr + current_run->page_count * PAGE_SIZE - 1;
		if (UtilIsInBounds(physical_address, base_addr, endAddr)) {
			return FALSE;
		}
	}
	return TRUE;
}

VOID ExUnlockUserBuffer(
	__inout PVOID LockVariable
)
{
	MmUnlockPages((PMDL)LockVariable);
	ExFreePool((PMDL)LockVariable);
	return;
}

NTSTATUS ExLockUserBuffer(
	__inout_bcount(Length) PVOID Buffer,
	__in ULONG Length,
	__in KPROCESSOR_MODE ProbeMode,
	__in LOCK_OPERATION LockMode,
	__deref_out PVOID *LockedBuffer,
	__deref_out PVOID *LockVariable
)
{
	PMDL Mdl;
	SIZE_T MdlSize;

	//
	// It is the caller's responsibility to ensure zero cannot be passed in.
	//

	ASSERT(Length != 0);

	*LockedBuffer = NULL;
	*LockVariable = NULL;

	//
	// Allocate an MDL to map the request.
	//

	MdlSize = MmSizeOfMdl(Buffer, Length);
	Mdl = (PMDL)ExAllocatePoolWithQuotaTag((POOL_TYPE)((int)NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE),
		MdlSize,
		'ofnI');
	if (Mdl == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Initialize MDL for request.
	//

	MmInitializeMdl(Mdl, Buffer, Length);

	__try {

		MmProbeAndLockPages(Mdl, ProbeMode, LockMode);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		ExFreePool(Mdl);

		return GetExceptionCode();
	}

	Mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;
	*LockedBuffer = MmGetSystemAddressForMdlSafe(Mdl, HighPagePriority);
	if (*LockedBuffer == NULL) {
		ExUnlockUserBuffer(Mdl);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	*LockVariable = Mdl;
	return STATUS_SUCCESS;
}