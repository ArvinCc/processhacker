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
#include <dyndata.h>

typedef BOOLEAN(*EnumNotifyRoutineCallback)(PVOID, void *);

VOID KphpCopyInfoUnicodeString(
    _Out_ PVOID Information,
    _In_opt_ PUNICODE_STRING UnicodeString
    );

NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KpiOpenDriver)
#pragma alloc_text(PAGE, KpiQueryInformationDriver)
#pragma alloc_text(PAGE, KphpCopyInfoUnicodeString)
#endif

NTSTATUS KpiOpenDriver(
    _Out_ PHANDLE DriverHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ KPROCESSOR_MODE AccessMode
    )
{
    PAGED_CODE();

    return KphOpenNamedObject(
        DriverHandle,
        DesiredAccess,
        ObjectAttributes,
        *IoDriverObjectType,
        AccessMode
        );
}

NTSTATUS KpiQueryInformationDriver(
    _In_ HANDLE DriverHandle,
    _In_ DRIVER_INFORMATION_CLASS DriverInformationClass,
    _Out_writes_bytes_(DriverInformationLength) PVOID DriverInformation,
    _In_ ULONG DriverInformationLength,
    _Out_opt_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE AccessMode
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_OBJECT driverObject;

    PAGED_CODE();

    if (AccessMode != KernelMode)
    {
        __try
        {
            ProbeForWrite(DriverInformation, DriverInformationLength, 1);

            if (ReturnLength)
                ProbeForWrite(ReturnLength, sizeof(ULONG), 1);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
    }

    status = ObReferenceObjectByHandle(
        DriverHandle,
        0,
        *IoDriverObjectType,
        AccessMode,
        &driverObject,
        NULL
        );

    if (!NT_SUCCESS(status))
        return status;

    __try
    {
        switch (DriverInformationClass)
        {
            // Basic information such as flags, driver base and driver size.
            case DriverBasicInformation:
            {
                if (DriverInformationLength == sizeof(DRIVER_BASIC_INFORMATION))
                {
                    PDRIVER_BASIC_INFORMATION basicInfo;

                    basicInfo = (PDRIVER_BASIC_INFORMATION)DriverInformation;
                    basicInfo->Flags = driverObject->Flags;
                    basicInfo->DriverStart = driverObject->DriverStart;
                    basicInfo->DriverSize = driverObject->DriverSize;
                }
                else
                {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                }

                if (ReturnLength)
                    *ReturnLength = sizeof(DRIVER_BASIC_INFORMATION);
            }
            break;

            // The name of the driver - e.g. \Driver\Null.
            case DriverNameInformation:
            {
                if (DriverInformation)
                {
                    /* Check buffer length. */
                    if (sizeof(UNICODE_STRING) + driverObject->DriverName.Length <=
                        DriverInformationLength)
                    {
                        KphpCopyInfoUnicodeString(
                            DriverInformation,
                            &driverObject->DriverName
                            );
                    }
                    else
                    {
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                }

                if (ReturnLength)
                    *ReturnLength = sizeof(UNICODE_STRING) + driverObject->DriverName.Length;
            }
            break;

            // The name of the driver's service key - e.g. \REGISTRY\...
            case DriverServiceKeyNameInformation:
            {
                if (driverObject->DriverExtension)
                {
                    if (DriverInformation)
                    {
                        if (sizeof(UNICODE_STRING) +
                            driverObject->DriverExtension->ServiceKeyName.Length <=
                            DriverInformationLength)
                        {
                            KphpCopyInfoUnicodeString(
                                DriverInformation,
                                &driverObject->DriverExtension->ServiceKeyName
                                );
                        }
                        else
                        {
                            status = STATUS_BUFFER_TOO_SMALL;
                        }
                    }

                    if (ReturnLength)
                    {
                        *ReturnLength = sizeof(UNICODE_STRING) +
                            driverObject->DriverExtension->ServiceKeyName.Length;
                    }
                }
                else
                {
                    if (DriverInformation)
                    {
                        if (sizeof(UNICODE_STRING) <= DriverInformationLength)
                        {
                            // Zero the information buffer.
                            KphpCopyInfoUnicodeString(
                                DriverInformation,
                                NULL
                                );
                        }
                        else
                        {
                            status = STATUS_BUFFER_TOO_SMALL;
                        }
                    }

                    if (ReturnLength)
                        *ReturnLength = sizeof(UNICODE_STRING);
                }
            }
            break;

            default:
            {
                status = STATUS_INVALID_INFO_CLASS;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
    }

    ObDereferenceObject(driverObject);

    return status;
}

VOID KphpCopyInfoUnicodeString(
    _Out_ PVOID Information,
    _In_opt_ PUNICODE_STRING UnicodeString
    )
{
    PUNICODE_STRING targetUnicodeString = Information;
    PWCHAR targetBuffer;

    PAGED_CODE();

    if (UnicodeString)
    {
        targetBuffer = (PWCHAR)PTR_ADD_OFFSET(Information, sizeof(UNICODE_STRING));

        targetUnicodeString->Length = UnicodeString->Length;
        targetUnicodeString->MaximumLength = UnicodeString->Length;
        targetUnicodeString->Buffer = targetBuffer;
        memcpy(targetBuffer, UnicodeString->Buffer, UnicodeString->Length);
    }
    else
    {
        targetUnicodeString->Length = 0;
        targetUnicodeString->MaximumLength = 0;
        targetUnicodeString->Buffer = NULL;
    }
}

NTSTATUS EnumPsCreateProcessNotifyRoutines(EnumNotifyRoutineCallback callback, void *ctx)
{
    PVOID MagicPtr, Point, NotifyAddr;

    if (!PspCreateProcessNotifyRoutine)
        return STATUS_NOT_FOUND;

    int maxCount = PspCreateProcessNotifyRoutineMaxCount ? PspCreateProcessNotifyRoutineMaxCount : 8;

#ifdef _WIN64
    for (int i = 0; i < maxCount; i++)
    {
        MagicPtr = (PVOID)((PUCHAR)PspCreateProcessNotifyRoutine + i * sizeof(PVOID));
        Point = (PVOID)*(PULONG64)(MagicPtr);
        if (Point != 0 && MmIsAddressValid(Point))
        {
            NotifyAddr = (PVOID)*(PULONG64)(((ULONG64)Point & 0xfffffffffffffff0ui64) + sizeof(EX_RUNDOWN_REF));
            if (NotifyAddr > MmSystemRangeStart && callback(NotifyAddr, ctx))
                return STATUS_SUCCESS;
        }
    }
#else
    for (int i = 0; i < maxCount; i++)
    {
        MagicPtr = (PVOID)((PUCHAR)PspCreateProcessNotifyRoutine + i * sizeof(PVOID));
        Point = (PVOID)*(PULONG)(MagicPtr);
        if (Point != 0 && MmIsAddressValid(Point))
        {
            NotifyAddr = (PVOID)*(PULONG)(((ULONG)Point & 0xfffffff8) + sizeof(EX_RUNDOWN_REF));
            if (NotifyAddr > MmSystemRangeStart && callback(NotifyAddr, ctx))
                return STATUS_SUCCESS;
        }
    }
#endif
    return STATUS_SUCCESS;
}

NTSTATUS EnumPsLoadImageNotifyRoutines(EnumNotifyRoutineCallback callback, void *ctx)
{
    PVOID MagicPtr, Point, NotifyAddr;

    if (!PspLoadImageNotifyRoutine)
        return STATUS_NOT_FOUND;

    int maxCount = PspLoadImageNotifyRoutineMaxCount ? PspLoadImageNotifyRoutineMaxCount : 8;

#ifdef _WIN64
    for (int i = 0; i < maxCount; i++)
    {
        MagicPtr = (PVOID)((PUCHAR)PspLoadImageNotifyRoutine + i * sizeof(PVOID));
        Point = (PVOID)*(PULONG64)(MagicPtr);
        if (Point != 0 && MmIsAddressValid(Point))
        {
            NotifyAddr = (PVOID)*(PULONG64)(((ULONG64)Point & 0xfffffffffffffff0ui64) + sizeof(EX_RUNDOWN_REF));
            if (NotifyAddr > MmSystemRangeStart && callback(NotifyAddr, ctx))
                return STATUS_SUCCESS;
        }
    }
#else
    for (int i = 0; i < maxCount; i++)
    {
        MagicPtr = (PVOID)((PUCHAR)PspLoadImageNotifyRoutine + i * sizeof(PVOID));
        Point = (PVOID)*(PULONG)(MagicPtr);
        if (Point != 0 && MmIsAddressValid(Point))
        {
            NotifyAddr = (PVOID)*(PULONG)(((ULONG)Point & 0xfffffff8) + sizeof(EX_RUNDOWN_REF));
            if (NotifyAddr > MmSystemRangeStart && callback(NotifyAddr, ctx))
                return STATUS_SUCCESS;
        }
    }
#endif
    return STATUS_SUCCESS;
}

typedef struct _KpiEnumKernelCallbackContext
{
    PVOID UserBuffer;
    PVOID MappedAddress;
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG BufferLength;
    ULONG *RequiredLength;
    NTSTATUS Status;
    ULONG CurrentEnumType;
}KpiEnumKernelCallbackContext;

BOOLEAN KpiEnumKernelCallback_Enumerator(PVOID NotifyRoutine, void *context)
{
    PVOID ImageBase2;
    KpiEnumKernelCallbackContext *ctx = (KpiEnumKernelCallbackContext *)context;

    __try
    {
        KPH_ENUM_CALLBACK_ENTRY * EntryInfo = (KPH_ENUM_CALLBACK_ENTRY *)((PUCHAR)ctx->MappedAddress + ctx->TotalSize);
        ctx->NextEntryOffset = sizeof(KPH_ENUM_CALLBACK_ENTRY);
        ctx->TotalSize += sizeof(KPH_ENUM_CALLBACK_ENTRY);

        if (ctx->TotalSize > ctx->BufferLength)
        {
            ctx->Status = STATUS_INFO_LENGTH_MISMATCH;
            if (ARGUMENT_PRESENT(ctx->RequiredLength) == FALSE)
                __leave;
        }
        else
        {
            EntryInfo->NextEntryOffset = 0;
            EntryInfo->CallbackAddress = NotifyRoutine;
            EntryInfo->Type = ctx->CurrentEnumType;
            EntryInfo->ImageBase = RtlPcToFileHeader(NotifyRoutine, &ImageBase2);
        }

        if (NT_SUCCESS(ctx->Status)) {
            EntryInfo->NextEntryOffset = ctx->NextEntryOffset;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {

    }

    if (ARGUMENT_PRESENT(ctx->RequiredLength)) {
        *ctx->RequiredLength = ctx->TotalSize;
    }

    return ctx->Status != STATUS_SUCCESS;
}

NTSTATUS KpiEnumKernelCallback(
    _Out_writes_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength,
    _Out_opt_ PULONG ReturnLength,
    _In_ KPROCESSOR_MODE AccessMode
)
{
    KpiEnumKernelCallbackContext ctx;

    PVOID MappedAddress = NULL;
    PVOID LockVariable = NULL;
    NTSTATUS st;

    if (ARGUMENT_PRESENT(ReturnLength)) {
        *ReturnLength = 0;
    }
 
    if (BufferLength > 0)
    {
        st = ExLockUserBuffer(Buffer,
            BufferLength,
            ExGetPreviousMode(),
            IoWriteAccess,
            &MappedAddress,
            &LockVariable);

        if (!NT_SUCCESS(st))
            return st;
    }

    ctx.UserBuffer = Buffer;
    ctx.MappedAddress = MappedAddress;
    ctx.NextEntryOffset = 0;
    ctx.BufferLength = BufferLength;
    ctx.RequiredLength = ReturnLength;
    ctx.TotalSize = 0;
    ctx.Status = STATUS_SUCCESS;

    ctx.CurrentEnumType = KphCallbackPsCreateProcess;
    st = EnumPsCreateProcessNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx);

    ctx.CurrentEnumType = KphCallbackPsLoadImage;
    st = EnumPsLoadImageNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx);

    if (!NT_SUCCESS(st))
        ctx.Status = st;

    if (MappedAddress != NULL)
        ExUnlockUserBuffer(LockVariable);

    return ctx.Status;
}
