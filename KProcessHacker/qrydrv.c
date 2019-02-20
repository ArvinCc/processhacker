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

BOOLEAN
FORCEINLINE
ExFastRefObjectNull(
    __in EX_FAST_REF FastRef
)
/*++

Routine Description:

    This routine allows the caller to test of the specified fastref value
    has a null pointer

Arguments:

    FastRef - Fast reference block to be used

Return Value:

    BOOLEAN - TRUE if the object is NULL FALSE otherwise

--*/
{
    return (BOOLEAN)(FastRef.Value == 0);
}

LOGICAL
FORCEINLINE
ExFastRefCanBeReferenced(
    __in EX_FAST_REF FastRef
)
/*++

Routine Description:

    This routine allows the caller to determine if the fast reference
    structure contains cached references.

Arguments:

    FastRef - Fast reference block to be used

Return Value:

    LOGICAL - TRUE: There were cached references in the object,
              FALSE: No cached references are available.

--*/
{
    return FastRef.RefCnt != 0;
}

PVOID
FORCEINLINE
ExFastRefGetObject(
    __in EX_FAST_REF FastRef
)
/*++

Routine Description:

    This routine allows the caller to obtain the object pointer from a fast
    reference structure.

Arguments:

    FastRef - Fast reference block to be used

Return Value:

    PVOID - The contained object or NULL if there isn't one.

--*/
{
    return (PVOID)(FastRef.Value & ~MAX_FAST_REFS);
}

EX_FAST_REF
ExFastReference(
    __inout PEX_FAST_REF FastRef
)
/*++

Routine Description:

    This routine attempts to obtain a fast (cached) reference from a fast
    reference structure.

Arguments:

    FastRef - Fast reference block to be used

Return Value:

    EX_FAST_REF - The old or current contents of the fast reference structure.

--*/
{
    EX_FAST_REF OldRef, NewRef;

    while (1) {
        //
        // Fetch the old contents of the fast ref structure
        //
        OldRef = ReadForWriteAccess(FastRef);
        //
        // If the object pointer is null or if there are no cached references
        // left then bail. In the second case this reference will need to be
        // taken while holding the lock. Both cases are covered by the single
        // test of the lower bits since a null pointer can never have cached
        // refs.
        //
        if (OldRef.RefCnt != 0) {
            //
            // We know the bottom bits can't underflow into the pointer for a
            // request that works so just decrement
            //
            NewRef.Value = OldRef.Value - 1;
            NewRef.Object = InterlockedCompareExchangePointerAcquire(&FastRef->Object,
                NewRef.Object,
                OldRef.Object);
            if (NewRef.Object != OldRef.Object) {
                //
                // The structured changed beneath us. Try the operation again
                //
                continue;
            }
        }
        break;
    }

    return OldRef;
}

LOGICAL
ExFastRefDereference(
    __inout PEX_FAST_REF FastRef,
    __in PVOID Object
)
/*++

Routine Description:

    This routine attempts to release a fast reference from a fast ref
    structure. This routine could be called for a reference obtained
    directly from the object but presumably the chances of the pointer
    matching would be unlikely. The algorithm will work correctly in this
    case.

Arguments:

    FastRef - Fast reference block to be used

    Object - The original object that the reference was taken on.

Return Value:

    LOGICAL - TRUE: The fast dereference worked ok, FALSE: the
              dereference didn't.

--*/
{
    EX_FAST_REF OldRef, NewRef;

    while (1) {
        //
        // Fetch the old contents of the fast ref structure
        //
        OldRef = ReadForWriteAccess(FastRef);

        //
        // If the reference cache is fully populated or the pointer has
        // changed to another object then just return the old value. The
        // caller can return the reference to the object instead.
        //
        if ((OldRef.Value ^ (ULONG_PTR)Object) >= MAX_FAST_REFS) {
            return FALSE;
        }
        //
        // We know the bottom bits can't overflow into the pointer so just
        // increment
        //
        NewRef.Value = OldRef.Value + 1;
        NewRef.Object = InterlockedCompareExchangePointerRelease(&FastRef->Object,
            NewRef.Object,
            OldRef.Object);
        if (NewRef.Object != OldRef.Object) {
            //
            // The structured changed beneath us. Try the operation again
            //
            continue;
        }
        break;
    }
    return TRUE;
}

LOGICAL
FORCEINLINE
ExFastRefIsLastReference(
    __in EX_FAST_REF FastRef
)
/*++

Routine Description:

    This routine allows the caller to determine if the fast reference
    structure contains only 1 cached reference.

Arguments:

    FastRef - Fast reference block to be used

Return Value:

    LOGICAL - TRUE: There is only one cached reference in the object,
              FALSE: The is more or less than one cached reference available.

--*/
{
    return FastRef.RefCnt == 1;
}

ULONG
FORCEINLINE
ExFastRefGetAdditionalReferenceCount(
    VOID
)
{
    return MAX_FAST_REFS;
}

LOGICAL
FORCEINLINE
ExFastRefAddAdditionalReferenceCounts(
    __inout PEX_FAST_REF FastRef,
    __in PVOID Object,
    __in ULONG RefsToAdd
)
/*++

Routine Description:

    This routine attempts to update the cached references on structure to
    allow future callers to run lock free. Callers must have already biased
    the object by the RefsToAdd reference count. This operation can fail at
    which point the caller should removed the extra references added and
    continue.

Arguments:

    FastRef - Fast reference block to be used

    Object - The original object that has had its reference count biased.

    RefsToAdd - The number of references to add to the cache

Return Value:

    LOGICAL - TRUE: The references where cached ok, FALSE: The references
              could not be cached.

--*/
{
    EX_FAST_REF OldRef, NewRef;

    ASSERT(RefsToAdd <= MAX_FAST_REFS);
    ASSERT((((ULONG_PTR)Object)&MAX_FAST_REFS) == 0);

    while (1) {
        //
        // Fetch the old contents of the fast ref structure
        //
        OldRef = ReadForWriteAccess(FastRef);

        //
        // If the count would push us above maximum cached references or
        // if the object pointer has changed the fail the request.
        //
        if (OldRef.RefCnt + RefsToAdd > MAX_FAST_REFS ||
            (ULONG_PTR)Object != (OldRef.Value & ~MAX_FAST_REFS)) {
            return FALSE;
        }
        //
        // We know the bottom bits can't overflow into the pointer so just
        // increment
        //
        NewRef.Value = OldRef.Value + RefsToAdd;
        NewRef.Object = InterlockedCompareExchangePointerAcquire(&FastRef->Object,
            NewRef.Object,
            OldRef.Object);
        if (NewRef.Object != OldRef.Object) {
            //
            // The structured changed beneath us. Use the return value from the
            // exchange and try it all again.
            //
            continue;
        }
        break;
    }
    return TRUE;
}

PEX_CALLBACK_ROUTINE_BLOCK
ExReferenceCallBackBlock(
    IN OUT PEX_CALLBACK CallBack
)
/*++

Routine Description:

    This function takes a reference on the call back block inside the
    callback structure.

Arguments:

    CallBack - Call back to obtain the call back block from

Return Value:

    PEX_CALLBACK_ROUTINE_BLOCK - Referenced structure or NULL if these wasn't one

--*/
{
    EX_FAST_REF OldRef;
    PEX_CALLBACK_ROUTINE_BLOCK CallBackBlock;

    //
    // Get a reference to the callback block if we can.
    //
    OldRef = ExFastReference(&CallBack->RoutineBlock);

    //
    // If there is no callback then return
    //
    if (ExFastRefObjectNull(OldRef)) {
        return NULL;
    }
    //
    // If we didn't get a reference then use a lock to get one.
    //
    if (!ExFastRefCanBeReferenced(OldRef)) {
        PKTHREAD CurrentThread;
        CurrentThread = KeGetCurrentThread();

        KeEnterCriticalRegion();

       // ExAcquirePushLockExclusive(&ExpCallBackFlush);

        CallBackBlock = ExFastRefGetObject(CallBack->RoutineBlock);
        if (CallBackBlock && !ExAcquireRundownProtection(&CallBackBlock->RundownProtect)) {
            CallBackBlock = NULL;
        }

        //ExReleasePushLockExclusive(&ExpCallBackFlush);

        KeLeaveCriticalRegion();

        if (CallBackBlock == NULL) {
            return NULL;
        }

    }
    else {
        CallBackBlock = ExFastRefGetObject(OldRef);

        //
        // If we just removed the last reference then attempt fix it up.
        //
        if (ExFastRefIsLastReference(OldRef)) {// && !ExpCallBackReturnRefs
            ULONG RefsToAdd;

            RefsToAdd = ExFastRefGetAdditionalReferenceCount();

            //
            // If we can't add the references then just give up
            //
            if (ExAcquireRundownProtectionEx(&CallBackBlock->RundownProtect,
                RefsToAdd)) {
                //
                // Repopulate the cached refs. If this fails we just give them back.
                //
                if (!ExFastRefAddAdditionalReferenceCounts(&CallBack->RoutineBlock,
                    CallBackBlock,
                    RefsToAdd)) {
                    ExReleaseRundownProtectionEx(&CallBackBlock->RundownProtect,
                        RefsToAdd);
                }
            }
        }
    }

    return CallBackBlock;
}

PEX_CALLBACK_FUNCTION
ExGetCallBackBlockRoutine(
    IN PEX_CALLBACK_ROUTINE_BLOCK CallBackBlock
)
/*++

Routine Description:

    This function gets the routine associated with a call back block

Arguments:

    CallBackBlock - Call back block to obtain routine for

Return Value:

    PEX_CALLBACK_FUNCTION - The function pointer associated with this block

--*/
{
    return CallBackBlock->Function;
}

PVOID
ExGetCallBackBlockContext(
    IN PEX_CALLBACK_ROUTINE_BLOCK CallBackBlock
)
/*++

Routine Description:

    This function gets the context associated with a call back block

Arguments:

    CallBackBlock - Call back block to obtain context for

Return Value:

    PVOID - The context associated with this block

--*/
{
    return CallBackBlock->Context;
}

VOID
ExDereferenceCallBackBlock(
    IN OUT PEX_CALLBACK CallBack,
    IN PEX_CALLBACK_ROUTINE_BLOCK CallBackBlock
)
/*++

Routine Description:

    This returns a reference previous obtained on a call back block

Arguments:

    CallBackBlock - Call back block to return reference to

Return Value:

    None

--*/
{
    if (!ExFastRefDereference(&CallBack->RoutineBlock, CallBackBlock)) {
        ExReleaseRundownProtection(&CallBackBlock->RundownProtect);
    }
}

NTSTATUS EnumPsCreateProcessNotifyRoutines(EnumNotifyRoutineCallback callback, void *ctx, int flags)
{
    PVOID MagicPtr, Point, NotifyAddr;

    if (!PspCreateProcessNotifyRoutine)
        return STATUS_NOT_FOUND;

    int maxCount = PspCreateProcessNotifyRoutineMaxCount ? PspCreateProcessNotifyRoutineMaxCount : 8;

    PEX_CALLBACK Psp = (PEX_CALLBACK)PspCreateProcessNotifyRoutine;

    for (int i = 0; i < maxCount; i++)
    {
        PEX_CALLBACK_ROUTINE_BLOCK CallBack = ExReferenceCallBackBlock(&Psp[i]);
        if (CallBack != NULL) {
            PVOID Routine = ExGetCallBackBlockRoutine(CallBack);
            int CallbackFlags = (int)(ULONG_PTR)ExGetCallBackBlockContext(CallBack);
            if (Routine > MmSystemRangeStart && CallbackFlags == flags && callback(Routine, ctx))
            {
                ExDereferenceCallBackBlock(&Psp[i], CallBack);
                break;
            }
            ExDereferenceCallBackBlock(&Psp[i], CallBack);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS EnumPsCreateThreadNotifyRoutines(EnumNotifyRoutineCallback callback, void *ctx, int flags)
{
    PVOID MagicPtr, Point, NotifyAddr;

    if (!PspCreateThreadNotifyRoutine)
        return STATUS_NOT_FOUND;

    int maxCount = PspCreateThreadNotifyRoutineMaxCount ? PspCreateThreadNotifyRoutineMaxCount : 8;

    PEX_CALLBACK Psp = (PEX_CALLBACK)PspCreateThreadNotifyRoutine;

    for (int i = 0; i < maxCount; i++)
    {
        PEX_CALLBACK_ROUTINE_BLOCK CallBack = ExReferenceCallBackBlock(&Psp[i]);
        if (CallBack != NULL) {
            PVOID Routine = ExGetCallBackBlockRoutine(CallBack);
            int CallbackFlags = (int)(ULONG_PTR)ExGetCallBackBlockContext(CallBack);
            if (Routine > MmSystemRangeStart && CallbackFlags == flags && callback(Routine, ctx))
            {
                ExDereferenceCallBackBlock(&Psp[i], CallBack);
                break;
            }
            ExDereferenceCallBackBlock(&Psp[i], CallBack);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS EnumPsLoadImageNotifyRoutines(EnumNotifyRoutineCallback callback, void *ctx, int flags)
{
    PVOID MagicPtr, Point, NotifyAddr;

    if (!PspLoadImageNotifyRoutine)
        return STATUS_NOT_FOUND;

    int maxCount = PspLoadImageNotifyRoutineMaxCount ? PspLoadImageNotifyRoutineMaxCount : 8;

    PEX_CALLBACK Psp = (PEX_CALLBACK)PspLoadImageNotifyRoutine;

    for (int i = 0; i < maxCount; i++)
    {
        PEX_CALLBACK_ROUTINE_BLOCK CallBack = ExReferenceCallBackBlock(&Psp[i]);
        if (CallBack != NULL) {
            PVOID Routine = ExGetCallBackBlockRoutine(CallBack);
            int CallbackFlags = (int)(ULONG_PTR)ExGetCallBackBlockContext(CallBack);
            if (Routine > MmSystemRangeStart && CallbackFlags == flags && callback(Routine, ctx))
            {
                ExDereferenceCallBackBlock(&Psp[i], CallBack);
                break;
            }
            ExDereferenceCallBackBlock(&Psp[i], CallBack);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS EnumCmRegistryCallbacks(EnumNotifyRoutineCallback callback, void *ctx)
{
    if (!CmCallbackListHead)
        return STATUS_NOT_FOUND;

    PCM_NOTIFY_ENTRY notify = *(PCM_NOTIFY_ENTRY *)CmCallbackListHead;
    do
    {
        if (notify && MmIsAddressValid(notify))
        {
            if (notify->Function > MmSystemRangeStart && MmIsAddressValid((PVOID)(notify->Function)))
            {
                if (callback(notify->Function, ctx))
                    return STATUS_SUCCESS;
            }
        }
        else
        {
            break;
        }
        notify = (PCM_NOTIFY_ENTRY)notify->ListEntryHead.Flink;
    } while (notify != (*(PCM_NOTIFY_ENTRY*)(CmCallbackListHead)));

    return STATUS_SUCCESS;
}

NTSTATUS EnumProcessObCallbacks(EnumNotifyRoutineCallback callback, void *ctx, BOOLEAN IsPost)
{
    PLIST_ENTRY CurEntry;
    PLIST_ENTRY ListEntry = NULL;
    POBJECT_TYPE ObjType = *PsProcessType;

    if (KphDynOsVersionInfo.dwBuildNumber >= 9200)
    {
        POBJECT_TYPE_WIN8 ObjectType = (POBJECT_TYPE_WIN8)ObjType;
        ListEntry = (PLIST_ENTRY)&ObjectType->CallbackList;
    }
    else if (KphDynOsVersionInfo.dwBuildNumber >= 7600)
    {
        POBJECT_TYPE_WIN7 ObjectType = (POBJECT_TYPE_WIN7)ObjType;
        ListEntry = (PLIST_ENTRY)&ObjectType->CallbackList;
    }
    else if (KphDynOsVersionInfo.dwBuildNumber >= 6000)
    {
        POBJECT_TYPE_VISTA ObjectType = (POBJECT_TYPE_VISTA)ObjType;
        ListEntry = (PLIST_ENTRY)&ObjectType->CallbackList;
    }

    if (!ListEntry)
        return STATUS_NOT_FOUND;

    CurEntry = ListEntry->Flink;
    do
    {
        POB_CALLBACK ObCallback = (POB_CALLBACK)CurEntry;
        if (MmIsAddressValid(ObCallback))
        {
            if (ObCallback->ObHandle && ObCallback->ObjectType == ObjType)
            {
                if (IsPost && ObCallback->PostCall > MmSystemRangeStart)
                {
                    if (callback(ObCallback->PostCall, ctx))
                        return STATUS_SUCCESS;
                }
                else if (!IsPost && ObCallback->PreCall > MmSystemRangeStart)
                {
                    if (callback(ObCallback->PreCall, ctx))
                        return STATUS_SUCCESS;
                }
            }
        }
        CurEntry = CurEntry->Flink;
    } while (CurEntry != ListEntry);

    return STATUS_SUCCESS;
}

NTSTATUS EnumThreadObCallbacks(EnumNotifyRoutineCallback callback, void *ctx, BOOLEAN IsPost)
{
    PLIST_ENTRY CurEntry;
    PLIST_ENTRY ListEntry = NULL;
    POBJECT_TYPE ObjType = *PsThreadType;

    if (KphDynOsVersionInfo.dwBuildNumber >= 9200)
    {
        POBJECT_TYPE_WIN8 ObjectType = (POBJECT_TYPE_WIN8)ObjType;
        ListEntry = (PLIST_ENTRY)&ObjectType->CallbackList;
    }
    else if (KphDynOsVersionInfo.dwBuildNumber >= 7600)
    {
        POBJECT_TYPE_WIN7 ObjectType = (POBJECT_TYPE_WIN7)ObjType;
        ListEntry = (PLIST_ENTRY)&ObjectType->CallbackList;
    }
    else if (KphDynOsVersionInfo.dwBuildNumber >= 6000)
    {
        POBJECT_TYPE_VISTA ObjectType = (POBJECT_TYPE_VISTA)ObjType;
        ListEntry = (PLIST_ENTRY)&ObjectType->CallbackList;
    }

    if (!ListEntry)
        return STATUS_NOT_FOUND;

    CurEntry = ListEntry->Flink;
    do
    {
        POB_CALLBACK ObCallback = (POB_CALLBACK)CurEntry;
        if (MmIsAddressValid(ObCallback))
        {
            if (ObCallback->ObHandle && ObCallback->ObjectType == ObjType)
            {
                if (IsPost && ObCallback->PostCall > MmSystemRangeStart)
                {
                    if (callback(ObCallback->PostCall, ctx))
                        return STATUS_SUCCESS;
                }
                else if (!IsPost && ObCallback->PreCall > MmSystemRangeStart)
                {
                    if (callback(ObCallback->PreCall, ctx))
                        return STATUS_SUCCESS;
                }
            }
        }
        CurEntry = CurEntry->Flink;
    } while (CurEntry != ListEntry);

    return STATUS_SUCCESS;
}

NTSTATUS EnumerateDbgCallback(EnumNotifyRoutineCallback callback, void *ctx)
{
    if (!RtlpDebugPrintCallbackLock)
        return STATUS_NOT_FOUND;

    if (!RtlpDebugPrintCallbackList)
        return STATUS_NOT_FOUND;

    ExAcquireSpinLockSharedAtDpcLevel((PEX_SPIN_LOCK)RtlpDebugPrintCallbackLock);
    PLIST_ENTRY pEntry = (PLIST_ENTRY)RtlpDebugPrintCallbackList;
    while (1)
    {
        pEntry = pEntry->Flink;
        if (pEntry == RtlpDebugPrintCallbackList)
            break;

        PDBG_CALLBACK pDbgCallback = (PDBG_CALLBACK)CONTAINING_RECORD(pEntry, DBG_CALLBACK, ListEntry);

        if (ExAcquireRundownProtection(&pDbgCallback->RundownProtection))
        {
            if (callback(pDbgCallback->Callback, ctx))
            {
                ExReleaseRundownProtection(&pDbgCallback->RundownProtection);
                ExReleaseSpinLockSharedFromDpcLevel((PEX_SPIN_LOCK)RtlpDebugPrintCallbackLock);
                return STATUS_SUCCESS;
            }
            ExReleaseRundownProtection(&pDbgCallback->RundownProtection);
        }
    }
    ExReleaseSpinLockSharedFromDpcLevel((PEX_SPIN_LOCK)RtlpDebugPrintCallbackLock);

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
    ULONG CurrentEnumIndex;
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
            EntryInfo->Index = ctx->CurrentEnumIndex;
            ctx->CurrentEnumIndex++;
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
    ctx.CurrentEnumIndex = 0;
    st = EnumPsCreateProcessNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx, 0);

    ctx.CurrentEnumType = KphCallbackPsCreateProcessEx;
    ctx.CurrentEnumIndex = 0;
    st = EnumPsCreateProcessNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx, 2);

    ctx.CurrentEnumType = KphCallbackPsCreateProcessEx2;
    ctx.CurrentEnumIndex = 0;
    st = EnumPsCreateProcessNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx, 6);

    ctx.CurrentEnumType = KphCallbackPsCreateThread;
    ctx.CurrentEnumIndex = 0;
    st = EnumPsCreateThreadNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx, 0);

    ctx.CurrentEnumType = KphCallbackPsCreateThreadExNonSystem;
    ctx.CurrentEnumIndex = 0;
    st = EnumPsCreateThreadNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx, 1);

    ctx.CurrentEnumType = KphCallbackPsCreateThreadExSubSystems;
    ctx.CurrentEnumIndex = 0;
    st = EnumPsCreateThreadNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx, 2);

    ctx.CurrentEnumType = KphCallbackPsLoadImage;
    ctx.CurrentEnumIndex = 0;
    st = EnumPsLoadImageNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx, 0);

    ctx.CurrentEnumType = KphCallbackPsLoadImageEx;
    ctx.CurrentEnumIndex = 0;
    st = EnumPsLoadImageNotifyRoutines(KpiEnumKernelCallback_Enumerator, &ctx, 1);

    ctx.CurrentEnumType = KphCallbackCmRegistry;
    ctx.CurrentEnumIndex = 0;
    st = EnumCmRegistryCallbacks(KpiEnumKernelCallback_Enumerator, &ctx);

    ctx.CurrentEnumType = KphCallbackObProcessPre;
    ctx.CurrentEnumIndex = 0;
    st = EnumProcessObCallbacks(KpiEnumKernelCallback_Enumerator, &ctx, FALSE);

    ctx.CurrentEnumType = KphCallbackObProcessPost;
    ctx.CurrentEnumIndex = 0;
    st = EnumProcessObCallbacks(KpiEnumKernelCallback_Enumerator, &ctx, TRUE);

    ctx.CurrentEnumType = KphCallbackObThreadPre;
    ctx.CurrentEnumIndex = 0;
    st = EnumThreadObCallbacks(KpiEnumKernelCallback_Enumerator, &ctx, FALSE);

    ctx.CurrentEnumType = KphCallbackObThreadPost;
    ctx.CurrentEnumIndex = 0;
    st = EnumThreadObCallbacks(KpiEnumKernelCallback_Enumerator, &ctx, TRUE);

    ctx.CurrentEnumType = KphCallbackDbgPrint;
    ctx.CurrentEnumIndex = 0;
    st = EnumerateDbgCallback(KpiEnumKernelCallback_Enumerator, &ctx);

    if (!NT_SUCCESS(st))
        ctx.Status = st;

    if (MappedAddress != NULL)
        ExUnlockUserBuffer(LockVariable);

    return ctx.Status;
}
