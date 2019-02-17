/*
 * Process Hacker Extended Tools -
 *   ETW disk monitoring
 *
 * Copyright (C) 2011 wj32
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

#include "exttools.h"
#include "etwmon.h"
#include "kphuser.h"

VOID EtpRemoveCallbackItem(
    _In_ PET_CALLBACK_ITEM CallbackItem
);

VOID NTAPI EtpCallbackItemDeleteProcedure(
    _In_ PVOID Object,
    _In_ ULONG Flags
);

BOOLEAN NTAPI EtpCallbackHashtableEqualFunction(
    _In_ PVOID Entry1,
    _In_ PVOID Entry2
);

ULONG NTAPI EtpCallbackHashtableHashFunction(
    _In_ PVOID Entry
);

PPH_OBJECT_TYPE EtCallbackItemType;
PPH_HASHTABLE EtCallbackHashtable;
PH_QUEUED_LOCK EtCallbackHashtableLock = PH_QUEUED_LOCK_INIT;

PH_CALLBACK_DECLARE(EtCallbackItemAddedEvent);
PH_CALLBACK_DECLARE(EtCallbackItemModifiedEvent);
PH_CALLBACK_DECLARE(EtCallbackItemRemovedEvent);
PH_CALLBACK_DECLARE(EtCallbackItemsUpdatedEvent);

PPH_STRING EtGetKernelModuleName(PVOID ImageBase, PRTL_PROCESS_MODULES kernelModules)
{
    for (ULONG i = 0; i < kernelModules->NumberOfModules; ++i)
    {
        if(kernelModules->Modules[i].ImageBase == ImageBase)
            return PhConvertMultiByteToUtf16(kernelModules->Modules[i].FullPathName);
    }

    return NULL;
}

VOID EtGetCallbackInformationInternal(
    PVOID CallbackAddress,
    ULONG Type,
    PVOID ImageBase,
    PRTL_PROCESS_MODULES kernelModules
)
{
    PET_CALLBACK_ITEM  callbackItem;
    WCHAR CallbackAddressString[PH_PTR_STR_LEN_1];
    WCHAR CallbackAddressOffsetString[PH_PTR_STR_LEN_1];

    callbackItem = EtReferenceCallbackItem(CallbackAddress, Type);

    if (!callbackItem)
    {
        // item not found (or the address was re-used), create it.

        callbackItem = EtCreateCallbackItem();

        callbackItem->Alive = TRUE;
        callbackItem->CallbackAddress = CallbackAddress;
        callbackItem->Type = Type;
        callbackItem->ImageBase = ImageBase;
        callbackItem->ImageName = EtGetKernelModuleName(ImageBase, kernelModules);
        if (!callbackItem->ImageName)
        {
            callbackItem->ImageName = PhReferenceEmptyString();
            callbackItem->ImageNameWin32 = PhReferenceEmptyString();
            callbackItem->ImageBaseName = PhReferenceEmptyString();
        }
        else
        {
            callbackItem->ImageNameWin32 = PhGetFileName(callbackItem->ImageName);
            callbackItem->ImageBaseName = PhGetBaseName(callbackItem->ImageName);
        }

        PhPrintPointer(CallbackAddressString, callbackItem->CallbackAddress);
        if (callbackItem->ImageBase)
        {
            PhPrintPointer(CallbackAddressOffsetString, (PVOID)((PUCHAR)callbackItem->CallbackAddress - (PUCHAR)callbackItem->ImageBase));

            callbackItem->CallbackAddressString = PhFormatString(
                L"%s (%s+%s)",
                CallbackAddressString,
                callbackItem->ImageBaseName->Buffer,
                CallbackAddressOffsetString
            );
        }
        else
        {
            callbackItem->CallbackAddressString = PhCreateString(CallbackAddressString);
        }

        // Add the disk item to the hashtable.
        PhAcquireQueuedLockExclusive(&EtCallbackHashtableLock);
        PhAddEntryHashtable(EtCallbackHashtable, &callbackItem);
        PhReleaseQueuedLockExclusive(&EtCallbackHashtableLock);

        // Raise the disk item added event.
        PhInvokeCallback(&EtCallbackItemAddedEvent, callbackItem);
    }
    else
    {
        callbackItem->Alive = TRUE;
    }
}

VOID EtGetCallbackInformationEnumerate(PRTL_PROCESS_MODULES kernelModules)
{
    NTSTATUS st;
    ULONG cbBuffer = 0;
    ULONG cbReturn = 0;
    PVOID pBuffer = NULL;
    PKPH_ENUM_CALLBACK_ENTRY pInfo = NULL;

    static ULONG successBufferSize = 0;

    while (1)
    {
        if (successBufferSize && !cbBuffer)
            cbBuffer = successBufferSize;
        else
            cbBuffer += 0x1000;

        pBuffer = PhAllocate(cbBuffer);

        if (pBuffer == NULL)
        {
            return;
        }

        st = KphEnumKernelCallback(pBuffer, cbBuffer, &cbReturn);

        if (STATUS_SUCCESS == st)
        {
            break;
        }

        PhFree(pBuffer);

        if (STATUS_INFO_LENGTH_MISMATCH != st)//buffer length mismatch
        {
            return;
        }
    }

    if (pBuffer == NULL)
        return;

    if (cbReturn)
    {
        if (cbBuffer > successBufferSize)
            successBufferSize = cbBuffer;

        pInfo = (PKPH_ENUM_CALLBACK_ENTRY)pBuffer;

        while (pInfo)
        {
            if (pInfo->CallbackAddress)
            {
                EtGetCallbackInformationInternal(pInfo->CallbackAddress, pInfo->Type, pInfo->ImageBase, kernelModules);
            }

            if (pInfo->NextEntryOffset == 0)
                break;

            pInfo = (PKPH_ENUM_CALLBACK_ENTRY)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
        }
    }

    PhFree(pBuffer);
}

VOID EtGetCallbackInformation(VOID)
{
    PET_CALLBACK_ITEM callbackItem;
    ULONG enumerationKey;
    PRTL_PROCESS_MODULES kernelModules = NULL;

    PhEnumKernelModules(&kernelModules);

    enumerationKey = 0;
    while (PhEnumHashtable(EtCallbackHashtable, (PVOID *)&callbackItem, &enumerationKey))
    {
        callbackItem->Alive = FALSE;
    }

    EtGetCallbackInformationEnumerate(kernelModules);

    enumerationKey = 0;
    while (PhEnumHashtable(EtCallbackHashtable, (PVOID *)&callbackItem, &enumerationKey))
    {
        if (!callbackItem->Alive)
            EtpRemoveCallbackItem(callbackItem);
    }

    if(kernelModules)
        PhFree(kernelModules);

    PhInvokeCallback(&EtCallbackItemsUpdatedEvent, NULL);
}

VOID EtInitializeCallbackInformation(
    VOID
)
{
    EtCallbackItemType = PhCreateObjectType(L"CallbackItem", 0, EtpCallbackItemDeleteProcedure);
    EtCallbackHashtable = PhCreateHashtable(
        sizeof(PET_CALLBACK_ITEM),
        EtpCallbackHashtableEqualFunction,
        EtpCallbackHashtableHashFunction,
        128
    );

    // Collect all existing callbacks.
    EtGetCallbackInformation();
}

PET_CALLBACK_ITEM EtCreateCallbackItem(
    VOID
)
{
    PET_CALLBACK_ITEM callbackItem;

    callbackItem = PhCreateObject(sizeof(ET_CALLBACK_ITEM), EtCallbackItemType);
    memset(callbackItem, 0, sizeof(ET_CALLBACK_ITEM));

    return callbackItem;
}

VOID NTAPI EtpCallbackItemDeleteProcedure(
    _In_ PVOID Object,
    _In_ ULONG Flags
)
{
    PET_CALLBACK_ITEM callbackItem = Object;

    if (callbackItem->ImageName) PhDereferenceObject(callbackItem->ImageName);
    if (callbackItem->ImageNameWin32) PhDereferenceObject(callbackItem->ImageNameWin32);
    if (callbackItem->ImageBaseName) PhDereferenceObject(callbackItem->ImageBaseName);
    if (callbackItem->CallbackAddressString) PhDereferenceObject(callbackItem->CallbackAddressString);
}

BOOLEAN NTAPI EtpCallbackHashtableEqualFunction(
    _In_ PVOID Entry1,
    _In_ PVOID Entry2
)
{
    PET_CALLBACK_ITEM callbackItem1 = *(PET_CALLBACK_ITEM *)Entry1;
    PET_CALLBACK_ITEM callbackItem2 = *(PET_CALLBACK_ITEM *)Entry2;

    return callbackItem1->CallbackAddress == callbackItem2->CallbackAddress && callbackItem1->Type == callbackItem2->Type;
}

ULONG NTAPI EtpCallbackHashtableHashFunction(
    _In_ PVOID Entry
)
{
    PET_CALLBACK_ITEM callbackItem = *(PET_CALLBACK_ITEM *)Entry;

    return ((ULONG)(ULONG_PTR)callbackItem->CallbackAddress ^ callbackItem->Type);
}

PET_CALLBACK_ITEM EtReferenceCallbackItem(
    _In_ PVOID CallbackAddress,
    _In_ ULONG Type
)
{
    ET_CALLBACK_ITEM lookupCallbackItem;
    PET_CALLBACK_ITEM lookupCallbackItemPtr = &lookupCallbackItem;
    PET_CALLBACK_ITEM *callbackItemPtr;
    PET_CALLBACK_ITEM callbackItem;

    lookupCallbackItem.CallbackAddress = CallbackAddress;
    lookupCallbackItem.Type = Type;

    PhAcquireQueuedLockShared(&EtCallbackHashtableLock);

    callbackItemPtr = (PET_CALLBACK_ITEM *)PhFindEntryHashtable(
        EtCallbackHashtable,
        &lookupCallbackItemPtr
    );

    if (callbackItemPtr)
        PhSetReference(&callbackItem, *callbackItemPtr);
    else
        callbackItem = NULL;

    PhReleaseQueuedLockShared(&EtCallbackHashtableLock);

    return callbackItem;
}

VOID EtpRemoveCallbackItem(
    _In_ PET_CALLBACK_ITEM CallbackItem
)
{
    PhRemoveEntryHashtable(EtCallbackHashtable, &CallbackItem);
    PhDereferenceObject(CallbackItem);
}
