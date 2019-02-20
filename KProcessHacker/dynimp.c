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

#include <stddef.h>
#include "pestructs.h"
#include "detours.h"

PVOID PspCreateProcessNotifyRoutine = NULL;
ULONG PspCreateProcessNotifyRoutineMaxCount = 0;
PVOID PspCreateThreadNotifyRoutine = NULL;
ULONG PspCreateThreadNotifyRoutineMaxCount = 0;
PVOID PspLoadImageNotifyRoutine = NULL;
ULONG PspLoadImageNotifyRoutineMaxCount = 0;
PVOID CmCallbackListHead =NULL;
PKSPIN_LOCK RtlpDebugPrintCallbackLock = NULL;
PLIST_ENTRY RtlpDebugPrintCallbackList = NULL;
MemoryRange_t NtosRange = { 0 };
MemoryRange_t ThisRange = { 0 };

NTSTATUS KphLoadKernelModule(PUNICODE_STRING KernelFileName, LoadModFileCallback callback, void *context);
NTSTATUS KphEnumSystemModules(EnumSystemModuleCallback callback, PVOID Context);
BOOLEAN KphInitGetKernelInfo(PRTL_PROCESS_MODULE_INFORMATION pMod, PVOID checkPtr);
PVOID KphGetProcAddress(PVOID uModBase, CHAR *cSearchFnName);
NTSTATUS KphSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
VOID KphGetPspCreateProcessNotifyRoutine(BOOLEAN IsThreadNotify);
VOID KphGetPspLoadImageNotifyRoutine(VOID);
VOID KphGetCmCallback(VOID);
VOID KphInitFromKernelFile(PVOID Buffer, SIZE_T BufferSize, void *Context);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KphGetSystemRoutineAddress)
#pragma alloc_text(PAGE, KphDynamicImport)
#pragma alloc_text(INIT, KphInitGetKernelInfo)
#pragma alloc_text(PAGE, KphLoadKernelModule)
#pragma alloc_text(PAGE, KphEnumSystemModules)
#pragma alloc_text(PAGE, KphSearchPattern)
#pragma alloc_text(PAGE, KphGetProcAddress)
#pragma alloc_text(INIT, KphGetPspCreateProcessNotifyRoutine)
#pragma alloc_text(INIT, KphGetPspLoadImageNotifyRoutine)
#pragma alloc_text(INIT, KphGetCmCallback)
#pragma alloc_text(INIT, KphInitFromKernelFile)
#endif

/**
 * Dynamically imports routines.
 */
VOID KphDynamicImport(
    VOID
    )
{
    PAGED_CODE();

    UNICODE_STRING KernelFileName = { 0 };

    KphEnumSystemModules(KphInitGetKernelInfo, &KernelFileName);
    KphLoadKernelModule(&KernelFileName, KphInitFromKernelFile, NULL);

    if (KernelFileName.Buffer)
        ExFreePool(KernelFileName.Buffer);

    KphGetPspCreateProcessNotifyRoutine(FALSE);
    KphGetPspCreateProcessNotifyRoutine(TRUE);
    KphGetPspLoadImageNotifyRoutine();
    KphGetCmCallback();
}

NTSTATUS KphSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
    ULONG_PTR i, j;
    if (ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_INVALID_PARAMETER;

    for (i = 0; i < size - len; i++)
    {
        BOOLEAN found = TRUE;
        for (j = 0; j < len; j++)
        {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE)
        {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

/**
 * Retrieves the address of a function exported by NTOS or HAL.
 *
 * \param SystemRoutineName The name of the function.
 *
 * \return The address of the function, or NULL if the function could
 * not be found.
 */
PVOID KphGetSystemRoutineAddress(
    _In_ PWSTR SystemRoutineName
    )
{
    UNICODE_STRING systemRoutineName;

    PAGED_CODE();

    RtlInitUnicodeString(&systemRoutineName, SystemRoutineName);

    return MmGetSystemRoutineAddress(&systemRoutineName);
}

NTSTATUS KphEnumSystemModules(EnumSystemModuleCallback callback, PVOID Context)
{
    ULONG i;
    ULONG cbBuffer = 0;
    PVOID pBuffer = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    while (1)
    {
        cbBuffer += 0x40000;
        pBuffer = ExAllocatePoolWithTag(PagedPool, cbBuffer, 'TXSB');

        if (pBuffer == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = ZwQuerySystemInformation(SystemModuleInformation, pBuffer, cbBuffer, NULL);

        if (NT_SUCCESS(Status))
        {
            break;
        }

        ExFreePoolWithTag(pBuffer, 'TXSB');

        if (Status != STATUS_INFO_LENGTH_MISMATCH)
        {
            return Status;
        }
    }

    if (pBuffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    if (NT_SUCCESS(Status))
    {
        PRTL_PROCESS_MODULES pMods = (PRTL_PROCESS_MODULES)pBuffer;

        for (i = 0; i < pMods->NumberOfModules; i++)
        {
            if (callback(&pMods->Modules[i], Context))
            {
                Status = STATUS_SUCCESS;
                break;
            }
        }
    }

    ExFreePoolWithTag(pBuffer, 'TXSB');

    return Status;
}

PVOID MiFindExportedRoutine2(
    PVOID DllBase,
    PIMAGE_EXPORT_DIRECTORY ExportDirectory,
    ULONG ExportSize,
    BOOLEAN ByName,
    PCHAR RoutineName,
    ULONG Ordinal
)
{

    if (ExportDirectory == NULL || ExportSize == 0)
        return NULL;

    if (!ByName)
    {
        PULONG AddressTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
        return (PVOID)AddressTableBase[Ordinal];
    }

    PULONG NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);
    PUSHORT NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

    LONG High;
    LONG Low;
    LONG Middle;
    LONG Result;

    Low = 0;
    Middle = 0;
    High = ExportDirectory->NumberOfNames - 1;
    while (High >= Low)
    {
        Middle = (Low + High) >> 1;
        Result = strcmp(RoutineName,
            (PCHAR)DllBase + NameTableBase[Middle]);
        if (Result < 0)
        {
            High = Middle - 1;
        }
        else if (Result > 0)
        {
            Low = Middle + 1;
        }
        else
        {
            break;
        }
    }
    if (High < Low)
    {
        return NULL;
    }
    auto OrdinalNumber = NameOrdinalTableBase[Middle];
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
    {
        return NULL;
    }
    PULONG AddrTable = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
    PVOID FunctionAddress = (PVOID)((PCHAR)DllBase + AddrTable[OrdinalNumber]);
    if ((ULONG_PTR)FunctionAddress > (ULONG_PTR)ExportDirectory &&
        (ULONG_PTR)FunctionAddress < ((ULONG_PTR)ExportDirectory + ExportSize))
    {
        FunctionAddress = NULL;
    }
    return FunctionAddress;
}

PVOID KphGetProcAddress(PVOID uModBase, CHAR *cSearchFnName)
{
    IMAGE_DOS_HEADER *doshdr;
#ifdef _WIN64
    IMAGE_OPTIONAL_HEADER64 *opthdr;
#else
    IMAGE_OPTIONAL_HEADER32 *opthdr;
#endif
    IMAGE_EXPORT_DIRECTORY *exptable;
    ULONG size;

    doshdr = (IMAGE_DOS_HEADER *)uModBase;
    if (NULL == doshdr)
        return NULL;
#ifdef _WIN64
    opthdr = (IMAGE_OPTIONAL_HEADER64 *)((PUCHAR)uModBase + doshdr->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
#else
    opthdr = (IMAGE_OPTIONAL_HEADER32 *)((PUCHAR)uModBase + doshdr->e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER));
#endif
    if (NULL == opthdr)
        return NULL;

    exptable = (IMAGE_EXPORT_DIRECTORY *)((PUCHAR)uModBase + opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (NULL == exptable)
        return NULL;

    size = opthdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    return MiFindExportedRoutine2(uModBase, exptable, size, TRUE, cSearchFnName, 0);
}

NTSTATUS KphLoadKernelModule(PUNICODE_STRING KernelFileName, LoadModFileCallback callback, void *context)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE FileHandle = NULL, SectionHandle = NULL;
    PVOID SectionBase = NULL;
    SIZE_T SectionSize = 0;

    if (!KernelFileName->Buffer)
        return STATUS_OBJECT_NAME_INVALID;

    InitializeObjectAttributes(&oa, KernelFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    NTSTATUS st = ZwOpenFile(&FileHandle, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (st == STATUS_SHARING_VIOLATION)
        st = ZwOpenFile(&FileHandle, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (NT_SUCCESS(st))
    {
        oa.ObjectName = 0;
        st = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &oa, 0, PAGE_READONLY, MEM_IMAGE, FileHandle);
        if (NT_SUCCESS(st))
        {
            st = ZwMapViewOfSection(SectionHandle, NtCurrentProcess(), &SectionBase, 0, 0, 0, &SectionSize, ViewShare, MEM_TOP_DOWN, PAGE_READONLY);
            if (NT_SUCCESS(st))
            {
                callback(SectionBase, SectionSize, context);
                ZwUnmapViewOfSection(NtCurrentProcess(), SectionBase);
            }
            else
            {
                dprintf("map kernel section failed with %08X.", st);
                return st;
            }
            ZwClose(SectionHandle);
        }
        else
        {
            dprintf("open kernel section failed with %08X.", st);
            return st;
        }
        ZwClose(FileHandle);
    }
    else
    {
        dprintf("open kernel file failed with %08X.",st);
        return st;
    }
    return STATUS_SUCCESS;
}

BOOLEAN KphInitGetKernelInfo(PRTL_PROCESS_MODULE_INFORMATION pMod, PVOID context)
{
    PUNICODE_STRING KernelFileName = (PUNICODE_STRING)context;

    if (!NtosRange.Base)
    {
        if (pMod->LoadOrderIndex == 0)
        {
            NtosRange.Base = pMod->ImageBase;
            NtosRange.End = (PUCHAR)pMod->ImageBase + pMod->ImageSize;

            ANSI_STRING astrKernelName = { 0 };
            UNICODE_STRING ustrKernelName = { 0 };
            RtlInitAnsiString(&astrKernelName, (PCHAR)(pMod->FullPathName + pMod->OffsetToFileName));

            KernelFileName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, 260 * sizeof(WCHAR), 'TXSB');
            if (KernelFileName->Buffer)
            {
                KernelFileName->Length = 0;
                KernelFileName->MaximumLength = 260 * sizeof(WCHAR);

                RtlInitUnicodeString(&ustrKernelName, L"\\SystemRoot\\System32\\");
                RtlCopyUnicodeString(KernelFileName, &ustrKernelName);

                ustrKernelName.Buffer = (PWCH)((PUCHAR)KernelFileName->Buffer + KernelFileName->Length);
                ustrKernelName.Length = 0;
                ustrKernelName.MaximumLength = KernelFileName->MaximumLength - KernelFileName->Length;

                RtlAnsiStringToUnicodeString(&ustrKernelName, &astrKernelName, FALSE);
                KernelFileName->Length += ustrKernelName.Length;
            }

            return FALSE;
        }
    }

    if (!ThisRange.Base)
    {
        PVOID checkPtr2 = KphInitGetKernelInfo;
        if (checkPtr2 >= pMod->ImageBase &&
            checkPtr2 < (PVOID)((PUCHAR)pMod->ImageBase + pMod->ImageSize))
        {
            ThisRange.Base = pMod->ImageBase;
            ThisRange.End = (PUCHAR)pMod->ImageBase + pMod->ImageSize;
            return FALSE;
        }
    }

    return FALSE;
}

typedef struct
{
    int IncValue[4];
    int IncReg[4];
    int IncCount;
    ULONG MaxCount;
}GetRoutineMaxCount_Context;

typedef struct
{
    int Mov_InstCount;
    int Call_InstCount;
    GetRoutineMaxCount_Context RoutineMaxCount;
}KphGetPspLoadImageNotifyRoutine_Context;

typedef struct
{
    PVOID PspSet;
    PVOID PspRoutine;
    PVOID Candidate_CallTarget;
    int FuncEnd_InstCount;
    int Mov_InstCount;
    int Call_InstCount;
    PVOID Candidate_Mov_Mem;
    GetRoutineMaxCount_Context RoutineMaxCount;
}KphGetPspCreateProcessNotifyRoutine_Context;

BOOLEAN FindRoutineMaxCount_Callback(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context)
{
    GetRoutineMaxCount_Context * ctx = (GetRoutineMaxCount_Context *)context;

    if (inst->id == X86_INS_ADD)
    {
        if (inst->detail->x86.op_count == 2)
        {
            if (inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_IMM
                && IsCommonRegister(inst->detail->x86.operands[0].reg))
            {
                if (ctx->IncCount < 4)
                {
                    ctx->IncValue[ctx->IncCount] = (int)inst->detail->x86.operands[1].imm;
                    ctx->IncReg[ctx->IncCount] = inst->detail->x86.operands[0].reg;
                    ctx->IncCount++;
                }
            }
            else if (inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_REG
                && IsCommonRegister(inst->detail->x86.operands[0].reg))
            {
                if (ctx->IncCount < 4)
                {
                    ctx->IncValue[ctx->IncCount] = 1;
                    ctx->IncReg[ctx->IncCount] = inst->detail->x86.operands[0].reg;
                    ctx->IncCount++;
                }
            }
        }
    }
    else if (inst->id == X86_INS_INC)
    {
        if (inst->detail->x86.op_count == 1 && inst->detail->x86.operands[0].type == X86_OP_REG
            && IsCommonRegister(inst->detail->x86.operands[0].reg))
        {
            if (ctx->IncCount < 4)
            {
                ctx->IncValue[ctx->IncCount] = 1;
                ctx->IncReg[ctx->IncCount] = inst->detail->x86.operands[0].reg;
                ctx->IncCount++;
            }
        }
    }

    if (ctx->IncCount)
    {
        if (inst->id == X86_INS_CMP && inst->detail->x86.op_count == 2)
        {
            if (inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_IMM
                && IsCommonRegister(inst->detail->x86.operands[0].reg))
            {
                for (int i = 0; i < ctx->IncCount; ctx->IncCount++)
                {
                    if (inst->detail->x86.operands[0].reg == ctx->IncReg[i] && ctx->IncValue[i] > 0)
                    {
                        ctx->MaxCount = (ULONG)(inst->detail->x86.operands[1].imm / ctx->IncValue[i]);
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

BOOLEAN KphGetPspLoadImageNotifyRoutine_Callback(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context)
{
    KphGetPspLoadImageNotifyRoutine_Context * ctx = (KphGetPspLoadImageNotifyRoutine_Context *)context;

    if (!PspLoadImageNotifyRoutine)
    {
#ifdef _WIN64
        //48 8D ?? ?? ?? ?? ?? lea rcx/rsi,_PspLoadImageNotifyRoutine
        if (inst->id == X86_INS_LEA && inst->detail->x86.op_count == 2 &&
            inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_MEM
            && IsCommonRegister(inst->detail->x86.operands[0].reg) && inst->detail->x86.operands[1].mem.base == X86_REG_RIP)
        {
            PspLoadImageNotifyRoutine = (PVOID)(pAddress + instLen + (int)inst->detail->x86.operands[1].mem.disp);
            ctx->Mov_InstCount = instCount;
        }
#else
        //XX ?? ?? ?? ??	mov ebx/esi/edi/eax/ecx/edx, offset _PspLoadImageNotifyRoutine
        if (inst->id == X86_INS_MOV && inst->detail->x86.op_count == 2 && inst->detail->x86.operands[1].type == X86_OP_IMM &&
            ((inst->detail->x86.operands[0].type == X86_OP_REG && IsCommonRegister(inst->detail->x86.operands[0].reg)) ||
            (inst->detail->x86.operands[0].type == X86_OP_MEM && IsStackRegister((x86_reg)inst->detail->x86.operands[0].mem.base)))
            )
        {
            PVOID imm = (PVOID)(ULONG_PTR)inst->detail->x86.operands[1].imm;
            //avoid B8 9A 00 00 C0                                      mov     eax, 0C000009Ah
            if (IsInMemoryRange(imm, &NtosRange))
            {
                PspLoadImageNotifyRoutine = imm;
                ctx->Mov_InstCount = instCount;
            }
        }
#endif
    }
    //E8 ?? ?? ?? ??                                      call    _ExCompareExchangeCallBack@1
    if (ctx->Mov_InstCount && instCount - ctx->Mov_InstCount < 10 && !ctx->Call_InstCount &&
        instLen == 5 && pAddress[0] == 0xE8)
    {
        ctx->Call_InstCount = instCount;
    }

    if (!ctx->RoutineMaxCount.MaxCount && ctx->Call_InstCount && instCount - ctx->Call_InstCount < 12)
    {
        FindRoutineMaxCount_Callback(inst, pAddress, instLen, instCount, &ctx->RoutineMaxCount);
        if (!ctx->RoutineMaxCount.MaxCount)
        {
            //0F 84 ?? ?? ?? ??                                   jz
            //0F 85 ?? ?? ?? ??                                   jnz
            //74 ??                                               jz      short
            //75 ??                                               jnz     short
            if ((inst->id == X86_INS_JE || inst->id == X86_INS_JNE) &&
                inst->detail->x86.op_count == 1 && inst->detail->x86.operands[0].type == X86_OP_IMM)
            {
                PVOID imm = (PVOID)inst->detail->x86.operands[0].imm;

                if (MmIsAddressValid(imm) && IsInMemoryRange(imm, &NtosRange))
                {
                    GetRoutineMaxCount_Context ctx2;
                    for (int i = 0; i < 4; ++i)
                    {
                        ctx2.IncValue[i] = 0;
                        ctx2.IncReg[i] = 0;
                    }
                    ctx2.IncCount = 0;
                    ctx2.MaxCount = 0;
                    DisasmRanges(imm, 50, FindRoutineMaxCount_Callback, &ctx2);

                    if (ctx2.MaxCount)
                        PspLoadImageNotifyRoutineMaxCount = ctx2.MaxCount;
                }
            }
        }
    }

    return (PspLoadImageNotifyRoutine && PspLoadImageNotifyRoutineMaxCount);
}

VOID KphGetPspLoadImageNotifyRoutine(VOID)
{
    PUCHAR pAddress = (PUCHAR)KphGetSystemRoutineAddress(L"PsSetLoadImageNotifyRoutine");

    PVOID pfnPsSetLoadImageNotifyRoutineEx = KphGetSystemRoutineAddress(L"PsSetLoadImageNotifyRoutineEx");
    if (pfnPsSetLoadImageNotifyRoutineEx)
        pAddress = (PUCHAR)pfnPsSetLoadImageNotifyRoutineEx;

    KphGetPspLoadImageNotifyRoutine_Context ctx;
    ctx.Mov_InstCount = 0;
    ctx.Call_InstCount = 0;
    for (int i = 0; i < 4; ++i)
    {
        ctx.RoutineMaxCount.IncValue[i] = 0;
        ctx.RoutineMaxCount.IncReg[i] = 0;
    }
    ctx.RoutineMaxCount.IncCount = 0;
    ctx.RoutineMaxCount.MaxCount = 0;

    DisasmRanges(pAddress, 0x150, KphGetPspLoadImageNotifyRoutine_Callback, &ctx);

    if (!PspLoadImageNotifyRoutine)
    {
        dprintf("PspLoadImageNotifyRoutine not found\n");
        return;
    }

    if (!PspLoadImageNotifyRoutineMaxCount)
    {
        dprintf("PspLoadImageNotifyRoutineMaxCount not found\n");
        return;
    }

    dprintf("PspLoadImageNotifyRoutine %p\n", PspLoadImageNotifyRoutine);
    dprintf("PspLoadImageNotifyRoutineMaxCount %d\n", PspLoadImageNotifyRoutineMaxCount);
}

BOOLEAN KphGetPspCreateProcessNotifyRoutine_FirstStage(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context)
{
    //HYPERPLATFORM_LOG_INFO_SAFE("opcode0 %p, %d %d %02X %02X %02X %02X %02X", pAddress, instCount, instLen, inst->bytes[0], inst->bytes[1], inst->bytes[2], inst->bytes[3], inst->bytes[4]);

    KphGetPspCreateProcessNotifyRoutine_Context * ctx = (KphGetPspCreateProcessNotifyRoutine_Context *)context;
    if (instLen == 1 && (pAddress[0] == 0xCC || pAddress[0] == 0x90))
    {
        ctx->FuncEnd_InstCount = instCount;
        return TRUE;
    }
    if (inst->id == X86_INS_RET)
    {
        ctx->FuncEnd_InstCount = instCount;
        return TRUE;
    }
    if (instLen == 5 && pAddress[0] == 0xE9)//jmp
    {
        //HYPERPLATFORM_LOG_INFO_SAFE("jmp found");

        ctx->PspSet = (PVOID)(pAddress + instLen + *(int *)(pAddress + 1));
        return TRUE;
    }
    else if (!ctx->Candidate_CallTarget && instLen == 5 && pAddress[0] == 0xE8)//call
    {
        ctx->Candidate_CallTarget = (PVOID)(pAddress + 5 + *(int *)(pAddress + 1));
    }

    return FALSE;
}

BOOLEAN KphGetPspCreateProcessNotifyRoutine_SecondStage(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context)
{
    KphGetPspCreateProcessNotifyRoutine_Context * ctx = (KphGetPspCreateProcessNotifyRoutine_Context *)context;
    //dprintf("opcode %p, %d %d %02X %02X %02X %02X %02X\n", pAddress, instCount, instLen, inst->bytes[0], inst->bytes[1], inst->bytes[2], inst->bytes[3], inst->bytes[4]);

    if (!ctx->PspRoutine)
    {
#ifdef _WIN64
        //4C 8D 25 04 1C DE FF                                lea     r12, PspCreateProcessNotifyRoutine
        //4C 8D 2D 5C F5 E5 FF                                lea     r13, PspCreateProcessNotifyRoutine
        //4C 8D 35 C3 DB D6 FF                                lea     r14, PspCreateProcessNotifyRoutine
        //4C 8D 3D A1 C4 DF FF                                lea     r15, PspCreateProcessNotifyRoutine
        //4C 8D 0D A1 C4 DF FF                                lea     rcx, PspCreateProcessNotifyRoutine
        if (inst->id == X86_INS_LEA && inst->detail->x86.op_count == 2 &&
            inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_MEM
            && inst->detail->x86.operands[1].mem.base == X86_REG_RIP && IsCommonRegister(inst->detail->x86.operands[0].reg))
        {
            ctx->PspRoutine = (PVOID)(pAddress + instLen + (int)inst->detail->x86.operands[1].mem.disp);
            ctx->Mov_InstCount = instCount;
        }
#else
        //XX ?? ?? ?? ??									mov ebx/esi/edi/eax/ecx/edx, offset _PspCreateProcessNotifyRoutine
        //C7 45 0C ?? ?? ?? ??                              mov     [ebp+arg_4], offset _PspCreateProcessNotifyRoutine
        if (!ctx->Candidate_Mov_Mem)
        {
            if (inst->id == X86_INS_MOV &&
                inst->detail->x86.op_count == 2 && inst->detail->x86.operands[1].type == X86_OP_IMM &&
                ((inst->detail->x86.operands[0].type == X86_OP_REG && IsCommonRegister(inst->detail->x86.operands[0].reg)) ||
                (inst->detail->x86.operands[0].type == X86_OP_MEM && IsStackRegister((x86_reg)inst->detail->x86.operands[0].mem.base)))
                )
            {
                PVOID imm = (PVOID)(ULONG_PTR)inst->detail->x86.operands[1].imm;
                if (IsInMemoryRange(imm, &NtosRange))
                {
                    ctx->Candidate_Mov_Mem = imm;
                    ctx->Mov_InstCount = instCount;
                }
            }
        }

#endif
    }

    //E8 ?? ?? ?? ??                                      call    _ExCompareExchangeCallBack@1
    if (ctx->Mov_InstCount && instCount - ctx->Mov_InstCount < 10 && !ctx->Call_InstCount &&
        instLen == 5 && pAddress[0] == 0xE8)
    {
#ifndef _WIN64
        if (!ctx->PspRoutine && ctx->Candidate_Mov_Mem)
            ctx->PspRoutine = ctx->Candidate_Mov_Mem;
#endif

        //HYPERPLATFORM_LOG_INFO_SAFE("call found");
        ctx->Call_InstCount = instCount;
    }

    if (!ctx->RoutineMaxCount.MaxCount && ctx->Call_InstCount && instCount - ctx->Call_InstCount < 12)
    {
        FindRoutineMaxCount_Callback(inst, pAddress, instLen, instCount, &ctx->RoutineMaxCount);
        if (!ctx->RoutineMaxCount.MaxCount)
        {
            //0F 84 ?? ?? ?? ??                                   jz
            //0F 85 ?? ?? ?? ??                                   jnz
            //74 ??                                               jz      short
            //75 ??                                               jnz     short
            if ((inst->id == X86_INS_JE || inst->id == X86_INS_JNE) &&
                inst->detail->x86.op_count == 1 && inst->detail->x86.operands[0].type == X86_OP_IMM)
            {
                PVOID imm = (PVOID)inst->detail->x86.operands[0].imm;

                if (MmIsAddressValid(imm) && IsInMemoryRange(imm, &NtosRange))
                {
                    GetRoutineMaxCount_Context ctx2;
                    for (int i = 0; i < 4; ++i)
                    {
                        ctx2.IncValue[i] = 0;
                        ctx2.IncReg[i] = 0;
                    }
                    ctx2.IncCount = 0;
                    ctx2.MaxCount = 0;
                    DisasmRanges(imm, 50, FindRoutineMaxCount_Callback, &ctx2);

                    if (ctx2.MaxCount)
                        ctx->RoutineMaxCount.MaxCount = ctx2.MaxCount;
                }
            }
        }
    }

    return (ctx->PspRoutine && ctx->RoutineMaxCount.MaxCount);
}

VOID KphGetPspCreateProcessNotifyRoutine(BOOLEAN IsThreadNotify)
{
    KphGetPspCreateProcessNotifyRoutine_Context ctx;

    PVOID PsSet, PsSetEx;
    if (!IsThreadNotify)
    {
        PsSet = KphGetSystemRoutineAddress(L"PsSetCreateProcessNotifyRoutine");
        PsSetEx = KphGetSystemRoutineAddress(L"PsSetCreateProcessNotifyRoutineEx");
    }
    else
    {
        PsSet = KphGetSystemRoutineAddress(L"PsSetCreateThreadNotifyRoutine");
        PsSetEx = KphGetSystemRoutineAddress(L"PsSetCreateThreadNotifyRoutineEx");
    }

    ctx.PspSet = NULL;
    ctx.PspRoutine = NULL;
    ctx.Candidate_CallTarget = NULL;
    ctx.FuncEnd_InstCount = 0;
    ctx.Mov_InstCount = 0;
    ctx.Call_InstCount = 0;
    ctx.Candidate_Mov_Mem = NULL;
    for (int i = 0; i < 4; ++i)
    {
        ctx.RoutineMaxCount.IncValue[i] = 0;
        ctx.RoutineMaxCount.IncReg[i] = 0;
    }
    ctx.RoutineMaxCount.IncCount = 0;
    ctx.RoutineMaxCount.MaxCount = 0;

    if (PsSetEx)
    {
        DisasmRanges(PsSet, 100, KphGetPspCreateProcessNotifyRoutine_FirstStage, &ctx);

        if (!ctx.PspSet && ctx.Candidate_CallTarget && ctx.FuncEnd_InstCount && ctx.FuncEnd_InstCount <= 12)
            ctx.PspSet = ctx.Candidate_CallTarget;
    }

    if (!ctx.PspSet)
        ctx.PspSet = PsSet;

    DisasmRanges(ctx.PspSet, 0x150, KphGetPspCreateProcessNotifyRoutine_SecondStage, &ctx);

    if (!IsThreadNotify)
    {
        PspCreateProcessNotifyRoutine = ctx.PspRoutine;
        PspCreateProcessNotifyRoutineMaxCount = ctx.RoutineMaxCount.MaxCount;
        if (!PspCreateProcessNotifyRoutine)
        {
            dprintf("PspCreateProcessNotifyRoutine not found\n");
            return;
        }

        if (!PspCreateProcessNotifyRoutineMaxCount)
        {
            dprintf("PspCreateProcessNotifyRoutineMaxCount not found\n");
            return;
        }
        dprintf("PspCreateProcessNotifyRoutine %p\n", PspCreateProcessNotifyRoutine);
        dprintf("PspCreateProcessNotifyRoutineMaxCount %d\n", PspCreateProcessNotifyRoutineMaxCount);
    }
    else
    {
        PspCreateThreadNotifyRoutine = ctx.PspRoutine;
        PspCreateThreadNotifyRoutineMaxCount = ctx.RoutineMaxCount.MaxCount;
        if (!PspCreateThreadNotifyRoutine)
        {
            dprintf("PspCreateThreadNotifyRoutine not found\n");
            return;
        }

        if (!PspCreateThreadNotifyRoutineMaxCount)
        {
            dprintf("PspCreateThreadNotifyRoutineMaxCount not found\n");
            return;
        }
        dprintf("PspCreateThreadNotifyRoutine %p\n", PspCreateThreadNotifyRoutine);
        dprintf("PspCreateThreadNotifyRoutineMaxCount %d\n", PspCreateThreadNotifyRoutineMaxCount);
    }    
}

typedef struct
{
#ifdef _WIN64
    int Lea_Rcx_InstCount;
    PVOID Lea_Rcx_Candidate;
#else
    int Mov_Exi_InstCount;
    PVOID Mov_Exi_Candidate;
#endif
    int Call_GetNext_InstCount;
}KphGetCmCallbackNT6_Context;

BOOLEAN KphGetCmCallback_CheckCmListGetNextElement(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context)
{
    //HYPERPLATFORM_LOG_INFO_SAFE("walk %p, %d %d %02X %02X %02X %02X %02X", pAddress, instCount, instLen, inst->bytes[0], inst->bytes[1], inst->bytes[2], inst->bytes[3], inst->bytes[4]);
#ifdef _WIN64
    //48 83 3A 00                                         cmp     qword ptr [rdx], 0
    if (inst->id == X86_INS_CMP && inst->detail->x86.op_count == 2
        && inst->detail->x86.operands[0].type == X86_OP_MEM && inst->detail->x86.operands[1].type == X86_OP_IMM && inst->detail->x86.operands[0].size == 8
        && (x86_reg)inst->detail->x86.operands[0].mem.base == X86_REG_RDX && inst->detail->x86.operands[1].imm == 0)
    {
        //HYPERPLATFORM_LOG_INFO_SAFE("CmListGetNextElement detected");
        return TRUE;
    }
    //49 63 C8                                            movsxd  rcx, r8d
    if (!memcmp(pAddress, "\x49\x63\xC8", 3))
    {
        return TRUE;
    }
#else
    //83 39 00                                            cmp     dword ptr [ecx], 0
    if (inst->id == X86_INS_CMP && inst->detail->x86.op_count == 2
        && inst->detail->x86.operands[0].type == X86_OP_MEM && inst->detail->x86.operands[1].type == X86_OP_IMM && inst->detail->x86.operands[0].size == 4
        && IsCommonRegister((x86_reg)inst->detail->x86.operands[0].mem.base) && inst->detail->x86.operands[1].imm == 0)
    {
        //HYPERPLATFORM_LOG_INFO_SAFE("CmListGetNextElement detected");
        return TRUE;
    }

#endif
    return FALSE;
}

BOOLEAN KphGetCmCallback_FindNT6(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context)
{
    //HYPERPLATFORM_LOG_INFO_SAFE("KphGetCmCallback_FindNT6 %p, %d %d %02X %02X %02X %02X %02X", pAddress, instCount, instLen, inst->bytes[0], inst->bytes[1], inst->bytes[2], inst->bytes[3], inst->bytes[4]);

    KphGetCmCallbackNT6_Context * ctx = (KphGetCmCallbackNT6_Context *)context;

#ifdef _WIN64
    //48 8D 0D B3 27 D2 FF                                lea     rcx, CallbackListHead
    if (inst->id == X86_INS_LEA && inst->detail->x86.op_count == 2
        && inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_MEM
        && inst->detail->x86.operands[0].reg == X86_REG_RCX && (x86_reg)inst->detail->x86.operands[1].mem.base == X86_REG_RIP)
    {
        PVOID imm = (PVOID)(pAddress + instLen + (int)inst->detail->x86.operands[1].mem.disp);
        if (IsInMemoryRange(imm, &NtosRange))
        {
            //HYPERPLATFORM_LOG_INFO_SAFE("lea found");

            ctx->Lea_Rcx_InstCount = instCount;
            ctx->Lea_Rcx_Candidate = imm;
            return FALSE;
        }
    }

    //E8 A2 61 E5 FF                                      call    CmListGetNextElement
    if (!ctx->Call_GetNext_InstCount && ctx->Lea_Rcx_InstCount
        && instCount - ctx->Lea_Rcx_InstCount < 10 &&
        instLen == 5 && pAddress[0] == 0xE8)
    {
        PVOID CallTarget = (PVOID)(pAddress + 5 + *(int *)(pAddress + 1));;
        if (IsInMemoryRange(CallTarget, &NtosRange))
        {
            if (DisasmRanges(CallTarget, 30, KphGetCmCallback_CheckCmListGetNextElement, NULL))
            {
                //HYPERPLATFORM_LOG_INFO_SAFE("call found");

                ctx->Call_GetNext_InstCount = instCount;
                CmCallbackListHead = ctx->Lea_Rcx_Candidate;
                //stop searching
                return TRUE;
            }
            else
            {
                ctx->Lea_Rcx_InstCount = 0;
                ctx->Lea_Rcx_Candidate = 0;
            }
        }
    }
#else
    //BE F0 B2 52 00                                      mov     esi, offset _CallbackListHead
    //B9 40 CF 60 00                                      mov     ecx, offset _CallbackListHead
    //BF D0 E1 55 00                                      mov     edi, offset _CallbackListHead
    if (inst->id == X86_INS_MOV && inst->detail->x86.op_count == 2
        && inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_IMM
        && IsCommonRegister(inst->detail->x86.operands[0].reg))
    {
        PVOID imm = (PVOID)(ULONG_PTR)inst->detail->x86.operands[1].imm;
        if (IsInMemoryRange(imm, &NtosRange))
        {
            //HYPERPLATFORM_LOG_INFO("mov found");
            ctx->Mov_Exi_InstCount = instCount;
            ctx->Mov_Exi_Candidate = imm;
            return FALSE;
        }
    }

    //E8 08 0B F4 FF                                      call    _CmListGetNextElement@12
    if (!ctx->Call_GetNext_InstCount && ctx->Mov_Exi_InstCount
        && instCount - ctx->Mov_Exi_InstCount < 15 &&
        instLen == 5 && pAddress[0] == 0xE8)
    {
        PVOID CallTarget = (PVOID)(pAddress + 5 + *(int *)(pAddress + 1));;
        if (IsInMemoryRange(CallTarget, &NtosRange))
        {
            //HYPERPLATFORM_LOG_INFO("call found");
            if (DisasmRanges(CallTarget, 30, KphGetCmCallback_CheckCmListGetNextElement, NULL))
            {
                ctx->Call_GetNext_InstCount = instCount;
                CmCallbackListHead = ctx->Mov_Exi_Candidate;
                //stop searching
                return TRUE;
            }
            else
            {
                ctx->Mov_Exi_InstCount = 0;
                ctx->Mov_Exi_Candidate = 0;
            }
        }
    }

#endif

    if (inst->id == X86_INS_RET)
    {
        //HYPERPLATFORM_LOG_INFO_SAFE("walk ret");
        return TRUE;
    }

    if (instLen == 1 && (inst->bytes[0] == 0xCC || inst->bytes[0] == 0x90))
    {
        //HYPERPLATFORM_LOG_INFO_SAFE("walk cc 90");
        return TRUE;
    }

    return FALSE;
}

VOID KphGetCmCallback(VOID)
{
    PUCHAR CmUnReg = (PUCHAR)KphGetSystemRoutineAddress(L"CmUnRegisterCallback");

    if (!CmUnReg)
        return;

    if (KphDynOsVersionInfo.dwBuildNumber >= 6000)
    {
        KphGetCmCallbackNT6_Context ctx;
#ifdef _WIN64
        ctx.Lea_Rcx_InstCount = 0;
        ctx.Lea_Rcx_Candidate = NULL;
#else
        ctx.Mov_Exi_InstCount = 0;
        ctx.Mov_Exi_Candidate = NULL;
#endif
        ctx.Call_GetNext_InstCount = 0;

        DisasmRanges(CmUnReg, 0x100, KphGetCmCallback_FindNT6, &ctx);

        if (!CmCallbackListHead)
        {
            dprintf("CmCallbackListHead not found\n");
            return;
        }

        dprintf("CmCallbackListHead %p\n", CmCallbackListHead);
    }
}

typedef struct
{
#ifdef _WIN64
    int Lea_Rcx_InstCount;
    PVOID Lea_Rcx_Candidate;
#else
    int Mov_Exi_InstCount;
    PVOID Mov_Exi_Candidate;
#endif
    int Call_GetNext_InstCount;
    PVOID ExAcq;
}KphGetDebugPrintCallback_Context;

BOOLEAN KphGetDebugPrintCallback(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context)
{
    KphGetDebugPrintCallback_Context *ctx = (KphGetDebugPrintCallback_Context *)context;

#ifdef _WIN64
    //48 8D 0D B3 27 D2 FF                                lea     rcx, CallbackListHead
    if (inst->id == X86_INS_LEA && inst->detail->x86.op_count == 2
        && inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_MEM
        && inst->detail->x86.operands[0].reg == X86_REG_RCX && (x86_reg)inst->detail->x86.operands[1].mem.base == X86_REG_RIP)
    {
        PVOID imm = (PVOID)(pAddress + instLen + (int)inst->detail->x86.operands[1].mem.disp);
        
        if (!RtlpDebugPrintCallbackLock)
        {
            ctx->Lea_Rcx_InstCount = instCount;
            ctx->Lea_Rcx_Candidate = imm;
            return FALSE;
        }
        else if (instCount > ctx->Call_GetNext_InstCount && instCount < ctx->Call_GetNext_InstCount + 8)
        {
            RtlpDebugPrintCallbackList = imm;
            return TRUE;
        }
    }

    //E8 A2 61 E5 FF                                      call    ExAcq
    if (!RtlpDebugPrintCallbackLock &&
        !ctx->Call_GetNext_InstCount && ctx->Lea_Rcx_InstCount
        && instCount - ctx->Lea_Rcx_InstCount < 10 &&
        instLen == 5 && pAddress[0] == 0xE8)
    {
        PVOID CallTarget = (PVOID)(pAddress + 5 + *(int *)(pAddress + 1));
        if (CallTarget == ctx->ExAcq)
        {
            ctx->Call_GetNext_InstCount = instCount;
            RtlpDebugPrintCallbackLock = ctx->Lea_Rcx_Candidate;
            return FALSE;
        }
    }
#else
    //BE F0 B2 52 00                                      mov     esi, offset _CallbackListHead
    //B9 40 CF 60 00                                      mov     ecx, offset _CallbackListHead
    //BF D0 E1 55 00                                      mov     edi, offset _CallbackListHead
    if (inst->id == X86_INS_MOV && inst->detail->x86.op_count == 2
        && inst->detail->x86.operands[0].type == X86_OP_REG && inst->detail->x86.operands[1].type == X86_OP_IMM
        && IsCommonRegister(inst->detail->x86.operands[0].reg))
    {
        PVOID imm = (PVOID)(ULONG_PTR)inst->detail->x86.operands[1].imm;
        ctx->Mov_Exi_InstCount = instCount;
        ctx->Mov_Exi_Candidate = imm;
        return FALSE;
    }

    //E8 08 0B F4 FF                                      call    _CmListGetNextElement@12
    if (!ctx->Call_GetNext_InstCount && ctx->Mov_Exi_InstCount
        && instCount - ctx->Mov_Exi_InstCount < 15 &&
        instLen == 5 && pAddress[0] == 0xE8)
    {
        PVOID CallTarget = (PVOID)(pAddress + 5 + *(int *)(pAddress + 1));;
        if (IsInMemoryRange(CallTarget, &NtosRange))
        {
            //HYPERPLATFORM_LOG_INFO("call found");
            if (DisasmRanges(CallTarget, 30, KphGetCmCallback_CheckCmListGetNextElement, NULL))
            {
                ctx->Call_GetNext_InstCount = instCount;
                CmCallbackListHead = ctx->Mov_Exi_Candidate;
                //stop searching
                return TRUE;
            }
            else
            {
                ctx->Mov_Exi_InstCount = 0;
                ctx->Mov_Exi_Candidate = 0;
            }
        }
    }

#endif

    if (inst->id == X86_INS_RET)
    {
        //HYPERPLATFORM_LOG_INFO_SAFE("walk ret");
        return TRUE;
    }

    if (instLen == 1 && (inst->bytes[0] == 0xCC || inst->bytes[0] == 0x90))
    {
        //HYPERPLATFORM_LOG_INFO_SAFE("walk cc 90");
        return TRUE;
    }

    return FALSE;
}

VOID KphInitFromKernelFile(PVOID Buffer, SIZE_T BufferSize, void *Context)
{
    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)Buffer;
    PIMAGE_NT_HEADERS ntheader = (PIMAGE_NT_HEADERS)((PUCHAR)Buffer + dosheader->e_lfanew);
    PIMAGE_SECTION_HEADER secheader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

    PUCHAR PAGEBase = NULL;
    SIZE_T PAGESize = 0;
    PUCHAR TEXTBase = NULL;
    SIZE_T TEXTSize = 0;
    PUCHAR INITBase = NULL;
    SIZE_T INITSize = 0;
    PUCHAR KVASBase = NULL;
    SIZE_T KVASSize = 0;

    for (auto i = 0; i < ntheader->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(secheader[i].Name, "PAGE\x0\x0\x0\x0", 8) == 0)
        {
            PAGEBase = (PUCHAR)Buffer + secheader[i].VirtualAddress;
            PAGESize = max(secheader[i].SizeOfRawData, secheader[i].Misc.VirtualSize);
        }
        else if (memcmp(secheader[i].Name, ".text\x0\x0\x0", 8) == 0)
        {
            TEXTBase = (PUCHAR)Buffer + secheader[i].VirtualAddress;
            TEXTSize = max(secheader[i].SizeOfRawData, secheader[i].Misc.VirtualSize);
        }
        else if (memcmp(secheader[i].Name, "KVASCODE", 8) == 0)
        {
            KVASBase = (PUCHAR)Buffer + secheader[i].VirtualAddress;
            KVASSize = max(secheader[i].SizeOfRawData, secheader[i].Misc.VirtualSize);
        }
        else if (memcmp(secheader[i].Name, "INIT\x0\x0\x0\x0", 8) == 0)
        {
            INITBase = (PUCHAR)Buffer + secheader[i].VirtualAddress;
            INITSize = max(secheader[i].SizeOfRawData, secheader[i].Misc.VirtualSize);
        }
    }

    if (INITBase)
    {
  
    }

    if (TEXTBase)
    {
        UCHAR pattern[] = "\x41\xB8\x44\x62\x43\x62\xE8";
        PVOID pFound = NULL;
        NTSTATUS st = KphSearchPattern(pattern, 0x2A, sizeof(pattern) - 1, TEXTBase, TEXTSize, &pFound);
        if (NT_SUCCESS(st)) {
            KphGetDebugPrintCallback_Context ctx;
            ctx.ExAcq = KphGetProcAddress(Buffer, "ExAcquireSpinLockExclusiveAtDpcLevel");
            ctx.Call_GetNext_InstCount = 0;
#ifdef _WIN64
            ctx.Lea_Rcx_Candidate = 0;
            ctx.Lea_Rcx_InstCount = 0;
#else
            ctx.Mov_Exi_InstCount = 0;
            ctx.Mov_Exi_Candidate = 0;
#endif
            DisasmRanges((PUCHAR)pFound, 0x100, KphGetDebugPrintCallback, &ctx);

            if (!RtlpDebugPrintCallbackLock)
            {
                dprintf("RtlpDebugPrintCallbackLock not found\n");
                return;
            }

            if (!RtlpDebugPrintCallbackList)
            {
                dprintf("RtlpDebugPrintCallbackList not found\n");
                return;
            }

            RtlpDebugPrintCallbackLock = (PKSPIN_LOCK)((PUCHAR)NtosRange.Base + ((PUCHAR)RtlpDebugPrintCallbackLock - (PUCHAR)Buffer));
            RtlpDebugPrintCallbackList = (PLIST_ENTRY)((PUCHAR)NtosRange.Base + ((PUCHAR)RtlpDebugPrintCallbackList - (PUCHAR)Buffer));

            dprintf("RtlpDebugPrintCallbackLock %p\n", RtlpDebugPrintCallbackLock);
            dprintf("RtlpDebugPrintCallbackList %p\n", RtlpDebugPrintCallbackList);
        }
    }

    if (PAGEBase)
    {

    }
}
