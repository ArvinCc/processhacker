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

#include "detours.h"

PVOID PspCreateProcessNotifyRoutine = NULL;
ULONG PspCreateProcessNotifyRoutineMaxCount = 0;
PVOID PspLoadImageNotifyRoutine = NULL;
ULONG PspLoadImageNotifyRoutineMaxCount = 0;
MemoryRange_t NtosRange = { 0 };
MemoryRange_t ThisRange = { 0 };

NTSTATUS KphEnumSystemModules(EnumSystemModuleCallback callback, PVOID Context);
BOOLEAN KphInitGetKernelInfo(PRTL_PROCESS_MODULE_INFORMATION pMod, PVOID checkPtr);
VOID KphGetPspCreateProcessNotifyRoutine(VOID);
VOID KphGetPspLoadImageNotifyRoutine(VOID);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KphGetSystemRoutineAddress)
#pragma alloc_text(PAGE, KphDynamicImport)
#pragma alloc_text(INIT, KphInitGetKernelInfo)
#pragma alloc_text(PAGE, KphEnumSystemModules)
#pragma alloc_text(INIT, KphGetPspCreateProcessNotifyRoutine)
#pragma alloc_text(INIT, KphGetPspLoadImageNotifyRoutine)
#endif

/**
 * Dynamically imports routines.
 */
VOID KphDynamicImport(
    VOID
    )
{
    PAGED_CODE();
    KphEnumSystemModules(KphInitGetKernelInfo, NULL);
    KphGetPspCreateProcessNotifyRoutine();
    KphGetPspLoadImageNotifyRoutine();
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

BOOLEAN KphInitGetKernelInfo(PRTL_PROCESS_MODULE_INFORMATION pMod, PVOID checkPtr)
{
    if (!NtosRange.Base)
    {
        if (pMod->LoadOrderIndex == 0)
        {
            NtosRange.Base = pMod->ImageBase;
            NtosRange.End = (PUCHAR)pMod->ImageBase + pMod->ImageSize;
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
    ULONG *MaxCount;
}GetRoutineMaxCount_Context;

typedef struct
{
    int Mov_InstCount;
    int Call_InstCount;
    GetRoutineMaxCount_Context RoutineMaxCount;
}KphGetPspLoadImageNotifyRoutine_Context;

typedef struct
{
    PVOID PspSetCreateProcessNotifyRoutine;
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
                        *ctx->MaxCount = (ULONG)(inst->detail->x86.operands[1].imm / ctx->IncValue[i]);
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

    if (!*ctx->RoutineMaxCount.MaxCount && ctx->Call_InstCount && instCount - ctx->Call_InstCount < 12)
    {
        FindRoutineMaxCount_Callback(inst, pAddress, instLen, instCount, &ctx->RoutineMaxCount);
        if (!*ctx->RoutineMaxCount.MaxCount)
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
                    ctx2.MaxCount = &PspLoadImageNotifyRoutineMaxCount;
                    DisasmRanges(imm, 50, FindRoutineMaxCount_Callback, &ctx2);
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
    ctx.RoutineMaxCount.MaxCount = &PspLoadImageNotifyRoutineMaxCount;

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

        ctx->PspSetCreateProcessNotifyRoutine = (PVOID)(pAddress + instLen + *(int *)(pAddress + 1));
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

    if (!PspCreateProcessNotifyRoutine)
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
            PspCreateProcessNotifyRoutine = (PVOID)(pAddress + instLen + (int)inst->detail->x86.operands[1].mem.disp);
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
        if (!PspCreateProcessNotifyRoutine && ctx->Candidate_Mov_Mem)
            PspCreateProcessNotifyRoutine = ctx->Candidate_Mov_Mem;
#endif

        //HYPERPLATFORM_LOG_INFO_SAFE("call found");
        ctx->Call_InstCount = instCount;
    }

    if (!*ctx->RoutineMaxCount.MaxCount && ctx->Call_InstCount && instCount - ctx->Call_InstCount < 12)
    {
        FindRoutineMaxCount_Callback(inst, pAddress, instLen, instCount, &ctx->RoutineMaxCount);
        if (!*ctx->RoutineMaxCount.MaxCount)
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
                    ctx2.MaxCount = &PspCreateProcessNotifyRoutineMaxCount;
                    DisasmRanges(imm, 50, FindRoutineMaxCount_Callback, &ctx2);
                }
            }
        }
    }

    return (PspCreateProcessNotifyRoutine && PspCreateProcessNotifyRoutineMaxCount);
}

VOID KphGetPspCreateProcessNotifyRoutine(VOID)
{
    KphGetPspCreateProcessNotifyRoutine_Context ctx;

    PVOID pfnPsSetCreateProcessNotifyRoutine, pfnPsSetCreateProcessNotifyRoutineEx;

    pfnPsSetCreateProcessNotifyRoutine = KphGetSystemRoutineAddress(L"PsSetCreateProcessNotifyRoutine");
    pfnPsSetCreateProcessNotifyRoutineEx = KphGetSystemRoutineAddress(L"PsSetCreateProcessNotifyRoutineEx");

    ctx.PspSetCreateProcessNotifyRoutine = NULL;
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
    ctx.RoutineMaxCount.MaxCount = &PspCreateProcessNotifyRoutineMaxCount;

    if (pfnPsSetCreateProcessNotifyRoutineEx)
    {
        DisasmRanges(pfnPsSetCreateProcessNotifyRoutineEx, 100, KphGetPspCreateProcessNotifyRoutine_FirstStage, &ctx);

        if (!ctx.PspSetCreateProcessNotifyRoutine && ctx.Candidate_CallTarget && ctx.FuncEnd_InstCount && ctx.FuncEnd_InstCount <= 12)
            ctx.PspSetCreateProcessNotifyRoutine = ctx.Candidate_CallTarget;
    }

    if (!ctx.PspSetCreateProcessNotifyRoutine)
        ctx.PspSetCreateProcessNotifyRoutine = pfnPsSetCreateProcessNotifyRoutine;

    DisasmRanges(ctx.PspSetCreateProcessNotifyRoutine, 0x150, KphGetPspCreateProcessNotifyRoutine_SecondStage, &ctx);

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
