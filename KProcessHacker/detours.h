#pragma once

#include "cs_driver_mm.h"

typedef struct WalkContext_s
{
    PVOID address;
    size_t len;
    int depth;
}WalkContext_t;

typedef void(*DisasmSingleCallback)(cs_insn *inst, PUCHAR pAddress, size_t instLen, PVOID context);
typedef BOOLEAN(*DisasmCallback)(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context);
typedef BOOLEAN(*DisasmCallbackWalk)(cs_insn *inst, PUCHAR pAddress, size_t instLen, int instCount, PVOID context, int depth);
typedef BOOLEAN(*DisasmCallbackEx)(cs_insn *inst, PUCHAR *ppAddress, size_t instLen, PVOID context);
typedef BOOLEAN(*IsInnerCallCallback)(cs_insn *inst, PUCHAR Address, PUCHAR TargetAddress);

BOOLEAN DisasmRanges(PVOID DisasmBase, SIZE_T DisasmSize, DisasmCallback callback, PVOID context);
BOOLEAN DisasmRangesWalk(PVOID DisasmBase, SIZE_T DisasmSize, DisasmCallbackWalk callback, PVOID context, int depth);
BOOLEAN DisasmRangesEx(PVOID DisasmBase, SIZE_T DisasmSize, DisasmCallbackEx callback, PVOID context);
VOID DisasmSingleInstruction(PVOID address, DisasmSingleCallback callback, void *context);
BOOLEAN IsInMemoryRange(PVOID VirtualAddress, MemoryRange_t *range);
BOOLEAN IsCommonRegister(x86_reg reg);
BOOLEAN IsCommonRegisterByte(x86_reg reg);
BOOLEAN IsStackRegister(x86_reg reg);
SIZE_T GetInstructionSize(PVOID address);

#define ULONG_TO_ULONG64(addr) ((ULONG64)addr & 0xFFFFFFFFull)
#define PVOID_TO_ULONG64(addr) (sizeof(addr) == 4 ? ULONG_TO_ULONG64(addr) : (ULONG64)addr)
