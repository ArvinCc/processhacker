#include <kph.h>
#include <fltKernel.h>
#include <intrin.h>
#include "detours.h"
#include "PEStructs.h"
#include "cs_driver_mm.h"

NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

// Returns a size of an instruction at the address
SIZE_T GetInstructionSize(PVOID address)
{
    PAGED_CODE();

    SIZE_T instlen = 0;
    // Save floating point state
    KFLOATING_SAVE float_save = { 0 };
    NTSTATUS status = KeSaveFloatingPointState(&float_save);
    if (NT_SUCCESS(status)) {
        // Disassemble at most 15 bytes to get an instruction size
        csh handle = 0;
#ifdef _WIN64
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
#else
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {
#endif
            cs_insn inst;
            RtlZeroMemory(&inst, sizeof(inst));
            uint8_t *addr = (uint8_t *)address;
            uint64_t vaddr = PVOID_TO_ULONG64(address);
            size_t size = 15;

            bool accessable = true;
            if ((PUCHAR)address + size < (PUCHAR)MmUserProbeAddress)
            {
                __try
                {
                    ProbeForRead(address, size, 1);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    accessable = FALSE;
                }
            }
            else
            {
                if (!MmIsAddressValid(address) || !MmIsAddressValid((PUCHAR)address + size))
                    accessable = FALSE;
            }

            if (accessable)
            {
                if (cs_disasm_iter(handle, &addr, &size, &vaddr, &inst)) {
                    instlen = inst.size;
                }
            }
            cs_close(&handle);
        }
        KeRestoreFloatingPointState(&float_save);
    }

    return instlen;
}

VOID DisasmSingleInstruction(PVOID address, DisasmSingleCallback callback, void *context)
{
    PAGED_CODE();

    // Save floating point state
    KFLOATING_SAVE float_save = { 0 };
    auto status = KeSaveFloatingPointState(&float_save);
    if (NT_SUCCESS(status)) {
        // Disassemble at most 15 bytes to get an instruction size
        csh handle = 0;
#ifdef _WIN64
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
#else
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {
#endif
            if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK) {

                cs_insn *insts = NULL;
                size_t count = 0;

                const uint8_t *addr = (uint8_t *)address;
                uint64_t vaddr = PVOID_TO_ULONG64(address);
                size_t size = 15;

                bool accessable = true;
                if ((PUCHAR)address + size < (PUCHAR)MmUserProbeAddress)
                {
                    __try
                    {
                        ProbeForRead(address, size, 1);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        accessable = false;
                    }
                }
                else
                {
                    if (!MmIsAddressValid(address) || !MmIsAddressValid((PUCHAR)address + size))
                        accessable = false;
                }

                if (accessable)
                {
                    count = cs_disasm(handle, addr, size, vaddr, 1, &insts);
                    if (count)
                    {
                        callback(insts, (PUCHAR)address, insts->size, context);
                    }
                }

                if (insts) {
                    cs_free(insts, count);
                    insts = NULL;
                }
            }
            cs_close(&handle);
        }
        KeRestoreFloatingPointState(&float_save);
    }
}

BOOLEAN IsStackRegister(x86_reg reg)
{
    switch (reg)
    {
    case X86_REG_EBP:case X86_REG_ESP:
#ifdef _WIN64
    case X86_REG_RBP:case X86_REG_RSP:
#endif
        return TRUE;
    }
    return FALSE;
}

BOOLEAN IsCommonRegister(x86_reg reg)
{
#ifdef _WIN64
    if (reg >= X86_REG_R8 && reg <= X86_REG_R15)
        return TRUE;
    if (reg >= X86_REG_R8D && reg <= X86_REG_R15D)
        return TRUE;
#endif

    switch (reg)
    {
    case X86_REG_EAX:case X86_REG_EBX:case X86_REG_ECX:case X86_REG_EDX:
    case X86_REG_ESI:case X86_REG_EDI:
#ifdef _WIN64
    case X86_REG_RAX:case X86_REG_RBX:case X86_REG_RCX:case X86_REG_RDX:
    case X86_REG_RSI:case X86_REG_RDI:
#endif
        return TRUE;
    }
    return FALSE;
}

BOOLEAN IsCommonRegisterByte(x86_reg reg)
{
#ifdef _WIN64
    if (reg >= X86_REG_R8B && reg >= X86_REG_R15B)
        return TRUE;
#endif

    switch (reg)
    {
    case X86_REG_AL:case X86_REG_BL:case X86_REG_CL:case X86_REG_DL:
        return TRUE;
    }
    return FALSE;
}

BOOLEAN IsInMemoryRange(PVOID VirtualAddress, MemoryRange_t *range)
{
    return (VirtualAddress >= range->Base && VirtualAddress < range->End);
}

BOOLEAN DisasmRangesWalk(PVOID DisasmBase, SIZE_T DisasmSize, DisasmCallbackWalk callback, PVOID context, int depth)
{
    PVOID ImageBase2;
    BOOLEAN success = FALSE;
    KFLOATING_SAVE float_save = { 0 };
    auto status = KeSaveFloatingPointState(&float_save);
    if (NT_SUCCESS(status)) {

        bool InitSection = false;

        PVOID ImageBase = RtlPcToFileHeader(DisasmBase, &ImageBase2);
        PVOID LockHandle = NULL;
        PVOID LockHandle2 = NULL;
        if (ImageBase)
        {
            PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(ImageBase);
            if (NtHeader)
            {
                PIMAGE_SECTION_HEADER SectionHdr = (PIMAGE_SECTION_HEADER)((PUCHAR)NtHeader + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + NtHeader->FileHeader.SizeOfOptionalHeader);
                for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                {
                    if ((PUCHAR)DisasmBase >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "INIT", 4))
                        {
                            InitSection = true;
                            break;
                        }
                    }

                    if ((PUCHAR)DisasmBase >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "PAGE", 4))
                        {
                            LockHandle = MmLockPagableDataSection(DisasmBase);
                        }
                    }

                    if ((PUCHAR)DisasmBase + DisasmSize - 1 >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase + DisasmSize - 1 < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "PAGE", 4))
                        {
                            LockHandle2 = MmLockPagableDataSection((PUCHAR)DisasmBase + DisasmSize - 1);
                        }
                    }
                }
            }
        }

        if (!InitSection)
        {
            csh handle = 0;
#ifdef _WIN64
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
#else
            if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {
#endif
                cs_insn *insts = NULL;
                size_t count = 0;
                int instCount = 1;

                if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK)
                {
                    PUCHAR pAddress = (PUCHAR)DisasmBase;

                    do
                    {
                        const uint8_t *addr = (uint8_t *)pAddress;
                        uint64_t vaddr = PVOID_TO_ULONG64(pAddress);
                        size_t size = 15;

                        if (insts) {
                            cs_free(insts, count);
                            insts = NULL;
                        }
                        if (pAddress + 15 < (PUCHAR)MmUserProbeAddress)
                        {
                            __try
                            {
                                ProbeForRead(pAddress, size, 1);
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                dprintf("pAddress %p unaccessable\n", pAddress);
                                break;
                            }
                        }
                        else
                        {
                            if (!MmIsAddressValid(pAddress) || !MmIsAddressValid(pAddress + size))
                            {
                                dprintf("pAddress %p unaccessable\n", pAddress);
                                break;
                            }
                        }
                        count = cs_disasm(handle, addr, size, vaddr, 1, &insts);
                        if (!count)
                        {
                            dprintf("pAddress %p count zero\n", pAddress);
                            break;
                        }
                        SIZE_T instLen = insts[0].size;
                        if (!instLen)
                        {
                            dprintf("pAddress %p inst zero\n", pAddress);
                            break;
                        }

                        if (callback(&insts[0], pAddress, instLen, instCount, context, depth))
                        {
                            success = TRUE;
                            break;
                        }

                        pAddress += instLen;
                        instCount++;
                    } while (pAddress < (PUCHAR)DisasmBase + DisasmSize);
                }
                else
                {
                    dprintf("failed to cs_option");
                }

                if (insts) {
                    cs_free(insts, count);
                    insts = NULL;
                }

                cs_close(&handle);
            }
            else
            {
                dprintf("failed to cs_open");
            }
            }
        if (LockHandle && LockHandle != (PVOID)-1)
        {
            MmUnlockPagableImageSection(LockHandle);
        }
        if (LockHandle2 && LockHandle2 != (PVOID)-1)
        {
            MmUnlockPagableImageSection(LockHandle2);
        }

        KeRestoreFloatingPointState(&float_save);
    }
    else
    {
         dprintf("failed to save float");
    }

    return success;
}

BOOLEAN DisasmRanges(PVOID DisasmBase, SIZE_T DisasmSize, DisasmCallback callback, PVOID context)
{
    PVOID ImageBase2;
    BOOLEAN success = FALSE;
    KFLOATING_SAVE float_save = { 0 };
    auto status = KeSaveFloatingPointState(&float_save);
    if (NT_SUCCESS(status)) {

        bool InitSection = false;

        PVOID ImageBase = RtlPcToFileHeader(DisasmBase, &ImageBase2);
        PVOID LockHandle = NULL;
        PVOID LockHandle2 = NULL;
        if (ImageBase)
        {
            PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(ImageBase);
            if (NtHeader)
            {
                PIMAGE_SECTION_HEADER SectionHdr = (PIMAGE_SECTION_HEADER)((PUCHAR)NtHeader + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + NtHeader->FileHeader.SizeOfOptionalHeader);
                for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                {
                    if ((PUCHAR)DisasmBase >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "INIT", 4))
                        {
                            InitSection = true;
                            break;
                        }
                    }

                    if ((PUCHAR)DisasmBase >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "PAGE", 4))
                        {
                            LockHandle = MmLockPagableDataSection(DisasmBase);
                        }
                    }

                    if ((PUCHAR)DisasmBase + DisasmSize - 1 >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase + DisasmSize - 1 < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "PAGE", 4))
                        {
                            LockHandle2 = MmLockPagableDataSection((PUCHAR)DisasmBase + DisasmSize - 1);
                        }
                    }
                }
            }
        }

        if (!InitSection)
        {
            csh handle = 0;
#ifdef _WIN64
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
#else
            if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {
#endif
                cs_insn *insts = NULL;
                size_t count = 0;
                int instCount = 1;
                uint8_t *addr;
                uint64_t vaddr;
                size_t size;
                if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK)
                {
                    PUCHAR pAddress = (PUCHAR)DisasmBase;

                    do
                    {
                        addr = (uint8_t *)pAddress;
                        vaddr = PVOID_TO_ULONG64(pAddress);
                        size = 15;

                        if (insts) {
                            cs_free(insts, count);
                            insts = NULL;
                        }
                        if (pAddress + size < (PUCHAR)MmUserProbeAddress)
                        {
                            __try
                            {
                                ProbeForRead(pAddress, size, 1);
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                dprintf("pAddress %p unaccessable\n", pAddress);
                                break;
                            }
                        }
                        else
                        {
                            if (!MmIsAddressValid(pAddress) || !MmIsAddressValid(pAddress + size))
                            {
                                dprintf("pAddress %p unaccessable\n", pAddress);
                                break;
                            }
                        }
                        count = cs_disasm(handle, addr, size, vaddr, 1, &insts);
                        if (!count)
                        {
                            dprintf("pAddress %p count zero\n", pAddress);
                            break;
                        }
                        SIZE_T instLen = insts[0].size;
                        if (!instLen)
                        {
                            dprintf("pAddress %p inst zero\n", pAddress);
                            break;
                        }

                        if (callback(&insts[0], pAddress, instLen, instCount, context))
                        {
                            success = TRUE;
                            break;
                        }

                        pAddress += instLen;
                        instCount++;
                    } while (pAddress < (PUCHAR)DisasmBase + DisasmSize);
                }
                else
                {
                    dprintf("failed to cs_option");
                }

                if (insts) {
                    cs_free(insts, count);
                    insts = NULL;
                }

                cs_close(&handle);
            }
            else
            {
                dprintf("failed to cs_open");
            }
        }
        if (LockHandle && LockHandle != (PVOID)-1)
        {
            MmUnlockPagableImageSection(LockHandle);
        }
        if (LockHandle2 && LockHandle2 != (PVOID)-1)
        {
            MmUnlockPagableImageSection(LockHandle2);
        }

        KeRestoreFloatingPointState(&float_save);
    }
    else
    {
        dprintf("failed to save float");
    }

    return success;
}

BOOLEAN DisasmRangesEx(PVOID DisasmBase, SIZE_T DisasmSize, DisasmCallbackEx callback, PVOID context)
{
    PVOID ImageBase2;
    BOOLEAN success = FALSE;
    KFLOATING_SAVE float_save = { 0 };
    auto status = KeSaveFloatingPointState(&float_save);
    if (NT_SUCCESS(status)) {

        bool InitSection = false;

        PVOID ImageBase = RtlPcToFileHeader(DisasmBase, &ImageBase2);
        PVOID LockHandle = NULL;
        PVOID LockHandle2 = NULL;
        if (ImageBase)
        {
            PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(ImageBase);
            if (NtHeader)
            {
                PIMAGE_SECTION_HEADER SectionHdr = (PIMAGE_SECTION_HEADER)((PUCHAR)NtHeader + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + NtHeader->FileHeader.SizeOfOptionalHeader);
                for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                {
                    if ((PUCHAR)DisasmBase >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "INIT", 4))
                        {
                            InitSection = true;
                            break;
                        }
                    }

                    if ((PUCHAR)DisasmBase >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "PAGE", 4))
                        {
                            LockHandle = MmLockPagableDataSection(DisasmBase);
                        }
                    }

                    if ((PUCHAR)DisasmBase + DisasmSize - 1 >= (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress &&
                        (PUCHAR)DisasmBase + DisasmSize - 1 < (PUCHAR)ImageBase + SectionHdr[i].VirtualAddress + SectionHdr[i].SizeOfRawData)
                    {
                        if (0 == memcmp(SectionHdr[i].Name, "PAGE", 4))
                        {
                            LockHandle2 = MmLockPagableDataSection((PUCHAR)DisasmBase + DisasmSize - 1);
                        }
                    }
                }
            }
        }

        if (!InitSection)
        {

            csh handle = 0;
#ifdef _WIN64
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK) {
#else
            if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK) {
#endif
                cs_insn *insts = NULL;
                size_t count = 0;

                if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK)
                {
                    PUCHAR pAddress = (PUCHAR)DisasmBase;

                    do
                    {
                        const uint8_t *addr = (uint8_t *)pAddress;
                        uint64_t vaddr = PVOID_TO_ULONG64(pAddress);
                        size_t size = 15;

                        if (insts) {
                            cs_free(insts, count);
                            insts = NULL;
                        }
                        if (pAddress + size < (PUCHAR)MmUserProbeAddress)
                        {
                            __try
                            {
                                ProbeForRead(pAddress, size, 1);
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {
                                dprintf("pAddress %p unaccessable\n", pAddress);
                                break;
                            }
                        }
                        else
                        {
                            if (!MmIsAddressValid(pAddress) || !MmIsAddressValid(pAddress + size))
                            {
                                dprintf("pAddress %p unaccessable\n", pAddress);
                                break;
                            }
                        }
                        count = cs_disasm(handle, addr, size, vaddr, 1, &insts);
                        if (!count)
                        {
                            dprintf("pAddress %p count zero\n", pAddress);
                            break;
                        }
                        SIZE_T instLen = insts[0].size;
                        if (!instLen)
                        {
                            dprintf("pAddress %p inst zero\n", pAddress);
                            break;
                        }

                        if (callback(&insts[0], &pAddress, instLen, context))
                        {
                            success = TRUE;
                            break;
                        }

                    } while (pAddress < (PUCHAR)DisasmBase + DisasmSize);
                }
                else
                {
                    dprintf("failed to cs_option");
                }

                if (insts) {
                    cs_free(insts, count);
                    insts = NULL;
                }

                cs_close(&handle);
            }
            else
            {
                dprintf("failed to cs_open");
            }
        }

        if (LockHandle && LockHandle != (PVOID)-1)
        {
            MmUnlockPagableImageSection(LockHandle);
        }
        if (LockHandle2 && LockHandle2 != (PVOID)-1)
        {
            MmUnlockPagableImageSection(LockHandle2);
        }

        KeRestoreFloatingPointState(&float_save);
    }
    else
    {
        dprintf("failed to save float");
    }
    return success;
}
