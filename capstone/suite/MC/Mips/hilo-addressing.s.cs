# CS_ARCH_MIPS, CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN, None
// 0x3c,0x04,0xde,0xae = lui $a0, %hi(addr)
0x03,0xe0,0x00,0x08 = jr $ra
// 0x80,0x82,0xbe,0xef = lb $v0, %lo(addr)($a0)
