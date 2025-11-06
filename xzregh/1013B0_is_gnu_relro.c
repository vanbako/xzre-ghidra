// /home/kali/xzre-ghidra/xzregh/1013B0_is_gnu_relro.c
// Function: is_gnu_relro @ 0x1013B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_gnu_relro(Elf64_Word p_type, u32 addend)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief checks if the provided identifiers represent a `PT_GNU_RELRO`
 *
 *   @param p_type program header type
 *   @param addend constant `0xA0000000`
 *   @return BOOL TRUE if the supplied pt_type is `PT_GNU_RELRO`, FALSE otherwise
 */

BOOL is_gnu_relro(Elf64_Word p_type,u32 addend)

{
  return (BOOL)(p_type + 1 + addend == 0x474e553);
}

