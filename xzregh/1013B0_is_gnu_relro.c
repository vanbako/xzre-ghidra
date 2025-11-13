// /home/kali/xzre-ghidra/xzregh/1013B0_is_gnu_relro.c
// Function: is_gnu_relro @ 0x1013B0
// Calling convention: unknown
// Prototype: undefined is_gnu_relro(void)


/*
 * AutoDoc: Obfuscated equality test for PT_GNU_RELRO. Instead of comparing `p_type` directly against `0x6474e552`, the code adds the caller supplied `addend` (always `0xa0000000`) and checks for the magic constant, which makes the instruction stream look less like a straightforward RELRO probe in the object file.
 */
#include "xzre_types.h"


bool is_gnu_relro(int param_1,int param_2)

{
  return param_1 + 1 + param_2 == 0x474e553;
}

