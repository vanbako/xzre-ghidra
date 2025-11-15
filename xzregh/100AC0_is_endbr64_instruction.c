// /home/kali/xzre-ghidra/xzregh/100AC0_is_endbr64_instruction.c
// Function: is_endbr64_instruction @ 0x100AC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_endbr64_instruction(u8 * code_start, u8 * code_end, u32 low_mask_part)


/*
 * AutoDoc: Sanity-checks that at least four bytes remain at `code_start` and then tests the dword against the ENDBR64 opcode, folding in the caller supplied `low_mask_part` so both CET prefix variants collapse to the same comparison.
 * The loader’s pattern scanners use it to cheaply confirm CET landing pads before treating the site as a safe function prologue.
 */

#include "xzre_types.h"

BOOL is_endbr64_instruction(u8 *code_start,u8 *code_end,u32 low_mask_part)

{
  BOOL BVar1;
  
  BVar1 = FALSE;
  if (3 < (long)code_end - (long)code_start) {
    BVar1 = (BOOL)((low_mask_part | 0x5e20000) + *(int *)code_start == 0xf223);
  }
  return BVar1;
}

