// /home/kali/xzre-ghidra/xzregh/100AC0_is_endbr64_instruction.c
// Function: is_endbr64_instruction @ 0x100AC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_endbr64_instruction(u8 * code_start, u8 * code_end, u32 low_mask_part)


/*
 * AutoDoc: Guards that at least four bytes remain and then compares the dword at `code_start` against ENDBR64, or'd with the caller-supplied `low_mask_part` so both CET prefix variants collapse to a single equality test.
 * Used by the prologue finders to cheaply vet potential landing pads before accepting them as function entries.
 */

#include "xzre_types.h"

BOOL is_endbr64_instruction(u8 *code_start,u8 *code_end,u32 low_mask_part)

{
  BOOL is_endbr;
  
  is_endbr = FALSE;
  if (3 < (long)code_end - (long)code_start) {
    is_endbr = (BOOL)((low_mask_part | 0x5e20000) + *(int *)code_start == 0xf223);
  }
  return is_endbr;
}

