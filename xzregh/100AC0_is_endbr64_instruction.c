// /home/kali/xzre-ghidra/xzregh/100AC0_is_endbr64_instruction.c
// Function: is_endbr64_instruction @ 0x100AC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_endbr64_instruction(u8 * code_start, u8 * code_end, u32 low_mask_part)


/*
 * AutoDoc: Fast equality test used when scanning for CET landing pads. When at least four bytes remain it ORs ENDBR64 (`0xF30F1EFA`) with the caller-supplied `low_mask_part` so both ENDBR64 and ENDBR32 collapse into a single signature, then compares the resulting dword against the bytes at `code_start`. Returns TRUE only when the stream contains a full ENDBR instruction; otherwise the prologue walkers keep scanning.
 */

#include "xzre_types.h"

BOOL is_endbr64_instruction(u8 *code_start,u8 *code_end,u32 low_mask_part)

{
  BOOL has_endbr;
  
  has_endbr = FALSE;
  if (3 < (long)code_end - (long)code_start) {
    has_endbr = (BOOL)((low_mask_part | 0x5e20000) + *(int *)code_start == 0xf223);
  }
  return has_endbr;
}

