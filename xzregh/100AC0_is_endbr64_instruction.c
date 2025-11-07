// /home/kali/xzre-ghidra/xzregh/100AC0_is_endbr64_instruction.c
// Function: is_endbr64_instruction @ 0x100AC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_endbr64_instruction(u8 * code_start, u8 * code_end, u32 low_mask_part)
/*
 * AutoDoc: Checks whether the bytes at the current cursor encode an ENDBR64 landing pad, including the CET prefix variations. The pattern scanners call it so the backdoor can safely step past CET trampolines while carving prologues to patch.
 */

#include "xzre_types.h"


BOOL is_endbr64_instruction(u8 *code_start,u8 *code_end,u32 low_mask_part)

{
  uint uVar1;
  
  uVar1 = 0;
  if (3 < (long)code_end - (long)code_start) {
    uVar1 = (uint)((low_mask_part | 0x5e20000) + *(int *)code_start == 0xf223);
  }
  return uVar1;
}

