// /home/kali/xzre-ghidra/xzregh/100AC0_is_endbr64_instruction.c
// Function: is_endbr64_instruction @ 0x100AC0
// Calling convention: unknown
// Prototype: undefined is_endbr64_instruction(void)


/*
 * AutoDoc: Checks whether the bytes at the current cursor encode an ENDBR64 landing pad, including the CET prefix variations. The pattern scanners call it so the backdoor can safely step past CET trampolines while carving prologues to patch.
 */
#include "xzre_types.h"


bool is_endbr64_instruction(int *param_1,long param_2,uint param_3)

{
  bool bVar1;
  
  bVar1 = FALSE;
  if (3 < param_2 - (long)param_1) {
    bVar1 = (param_3 | 0x5e20000) + *param_1 == 0xf223;
  }
  return bVar1;
}

