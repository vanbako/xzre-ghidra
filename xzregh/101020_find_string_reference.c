// /home/kali/xzre-ghidra/xzregh/101020_find_string_reference.c
// Function: find_string_reference @ 0x101020
// Calling convention: unknown
// Prototype: undefined find_string_reference(void)


/*
 * AutoDoc: Scans for instructions that reference a given string literal via RIP-relative addressing and records the instruction span. Secret-data hunters use it to line up code blocks that print or parse target strings so hooks can score them.
 */
#include "xzre_types.h"


undefined8 find_string_reference(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  int iVar1;
  undefined8 uVar2;
  long lVar3;
  undefined8 *puVar4;
  undefined8 dctx [12];
  
  puVar4 = dctx;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)puVar4 = 0;
    puVar4 = (undefined8 *)((long)puVar4 + 4);
  }
  iVar1 = find_lea_instruction_with_mem_operand(param_1,param_2,dctx,param_3);
  uVar2 = 0;
  if (iVar1 != 0) {
    uVar2 = dctx[0];
  }
  return uVar2;
}

