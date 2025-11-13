// /home/kali/xzre-ghidra/xzregh/102370_is_range_mapped.c
// Function: is_range_mapped @ 0x102370
// Calling convention: unknown
// Prototype: undefined is_range_mapped(void)


/*
 * AutoDoc: Userland page-probe that avoids importing `mincore(2)`. The helper aligns the requested address downward, then walks one page at a time toward `addr + length`, invoking the host's `pselect` with NULL fd sets and the page pointer passed in as the signal mask argument. If `pselect` faults with EFAULT the page is unmapped, otherwise the loop continues until every page succeeds. The routine relies on `ctx->libc_imports` to surface both `pselect` and `__errno_location`, and it refuses to touch addresses below 0x01000000 to avoid probing NULL or vsyscall.
 */
#include "xzre_types.h"


undefined8 is_range_mapped(ulong param_1,long param_2,long param_3)

{
  long lVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  ulong uVar5;
  undefined8 local_38;
  undefined8 local_30;
  
  if (param_2 == 0) {
    return 0;
  }
  if (param_1 < 0x1000000) {
LAB_00102393:
    uVar4 = 0;
  }
  else {
    uVar5 = param_1 & 0xfffffffffffff000;
    if (uVar5 < param_1 + param_2) {
      if (param_3 == 0) goto LAB_00102393;
      do {
        local_38 = 0;
        lVar1 = *(long *)(param_3 + 0x10);
        if (((lVar1 == 0) || (*(long *)(lVar1 + 0x50) == 0)) ||
           (*(code **)(lVar1 + 0x40) == (code *)0x0)) goto LAB_00102393;
        local_30 = 1;
        iVar2 = (**(code **)(lVar1 + 0x40))(1,0,0,0,&local_38,uVar5);
        if ((iVar2 < 0) &&
           ((piVar3 = (int *)(**(code **)(*(long *)(param_3 + 0x10) + 0x50))(), *piVar3 == 0xe ||
            (uVar5 == 0)))) {
          *piVar3 = 0;
          goto LAB_00102393;
        }
        uVar5 = uVar5 + 0x1000;
      } while (uVar5 < param_1 + param_2);
    }
    uVar4 = 1;
  }
  return uVar4;
}

