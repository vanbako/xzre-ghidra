// /home/kali/xzre-ghidra/xzregh/101B30_c_memmove.c
// Function: c_memmove @ 0x101B30
// Calling convention: unknown
// Prototype: undefined c_memmove(void)


/*
 * AutoDoc: Private implementation of `memmove` so the object never has to import libc for something this trivial. It detects backwards overlap (`src < dest < src+cnt`) and copies from the end towards the beginning in that case; every other scenario devolves into a forward copy loop. Either way the original `dest` pointer is returned so callers can chain copies just like they would with the libc version.
 */
#include "xzre_types.h"


void c_memmove(ulong param_1,ulong param_2,long param_3)

{
  long lVar1;
  
  if ((param_2 < param_1) && (param_1 < param_2 + param_3)) {
    lVar1 = param_3 + -1;
    if (param_3 != 0) {
      do {
        *(undefined1 *)(param_1 + lVar1) = *(undefined1 *)(param_2 + lVar1);
        lVar1 = lVar1 + -1;
      } while (lVar1 != -1);
      return;
    }
  }
  else {
    lVar1 = 0;
    if (param_3 == 0) {
      return;
    }
    do {
      *(undefined1 *)(param_1 + lVar1) = *(undefined1 *)(param_2 + lVar1);
      lVar1 = lVar1 + 1;
    } while (param_3 != lVar1);
  }
  return;
}

