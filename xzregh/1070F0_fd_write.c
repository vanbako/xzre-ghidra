// /home/kali/xzre-ghidra/xzregh/1070F0_fd_write.c
// Function: fd_write @ 0x1070F0
// Calling convention: unknown
// Prototype: undefined fd_write(void)


/*
 * AutoDoc: Mirror of `fd_read`: it requires valid write/errno pointers, retries on EINTR, and treats short
 * writes as fatal so callers either send the entire buffer or receive -1. It is the plumbing used
 * whenever the implant forges monitor messages.
 */
#include "xzre_types.h"


long fd_write(int param_1,long param_2,long param_3,long param_4)

{
  long lVar1;
  int *piVar2;
  long lVar3;
  int *errno_slot;
  
  if (param_3 == 0) {
    return 0;
  }
  if ((((param_4 == 0 || param_1 < 0) || (param_2 == 0)) || (*(long *)(param_4 + 0x38) == 0)) ||
     (lVar3 = param_3, *(long *)(param_4 + 0x50) == 0)) {
LAB_0010711f:
    param_3 = -1;
  }
  else {
    do {
      while( TRUE ) {
        lVar1 = (**(code **)(param_4 + 0x38))(param_1,param_2,lVar3);
        if (-1 < lVar1) break;
        piVar2 = (int *)(**(code **)(param_4 + 0x50))();
        if (*piVar2 != 4) goto LAB_0010711f;
      }
      if (lVar1 == 0) goto LAB_0010711f;
      param_2 = param_2 + lVar1;
      lVar3 = lVar3 - lVar1;
    } while (lVar3 != 0);
  }
  return param_3;
}

