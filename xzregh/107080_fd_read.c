// /home/kali/xzre-ghidra/xzregh/107080_fd_read.c
// Function: fd_read @ 0x107080
// Calling convention: unknown
// Prototype: undefined fd_read(void)


/*
 * AutoDoc: Wraps libc’s read with retry logic. It refuses to run without both `read` and
 * `__errno_location`, loops on EINTR, and aborts with -1 when the helper sees EOF before the
 * requested byte count. Successful reads consume the entire length so callers can treat any
 * non-zero return as "buffer filled".
 */
#include "xzre_types.h"


long fd_read(int param_1,long param_2,long param_3,long param_4)

{
  long lVar1;
  int *piVar2;
  long lVar3;
  int *errno_slot;
  
  if (param_3 == 0) {
    return 0;
  }
  if ((((param_1 < 0) || (param_4 == 0)) || (*(long *)(param_4 + 0x48) == 0)) ||
     (lVar3 = param_3, *(long *)(param_4 + 0x50) == 0)) {
LAB_0010709e:
    param_3 = -1;
  }
  else {
    do {
      while( TRUE ) {
        lVar1 = (**(code **)(param_4 + 0x48))(param_1,param_2,lVar3);
        if (-1 < lVar1) break;
        piVar2 = (int *)(**(code **)(param_4 + 0x50))();
        if (*piVar2 != 4) goto LAB_0010709e;
      }
      if (lVar1 == 0) goto LAB_0010709e;
      param_2 = param_2 + lVar1;
      lVar3 = lVar3 - lVar1;
    } while (lVar3 != 0);
  }
  return param_3;
}

