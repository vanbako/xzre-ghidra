// /home/kali/xzre-ghidra/xzregh/107170_contains_null_pointers.c
// Function: contains_null_pointers @ 0x107170
// Calling convention: unknown
// Prototype: undefined contains_null_pointers(void)


/*
 * AutoDoc: Linear check used before invoking crypto helpers. Given an array of pointers and a count, it
 * reports 1 as soon as it encounters a NULL slot, letting callers bail out if any required import
 * failed to resolve.
 */
#include "xzre_types.h"


undefined8 contains_null_pointers(long param_1,uint param_2)

{
  long lVar1;
  void **slot;
  
  lVar1 = 0;
  do {
    if (param_2 <= (uint)lVar1) {
      return 0;
    }
    lVar1 = lVar1 + 1;
  } while (*(long *)(param_1 + -8 + lVar1 * 8) != 0);
  return 1;
}

