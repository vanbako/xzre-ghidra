// /home/kali/xzre-ghidra/xzregh/107170_contains_null_pointers.c
// Function: contains_null_pointers @ 0x107170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall contains_null_pointers(void * * pointers, uint num_pointers)


/*
 * AutoDoc: Linear check used before invoking crypto helpers. Given an array of pointers and a count, it
 * reports 1 as soon as it encounters a NULL slot, letting callers bail out if any required import
 * failed to resolve.
 */
#include "xzre_types.h"


BOOL contains_null_pointers(void **pointers,uint num_pointers)

{
  void **ppvVar1;
  long lVar2;
  void **slot;
  
  lVar2 = 0;
  do {
    if (num_pointers <= (uint)lVar2) {
      return FALSE;
    }
    ppvVar1 = pointers + lVar2;
    lVar2 = lVar2 + 1;
  } while (*ppvVar1 != (void *)0x0);
  return TRUE;
}

