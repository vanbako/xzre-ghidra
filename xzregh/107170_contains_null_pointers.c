// /home/kali/xzre-ghidra/xzregh/107170_contains_null_pointers.c
// Function: contains_null_pointers @ 0x107170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall contains_null_pointers(void * * pointers, uint num_pointers)


/*
 * AutoDoc: Linear check used before invoking crypto helpers. Given an array of pointers and a count, it reports 1 as soon as it encounters
 * a NULL slot, letting callers bail out if any required import failed to resolve.
 */

#include "xzre_types.h"

BOOL contains_null_pointers(void **pointers,uint num_pointers)

{
  void **slot;
  size_t index;
  
  index = 0;
  do {
    if (num_pointers <= (uint)index) {
      return FALSE;
    }
    slot = pointers + index;
    index = index + 1;
  } while (*slot != (void *)0x0);
  return TRUE;
}

