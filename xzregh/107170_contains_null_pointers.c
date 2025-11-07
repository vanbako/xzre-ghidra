// /home/kali/xzre-ghidra/xzregh/107170_contains_null_pointers.c
// Function: contains_null_pointers @ 0x107170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall contains_null_pointers(void * * pointers, uint num_pointers)
/*
 * AutoDoc: Scans a pointer array for NULL entries. The crypto helpers call it to ensure every required OpenSSL import was resolved before attempting decrypt or verify operations.
 */

#include "xzre_types.h"


BOOL contains_null_pointers(void **pointers,uint num_pointers)

{
  void **ppvVar1;
  long lVar2;
  
  lVar2 = 0;
  do {
    if (num_pointers <= (uint)lVar2) {
      return 0;
    }
    ppvVar1 = pointers + lVar2;
    lVar2 = lVar2 + 1;
  } while (*ppvVar1 != (void *)0x0);
  return 1;
}

