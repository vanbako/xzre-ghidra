// /home/kali/xzre-ghidra/xzregh/107170_contains_null_pointers.c
// Function: contains_null_pointers @ 0x107170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall contains_null_pointers(void * * pointers, uint num_pointers)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief checks if the given array of pointers contains any NULL pointer
 *
 *   @param pointers array of pointers to check
 *   @param num_pointers number of pointers to check
 *   @return BOOL TRUE if @p pointers contains any NULL pointer, FALSE if all pointers are non-NULL
 */

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

