// /home/kali/xzre-ghidra/xzregh/1074B0_count_pointers.c
// Function: count_pointers @ 0x1074B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall count_pointers(void * * ptrs, u64 * count_out, libc_imports_t * funcs)
/*
 * AutoDoc: Uses malloc_usable_size to count populated pointer slots in a heap block without knowing the allocation size. Secret-data heuristics use it when walking monitor tables extracted from sshd memory.
 */

#include "xzre_types.h"


BOOL count_pointers(void **ptrs,u64 *count_out,libc_imports_t *funcs)

{
  BOOL BVar1;
  size_t nWords;
  size_t i;
  size_t blockSize;
  
  if (((ptrs == (void **)0x0) || (funcs == (libc_imports_t *)0x0)) ||
     (funcs->malloc_usable_size == (_func_17 *)0x0)) {
    return 0;
  }
  nWords = (*funcs->malloc_usable_size)(ptrs);
  if (nWords - 8 < 0x80) {
    i = 0;
    do {
      blockSize = i;
      if (ptrs[i] == (void *)0x0) break;
      i = (size_t)((int)i + 1);
      blockSize = nWords >> 3;
    } while (i < nWords >> 3);
    *count_out = blockSize;
    BVar1 = 1;
  }
  else {
    BVar1 = 0;
  }
  return BVar1;
}

