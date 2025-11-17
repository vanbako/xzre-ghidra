// /home/kali/xzre-ghidra/xzregh/1074B0_count_pointers.c
// Function: count_pointers @ 0x1074B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall count_pointers(void * * ptrs, u64 * count_out, libc_imports_t * funcs)


/*
 * AutoDoc: Uses `malloc_usable_size()` to measure a pointer array and counts consecutive non-NULL entries until it hits either a NULL or
 * the allocation boundary. Sensitive-data heuristics call it when walking sshd tables whose length isn’t stored explicitly.
 */

#include "xzre_types.h"

BOOL count_pointers(void **ptrs,u64 *count_out,libc_imports_t *funcs)

{
  BOOL BVar1;
  size_t block_size;
  ulong index;
  ulong count;
  
  if (((ptrs == (void **)0x0) || (funcs == (libc_imports_t *)0x0)) ||
     (funcs->malloc_usable_size == (pfn_malloc_usable_size_t)0x0)) {
    return FALSE;
  }
  block_size = (*funcs->malloc_usable_size)(ptrs);
  if (block_size - 8 < 0x80) {
    index = 0;
    do {
      count = index;
      if (ptrs[index] == (void *)0x0) break;
      index = (ulong)((int)index + 1);
      count = block_size >> 3;
    } while (index < block_size >> 3);
    *count_out = count;
    BVar1 = TRUE;
  }
  else {
    BVar1 = FALSE;
  }
  return BVar1;
}

