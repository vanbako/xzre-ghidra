// /home/kali/xzre-ghidra/xzregh/104060_get_lzma_allocator.c
// Function: get_lzma_allocator @ 0x104060
// Calling convention: __stdcall
// Prototype: lzma_allocator * __stdcall get_lzma_allocator(void)


/*
 * AutoDoc: Returns the `lzma_allocator` sub-structure embedded inside the fake allocator blob. Callers use it when they need to hand liblzma-style callbacks to another routine (e.g., passing an allocator into a liblzma API) while still pointing `opaque` at the implant's `elf_info_t`.
 */

#include "xzre_types.h"

lzma_allocator * get_lzma_allocator(void)

{
  fake_lzma_allocator_t *pfVar1;
  
  pfVar1 = get_lzma_allocator_address();
  return &pfVar1->allocator;
}

