// /home/kali/xzre-ghidra/xzregh/104060_get_lzma_allocator.c
// Function: get_lzma_allocator @ 0x104060
// Calling convention: unknown
// Prototype: undefined get_lzma_allocator(void)


/*
 * AutoDoc: Returns the `lzma_allocator` sub-structure embedded inside the fake allocator blob. Callers use it when they need to hand liblzma-style callbacks to another routine (e.g., passing an allocator into a liblzma API) while still pointing `opaque` at the implant's `elf_info_t`.
 */
#include "xzre_types.h"


long get_lzma_allocator(void)

{
  long lVar1;
  
  lVar1 = get_lzma_allocator_address(0x21);
  return lVar1 + 8;
}

