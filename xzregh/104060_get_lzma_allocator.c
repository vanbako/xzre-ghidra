// /home/kali/xzre-ghidra/xzregh/104060_get_lzma_allocator.c
// Function: get_lzma_allocator @ 0x104060
// Calling convention: __stdcall
// Prototype: lzma_allocator * __stdcall get_lzma_allocator(void)


/*
 * AutoDoc: Wraps `get_lzma_allocator_address()` so the loader can recover the fake allocator blob at runtime and expose only its embedded `lzma_allocator` callbacks. This lets callers pass liblzma-compatible alloc/free hooks downstream while the surrounding bookkeeping (and `opaque` pointer to the implant's `elf_info_t`) stays hidden.
 */
#include "xzre_types.h"

lzma_allocator * get_lzma_allocator(void)

{
  fake_lzma_allocator_t *fake_allocator;
  
  // AutoDoc: Resolve the relocated fake allocator blob each time; the sentinel math accounts for where the loader staged it.
  fake_allocator = get_lzma_allocator_address();
  // AutoDoc: Publish just the nested liblzma callbacks so outside callers never learn about the rest of the blob.
  return &fake_allocator->allocator;
}

