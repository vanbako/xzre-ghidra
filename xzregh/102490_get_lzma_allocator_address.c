// /home/kali/xzre-ghidra/xzregh/102490_get_lzma_allocator_address.c
// Function: get_lzma_allocator_address @ 0x102490
// Calling convention: __stdcall
// Prototype: fake_lzma_allocator_t * __stdcall get_lzma_allocator_address(void)
/*
 * AutoDoc: Manual pointer arithmetic that recovers the runtime address of the fake `fake_lzma_allocator_t` blob without requiring relocatable absolute addresses. The compiler emits a sentinel (`fake_lzma_allocator`) followed by padding, so this helper starts at that symbol and steps through the struct 12 times, effectively adding the baked-in 0x160-byte offset that lands on the real allocator instance the loader populated at build time.
 */

#include "xzre_types.h"


fake_lzma_allocator_t * get_lzma_allocator_address(void)

{
  uint local_14;
  fake_lzma_allocator_t *local_10;
  
  local_10 = (fake_lzma_allocator_t *)fake_lzma_allocator;
  for (local_14 = 0; local_14 < 0xc; local_14 = local_14 + 1) {
    local_10 = local_10 + 1;
  }
  return local_10;
}

