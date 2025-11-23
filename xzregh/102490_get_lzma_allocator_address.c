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
  uint slot_idx;
  fake_lzma_allocator_t *allocator_cursor;
  
  // AutoDoc: Start from the relocation-safe sentinel the compiler left embedded right before the real allocator blob.
  allocator_cursor = (fake_lzma_allocator_t *)fake_lzma_allocator;
  // AutoDoc: Walk 12 struct slots (~0x160 bytes) forward to reach the live allocator instance stage two writes.
  for (slot_idx = 0; slot_idx < 0xc; slot_idx = slot_idx + 1) {
    allocator_cursor = allocator_cursor + 1;
  }
  return allocator_cursor;
}

