// /home/kali/xzre-ghidra/xzregh/104060_get_fake_lzma_allocator.c
// Function: get_fake_lzma_allocator @ 0x104060
// Calling convention: __stdcall
// Prototype: lzma_allocator * __stdcall get_fake_lzma_allocator(void)


/*
 * AutoDoc: Convenience wrapper that returns a `lzma_allocator *` pointing at the embedded allocator table inside the relocated `fake_lzma_allocator_t` blob. Callers patch `allocator->opaque` with the `elf_info_t` they want to query and then use `lzma_alloc()`/`lzma_free()` so the fake callbacks (`fake_lzma_alloc_resolve_symbol`, `fake_lzma_free_noop`) can resolve imports via `elf_gnu_hash_lookup_symbol_addr()`.
 */

#include "xzre_types.h"

lzma_allocator * get_fake_lzma_allocator(void)

{
  fake_lzma_allocator_t *fake_allocator;
  
  // AutoDoc: Locate the relocated fake allocator blob (see `get_fake_lzma_allocator_blob()`) before exposing its nested callbacks.
  fake_allocator = get_fake_lzma_allocator_blob();
  // AutoDoc: Return the embedded `lzma_allocator` so callers can set `opaque` and pass it into liblzma allocation helpers.
  return &fake_allocator->allocator;
}

