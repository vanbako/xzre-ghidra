// /home/kali/xzre-ghidra/xzregh/101B80_fake_lzma_alloc.c
// Function: fake_lzma_alloc @ 0x101B80
// Calling convention: __stdcall
// Prototype: void * __stdcall fake_lzma_alloc(void * opaque, size_t nmemb, size_t size)


/*
 * AutoDoc: Companion to `fake_lzma_free` that turns the liblzma allocation API into a symbol resolver. The `opaque` parameter is treated as
 * an `elf_info_t *`, the requested `size` is reinterpreted as an `EncodedStringId`, and it simply returns whatever
 * `elf_symbol_get_addr()` produces. The `nmemb` argument is ignored because the helper is never asked to allocate real memory—it
 * only masquerades as an allocator long enough to bootstrap symbol lookups inside ld.so.
 */

#include "xzre_types.h"

void * fake_lzma_alloc(void *opaque,size_t nmemb,size_t size)

{
  void *symbol_addr;
  
  // AutoDoc: Treat `opaque` as `elf_info_t *` and `size` as the EncodedStringId the loader wants resolved.
  symbol_addr = elf_symbol_get_addr((elf_info_t *)opaque,(EncodedStringId)size);
  return symbol_addr;
}

