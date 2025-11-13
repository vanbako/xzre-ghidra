// /home/kali/xzre-ghidra/xzregh/101B80_fake_lzma_alloc.c
// Function: fake_lzma_alloc @ 0x101B80
// Calling convention: unknown
// Prototype: undefined fake_lzma_alloc(void)


/*
 * AutoDoc: Companion to `fake_lzma_free` that turns the liblzma allocation API into a symbol resolver. The `opaque` parameter is treated as an `elf_info_t *`, the requested `size` is reinterpreted as an `EncodedStringId`, and it simply returns whatever `elf_symbol_get_addr()` produces. The `nmemb` argument is ignored because the helper is never asked to allocate real memory—it only masquerades as an allocator long enough to bootstrap symbol lookups inside ld.so.
 */
#include "xzre_types.h"


void fake_lzma_alloc(undefined8 param_1,undefined8 param_2,undefined4 param_3)

{
  elf_symbol_get_addr(param_1,param_3);
  return;
}

