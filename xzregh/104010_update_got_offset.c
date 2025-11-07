// /home/kali/xzre-ghidra/xzregh/104010_update_got_offset.c
// Function: update_got_offset @ 0x104010
// Calling convention: __stdcall
// Prototype: void __stdcall update_got_offset(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Stores the cpuid random-symbol GOT offset constant in the entry context so absolute addresses can be reconstructed without relocations. It pairs with `update_got_address` when the loader patches the resolver slot.
 */
#include "xzre_types.h"


void update_got_offset(elf_entry_ctx_t *ctx)

{
  (ctx->got_ctx).got_offset = _Llzma_block_buffer_decode_0;
  return;
}

