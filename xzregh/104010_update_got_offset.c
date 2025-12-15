// /home/kali/xzre-ghidra/xzregh/104010_update_got_offset.c
// Function: update_got_offset @ 0x104010
// Calling convention: __stdcall
// Prototype: void __stdcall update_got_offset(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Copies `_Llzma_block_buffer_decode_0` (another relocation-safe symbol embedded beside the fake function table) into `ctx->got_ctx.got_base_offset`.
 * Every GOT helper subtracts this anchor when converting the baked relocation constants back into runtime addresses, so the helper
 * keeps the base in sync after IFUNC code mutates the resolver stack.
 */
#include "xzre_types.h"

void update_got_offset(elf_entry_ctx_t *ctx)

{
  // AutoDoc: Re-anchor the GOT math to `_Llzma_block_buffer_decode_0` so later helpers subtract the same baseline.
  (ctx->got_ctx).got_base_offset = _Llzma_block_buffer_decode_0;
  return;
}

