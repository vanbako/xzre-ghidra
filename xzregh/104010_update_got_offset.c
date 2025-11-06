// /home/kali/xzre-ghidra/xzregh/104010_update_got_offset.c
// Function: update_got_offset @ 0x104010
// Calling convention: __stdcall
// Prototype: void __stdcall update_got_offset(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief updates the offset to the GOT
 *
 *   the offset is the distance to the GOT relative to the address of the symbol cpuid_random_symbol
 *   this value is stored in @ref elf_entry_ctx_t.got_ctx.got_offset
 *
 *   @param ctx
 *   @return ptrdiff_t
 *
 * Upstream implementation excerpt (xzre/xzre_code/update_got_offset.c):
 *     void update_got_offset(elf_entry_ctx_t *ctx){
 *     	ctx->got_ctx.got_offset = cpuid_reloc_consts.cpuid_random_symbol_got_offset;
 *     }
 */

void update_got_offset(elf_entry_ctx_t *ctx)

{
  (ctx->got_ctx).got_offset = _Llzma_block_buffer_decode_0;
  return;
}

