// /home/kali/xzre-ghidra/xzregh/104030_init_elf_entry_ctx.c
// Function: init_elf_entry_ctx @ 0x104030
// Calling convention: __stdcall
// Prototype: void __stdcall init_elf_entry_ctx(elf_entry_ctx_t * ctx)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief initialises the elf_entry_ctx_t
 *
 *   stores the address of the symbol cpuid_random_symbol in elf_entry_ctx_t::symbol_ptr
 *   stores the return address of the function that called the IFUNC resolver which is a stack address in ld.so
 *   calls update_got_offset() to update elf_entry_ctx_t::got_offset
 *   calls update_cpuid_got_index() to update @ref elf_entry_ctx_t.got_ctx.cpuid_fn
 *
 *   @param ctx
 *
 * Upstream implementation excerpt (xzre/xzre_code/init_elf_entry_ctx.c):
 *     void init_elf_entry_ctx(elf_entry_ctx_t *ctx){
 *     	ctx->symbol_ptr = (void *)&cpuid_random_symbol;
 *     	ctx->got_ctx.return_address = (void *)ctx->frame_address[3];
 *     	update_got_offset(ctx);
 *     	update_cpuid_got_index(ctx);
 *     	ctx->got_ctx.got_ptr = NULL;
 *     }
 */

void init_elf_entry_ctx(elf_entry_ctx_t *ctx)

{
  ctx->symbol_ptr = &_Lrc_read_destroy;
  (ctx->got_ctx).return_address = (void *)ctx->frame_address[3];
  update_got_offset(ctx);
  update_cpuid_got_index(ctx);
  (ctx->got_ctx).got_ptr = (void *)0x0;
  return;
}

