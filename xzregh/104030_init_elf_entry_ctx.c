// /home/kali/xzre-ghidra/xzregh/104030_init_elf_entry_ctx.c
// Function: init_elf_entry_ctx @ 0x104030
// Calling convention: __stdcall
// Prototype: void __stdcall init_elf_entry_ctx(elf_entry_ctx_t * ctx)


void init_elf_entry_ctx(elf_entry_ctx_t *ctx)

{
  ctx->symbol_ptr = &_Lrc_read_destroy;
  (ctx->got_ctx).return_address = (void *)ctx->frame_address[3];
  update_got_offset(ctx);
  update_cpuid_got_index(ctx);
  (ctx->got_ctx).got_ptr = (void *)0x0;
  return;
}

