// /home/kali/xzre-ghidra/xzregh/103F80_get_tls_get_addr_random_symbol_got_offset.c
// Function: get_tls_get_addr_random_symbol_got_offset @ 0x103F80
// Calling convention: __stdcall
// Prototype: ptrdiff_t __stdcall get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Seeds `ctx->got_ctx.tls_got_entry` and `ctx->got_ctx.got_base_offset` with the canned values associated with the fake `__tls_get_addr`
 * symbol. The loader uses those numbers as the starting point for `update_got_address`, which refines them into the concrete GOT
 * entry address.
 */

#include "xzre_types.h"

ptrdiff_t get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t *ctx)

{
  ptrdiff_t got_offset;
  
  (ctx->got_ctx).tls_got_entry = (void *)0x2600;
  got_offset = elf_functions_offset;
  (ctx->got_ctx).got_base_offset = elf_functions_offset;
  return got_offset;
}

