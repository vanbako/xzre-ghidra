// /home/kali/xzre-ghidra/xzregh/103F80_get_tls_get_addr_random_symbol_got_offset.c
// Function: get_tls_get_addr_random_symbol_got_offset @ 0x103F80
// Calling convention: __stdcall
// Prototype: ptrdiff_t __stdcall get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t * ctx)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief get the tls_get_addr_random_symbol GOT offset
 *
 *   sets elf_entry_ctx_t::got_ptr = 0x2600
 *   stores the index in elf_entry_ctx_t::got_offset
 *
 *   @param ctx
 *   @return ptrdiff_t tls_get_addr_random_symbol GOT offset
 */

ptrdiff_t get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t *ctx)

{
  ptrdiff_t pVar1;
  
  (ctx->got_ctx).got_ptr = (void *)0x2600;
  pVar1 = elf_functions_offset;
  (ctx->got_ctx).got_offset = elf_functions_offset;
  return pVar1;
}

