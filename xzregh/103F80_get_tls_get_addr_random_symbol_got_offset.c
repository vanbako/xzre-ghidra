// /home/kali/xzre-ghidra/xzregh/103F80_get_tls_get_addr_random_symbol_got_offset.c
// Function: get_tls_get_addr_random_symbol_got_offset @ 0x103F80
// Calling convention: __stdcall
// Prototype: ptrdiff_t __stdcall get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t * ctx)
/*
 * AutoDoc: Seeds the entry context's GOT base and offset with the relocation constants tied to the canned `__tls_get_addr` symbol. Later code uses those values as the starting point when walking the PLT stub to discover the true GOT entry.
 */

#include "xzre_types.h"


ptrdiff_t get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t *ctx)

{
  ptrdiff_t pVar1;
  
  (ctx->got_ctx).got_ptr = (void *)0x2600;
  pVar1 = elf_functions_offset;
  (ctx->got_ctx).got_offset = elf_functions_offset;
  return pVar1;
}

