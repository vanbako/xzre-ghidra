// /home/kali/xzre-ghidra/xzregh/103F80_get_tls_get_addr_random_symbol_got_offset.c
// Function: get_tls_get_addr_random_symbol_got_offset @ 0x103F80
// Calling convention: __stdcall
// Prototype: ptrdiff_t __stdcall get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Seeds `ctx->got_ctx.tls_got_entry` and `ctx->got_ctx.got_base_offset` with the relocation constants that stand in for the fake `__tls_get_addr`
 * symbol embedded in liblzma. The helper writes the sentinel GOT index (0x2600) into the context, mirrors `elf_functions_offset` into both
 * its return value and the GOT base, and hands those numbers to `update_got_address`, which replays the PLT stub to find the concrete GOT entry.
 */

#include "xzre_types.h"

ptrdiff_t get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t *ctx)

{
  ptrdiff_t seeded_offset;
  
  // AutoDoc: Prime the GOT context with the baked 0x2600 index; later disassembly insists the PLT stub still references this slot before patching it.
  (ctx->got_ctx).tls_got_entry = (void *)0x2600;
  // AutoDoc: Return the relocation baseline published in the fake function table so callers and the context agree on the same offset.
  seeded_offset = elf_functions_offset;
  // AutoDoc: Copy the same baseline into `got_base_offset`; helpers like `update_got_address` subtract it when turning sentinel symbols into live pointers.
  (ctx->got_ctx).got_base_offset = elf_functions_offset;
  return seeded_offset;
}

