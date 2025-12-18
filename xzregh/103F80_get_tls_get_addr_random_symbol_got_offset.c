// /home/kali/xzre-ghidra/xzregh/103F80_get_tls_get_addr_random_symbol_got_offset.c
// Function: get_tls_get_addr_random_symbol_got_offset @ 0x103F80
// Calling convention: __stdcall
// Prototype: ptrdiff_t __stdcall get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Seeds the GOT/TLS bookkeeping used by `update_got_address`. It writes the 0x2600 opcode tag (0x25ff+1, matching the `ff 25` PLT jmp word) into
 * `ctx->got_ctx.tls_got_entry`, mirrors the relocation-safe `elf_functions_offset` into both its return value and `ctx->got_ctx.got_base_offset`, and leaves the
 * context ready for PLT parsing.
 */

#include "xzre_types.h"

ptrdiff_t get_tls_get_addr_random_symbol_got_offset(elf_entry_ctx_t *ctx)

{
  ptrdiff_t seeded_offset;
  
  // AutoDoc: Store the 0x25ff+1 opcode tag so `update_got_address` can verify the stub begins with `ff 25` before trusting the disp32.
  (ctx->got_ctx).tls_got_entry = (void *)0x2600;
  // AutoDoc: Return the relocation baseline published in the fake function table so callers and the context agree on the same offset.
  seeded_offset = elf_functions_offset;
  // AutoDoc: Copy the same baseline into `got_base_offset`; helpers like `update_got_address` subtract it when turning sentinel symbols into live pointers.
  (ctx->got_ctx).got_base_offset = elf_functions_offset;
  return seeded_offset;
}

