// /home/kali/xzre-ghidra/xzregh/103F80_seed_got_ctx_for_tls_get_addr_parse.c
// Function: seed_got_ctx_for_tls_get_addr_parse @ 0x103F80
// Calling convention: __stdcall
// Prototype: ptrdiff_t __stdcall seed_got_ctx_for_tls_get_addr_parse(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Seeds the GOT/TLS bookkeeping used by `resolve_gotplt_base_from_tls_get_addr`. It writes the 0x2600 opcode tag (0x25ff+1, matching the `ff 25` PLT jmp word) into
 * `ctx->got_ctx.tls_got_entry`, mirrors the relocation-safe `elf_functions_offset` into both its return value and `ctx->got_ctx.got_base_offset`, and leaves the
 * context ready for PLT parsing.
 */

#include "xzre_types.h"

ptrdiff_t seed_got_ctx_for_tls_get_addr_parse(elf_entry_ctx_t *ctx)

{
  ptrdiff_t seeded_offset;
  
  // AutoDoc: Store the 0x25ff+1 opcode tag so `resolve_gotplt_base_from_tls_get_addr` can verify the stub begins with `ff 25` before trusting the disp32.
  (ctx->got_ctx).tls_got_entry = (void *)0x2600;
  // AutoDoc: Return the relocation baseline published in the fake function table so callers and the context agree on the same offset.
  seeded_offset = elf_functions_offset;
  // AutoDoc: Copy the same baseline into `got_base_offset`; helpers like `resolve_gotplt_base_from_tls_get_addr` subtract it when turning sentinel symbols into live pointers.
  (ctx->got_ctx).got_base_offset = elf_functions_offset;
  return seeded_offset;
}

