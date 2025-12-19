// /home/kali/xzre-ghidra/xzregh/104010_cache_got_base_offset_from_cpuid_anchor.c
// Function: cache_got_base_offset_from_cpuid_anchor @ 0x104010
// Calling convention: __stdcall
// Prototype: void __stdcall cache_got_base_offset_from_cpuid_anchor(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Refreshes `ctx->got_ctx.got_base_offset` with the relocation-safe constant that turns the `cpuid_random_symbol` anchor into a `.got.plt` base pointer
 * (`got_base = cpuid_random_symbol_addr - got_base_offset`). Stage one calls this before patching so later GOT math subtracts the same baseline.
 */

#include "xzre_types.h"

void cache_got_base_offset_from_cpuid_anchor(elf_entry_ctx_t *ctx)

{
  // AutoDoc: Refresh the `.got.plt` baseline constant used when deriving the GOT base from the cpuid anchor.
  (ctx->got_ctx).got_base_offset = _Llzma_block_buffer_decode_0;
  return;
}

