// /home/kali/xzre-ghidra/xzregh/103F60_update_cpuid_got_index.c
// Function: update_cpuid_got_index @ 0x103F60
// Calling convention: __stdcall
// Prototype: void __stdcall update_cpuid_got_index(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Copies the relocation constants baked into `tls_get_addr_reloc_consts` into
 * `ctx->got_ctx.cpuid_fn`. That value is the GOT index of the cpuid resolver inside liblzma, so
 * later code can patch the correct slot without rescanning the PLT stub.
 */

#include "xzre_types.h"

void update_cpuid_got_index(elf_entry_ctx_t *ctx)

{
  (ctx->got_ctx).cpuid_fn = PTR_PTR_0010ca98;
  return;
}

