// /home/kali/xzre-ghidra/xzregh/103F60_update_cpuid_got_index.c
// Function: update_cpuid_got_index @ 0x103F60
// Calling convention: unknown
// Prototype: undefined update_cpuid_got_index(void)


/*
 * AutoDoc: Copies the relocation constants baked into `tls_get_addr_reloc_consts` into
 * `ctx->got_ctx.cpuid_fn`. That value is the GOT index of the cpuid resolver inside liblzma, so
 * later code can patch the correct slot without rescanning the PLT stub.
 */
#include "xzre_types.h"


void update_cpuid_got_index(long param_1)

{
  *(undefined **)(param_1 + 0x18) = tls_get_addr_reloc_consts;
  return;
}

