// /home/kali/xzre-ghidra/xzregh/103F60_update_cpuid_got_index.c
// Function: update_cpuid_got_index @ 0x103F60
// Calling convention: __stdcall
// Prototype: void __stdcall update_cpuid_got_index(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Copies the relocation constant baked into `tls_get_addr_reloc_consts` into `ctx->got_ctx.cpuid_slot_index`. That index identifies the cpuid
 * IFUNC slot within liblzma’s GOT, letting later hooks patch the right entry without rescanning the PLT after relocations.
 */

#include "xzre_types.h"

void update_cpuid_got_index(elf_entry_ctx_t *ctx)

{
  // AutoDoc: Lift the precomputed cpuid GOT index out of the relocation table and cache it so GOT surgery happens at the correct slot.
  (ctx->got_ctx).cpuid_slot_index = (u64)PTR_PTR_0010ca98;
  return;
}

