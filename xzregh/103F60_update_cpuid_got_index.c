// /home/kali/xzre-ghidra/xzregh/103F60_update_cpuid_got_index.c
// Function: update_cpuid_got_index @ 0x103F60
// Calling convention: __stdcall
// Prototype: void __stdcall update_cpuid_got_index(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Copies the baked cpuid `.got.plt` slot index constant into `ctx->got_ctx.cpuid_slot_index`. That slot index identifies the cpuid
 * IFUNC entry within liblzma’s GOT so setup code can stride directly to it when overwriting the resolver.
 */

#include "xzre_types.h"

void update_cpuid_got_index(elf_entry_ctx_t *ctx)

{
  // AutoDoc: Cache the baked cpuid `.got.plt` index so later code patches the intended slot.
  (ctx->got_ctx).cpuid_slot_index = (u64)PTR_PTR_0010ca98;
  return;
}

