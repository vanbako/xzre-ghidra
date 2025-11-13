// /home/kali/xzre-ghidra/xzregh/104010_update_got_offset.c
// Function: update_got_offset @ 0x104010
// Calling convention: unknown
// Prototype: undefined update_got_offset(void)


/*
 * AutoDoc: Copies `_Llzma_block_buffer_decode_0` into `ctx->got_ctx.got_offset`, giving the loader a
 * reproducible base when translating between the baked relocation constants and runtime
 * addresses. It pairs with `update_got_address` during the cpuid GOT patch.
 */
#include "xzre_types.h"


void update_got_offset(long param_1)

{
  *(undefined8 *)(param_1 + 0x20) = _Llzma_block_buffer_decode_0;
  return;
}

