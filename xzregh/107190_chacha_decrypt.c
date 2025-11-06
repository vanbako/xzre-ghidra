// /home/kali/xzre-ghidra/xzregh/107190_chacha_decrypt.c
// Function: chacha_decrypt @ 0x107190
// Calling convention: __stdcall
// Prototype: BOOL __stdcall chacha_decrypt(u8 * in, int inl, u8 * key, u8 * iv, u8 * out, imported_funcs_t * funcs)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief decrypts a buffer with chacha20
 *
 *   @param in the input buffer to decrypt
 *   @param inl the length of the input buffer
 *   @param key the 256bit chacha key
 *   @param iv the 128bit chacha iv
 *   @param out the output buffer
 *   @param funcs OpenSSL imported functions
 *   @return BOOL TRUE if successful, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/chacha_decrypt.c):
 *     BOOL chacha_decrypt(
 *     	u8 *in, int inl,
 *     	u8 *key, u8 *iv,
 *     	u8 *out, imported_funcs_t *funcs
 *     ){
 *     	int outl = 0;
 *     	if(!in || inl <= 0 || !iv || !out || !funcs) {
 *     		return FALSE;
 *     	}
 *     	if(contains_null_pointers((void **)&funcs->EVP_CIPHER_CTX_new, 6)){
 *     		return FALSE;
 *     	}
 *     	EVP_CIPHER_CTX *ctx = funcs->EVP_CIPHER_CTX_new();
 *     	if(!ctx){
 *     		return FALSE;
 *     	}
 *     	const EVP_CIPHER *cipher = EVP_chacha20();
 *     	if(funcs->EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) == TRUE
 *     	  && funcs->EVP_DecryptUpdate(ctx, out, &outl, in, inl) == TRUE
 *     	  && outl >= 0
 *     	){
 *     		if(funcs->EVP_DecryptFinal_ex(ctx, &out[outl], &outl) == TRUE
 *     		 && outl >= 0 && inl >= outl
 *     		){
 *     			funcs->EVP_CIPHER_CTX_free(ctx);
 *     			return TRUE;
 *     		}
 *     	}
 *     	if(funcs->EVP_CIPHER_CTX_free){
 *     		funcs->EVP_CIPHER_CTX_free(ctx);
 *     	}
 *     	return FALSE;
 *     }
 */

BOOL chacha_decrypt(u8 *in,int inl,u8 *key,u8 *iv,u8 *out,imported_funcs_t *funcs)

{
  _func_47 *p_Var1;
  int outl_1;
  int outl_2;
  int outl;
  BOOL BVar2;
  EVP_CIPHER_CTX *ctx;
  EVP_CIPHER *cipher;
  imported_funcs_t *piVar3;
  uint local_3c [3];
  
  local_3c[0] = 0;
  if (((((in != (u8 *)0x0) && (inl != 0)) && (iv != (u8 *)0x0)) &&
      ((out != (u8 *)0x0 && (funcs != (imported_funcs_t *)0x0)))) &&
     ((piVar3 = funcs, BVar2 = contains_null_pointers(&funcs->EVP_CIPHER_CTX_new,6), BVar2 == 0 &&
      (ctx = (*piVar3->EVP_CIPHER_CTX_new)(), ctx != (EVP_CIPHER_CTX *)0x0)))) {
    p_Var1 = funcs->EVP_DecryptInit_ex;
    cipher = (*funcs->EVP_chacha20)();
    outl_1 = (*p_Var1)(ctx,cipher,(ENGINE *)0x0,key,iv);
    if (outl_1 == 1) {
      outl_2 = (*funcs->EVP_DecryptUpdate)(ctx,out,(int *)local_3c,in,inl);
      if (((outl_2 == 1) && (-1 < (int)local_3c[0])) &&
         ((outl = (*funcs->EVP_DecryptFinal_ex)(ctx,out + (int)local_3c[0],(int *)local_3c),
          outl == 1 && ((-1 < (int)local_3c[0] && (local_3c[0] <= (uint)inl)))))) {
        (*funcs->EVP_CIPHER_CTX_free)(ctx);
        return 1;
      }
    }
    if (funcs->EVP_CIPHER_CTX_free != (_func_50 *)0x0) {
      (*funcs->EVP_CIPHER_CTX_free)(ctx);
    }
  }
  return 0;
}

