// /home/kali/xzre-ghidra/xzregh/107190_chacha_decrypt.c
// Function: chacha_decrypt @ 0x107190
// Calling convention: __stdcall
// Prototype: BOOL __stdcall chacha_decrypt(u8 * in, int inl, u8 * key, u8 * iv, u8 * out, imported_funcs_t * funcs)


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

