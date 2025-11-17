// /home/kali/xzre-ghidra/xzregh/107190_chacha_decrypt.c
// Function: chacha_decrypt @ 0x107190
// Calling convention: __stdcall
// Prototype: BOOL __stdcall chacha_decrypt(u8 * in, int inl, u8 * key, u8 * iv, u8 * out, imported_funcs_t * funcs)


/*
 * AutoDoc: Checks the caller supplied pointers/lengths, verifies that the EVP entries in imported_funcs are non-null
 * (contains_null_pointers), allocates an EVP_CIPHER_CTX, and runs EVP_chacha20 through Init/Update/Final. The helper enforces that
 * the final output length never exceeds the input, frees the context on every path, and reports TRUE only when all EVP calls
 * succeed.
 */

#include "xzre_types.h"

BOOL chacha_decrypt(u8 *in,int inl,u8 *key,u8 *iv,u8 *out,imported_funcs_t *funcs)

{
  pfn_EVP_DecryptInit_ex_t decrypt_init;
  BOOL has_missing_imports;
  int decrypt_status;
  EVP_CIPHER_CTX *ctx;
  const EVP_CIPHER *chacha_cipher;
  imported_funcs_t *imports;
  int outl;
  
  outl = 0;
  if (((((in != (u8 *)0x0) && (inl != 0)) && (iv != (u8 *)0x0)) &&
      ((out != (u8 *)0x0 && (funcs != (imported_funcs_t *)0x0)))) &&
     ((imports = funcs, has_missing_imports = contains_null_pointers(&funcs->EVP_CIPHER_CTX_new,6), has_missing_imports == FALSE
      && (ctx = (*imports->EVP_CIPHER_CTX_new)(), ctx != (EVP_CIPHER_CTX *)0x0)))) {
    decrypt_init = funcs->EVP_DecryptInit_ex;
    chacha_cipher = (*funcs->EVP_chacha20)();
    decrypt_status = (*decrypt_init)(ctx,chacha_cipher,(ENGINE *)0x0,key,iv);
    if (decrypt_status == 1) {
      decrypt_status = (*funcs->EVP_DecryptUpdate)(ctx,out,&outl,in,inl);
      if (((decrypt_status == 1) && (-1 < outl)) &&
         ((decrypt_status = (*funcs->EVP_DecryptFinal_ex)(ctx,out + outl,&outl), decrypt_status == 1 &&
          ((-1 < outl && ((uint)outl <= (uint)inl)))))) {
        (*funcs->EVP_CIPHER_CTX_free)(ctx);
        return TRUE;
      }
    }
    if (funcs->EVP_CIPHER_CTX_free != (pfn_EVP_CIPHER_CTX_free_t)0x0) {
      (*funcs->EVP_CIPHER_CTX_free)(ctx);
    }
  }
  return FALSE;
}

