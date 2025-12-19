// /home/kali/xzre-ghidra/xzregh/107190_chacha20_decrypt.c
// Function: chacha20_decrypt @ 0x107190
// Calling convention: __stdcall
// Prototype: BOOL __stdcall chacha20_decrypt(u8 * in, int inl, u8 * key, u8 * iv, u8 * out, imported_funcs_t * funcs)


/*
 * AutoDoc: Validates caller buffers and imported EVP symbols, allocates a temporary EVP_CIPHER_CTX, runs the ChaCha20 decrypt pipeline (Init -> Update -> Final), enforces that the accumulated plaintext never exceeds the input length, and tears the context down on every path. Only a full set of successful EVP calls returns TRUE.
 */

#include "xzre_types.h"

BOOL chacha20_decrypt(u8 *in,int inl,u8 *key,u8 *iv,u8 *out,imported_funcs_t *funcs)

{
  pfn_EVP_DecryptInit_ex_t decrypt_init;
  BOOL has_missing_imports;
  int decrypt_status;
  EVP_CIPHER_CTX *cipher_ctx;
  const EVP_CIPHER *chacha_cipher;
  imported_funcs_t *imports;
  int bytes_written;
  
  bytes_written = 0;
  if (((((in != (u8 *)0x0) && (inl != 0)) && (iv != (u8 *)0x0)) &&
      ((out != (u8 *)0x0 && (funcs != (imported_funcs_t *)0x0)))) &&
     // AutoDoc: Refuse to touch the cipher until every EVP dependency (CTX allocators, cipher lookup, init/update/final, free) is live.
     ((imports = funcs, has_missing_imports = pointer_array_has_null(&funcs->EVP_CIPHER_CTX_new,6), has_missing_imports == FALSE
      // AutoDoc: Allocate a scratch EVP_CIPHER_CTX for the decrypt; any failure short-circuits the helper.
      && (cipher_ctx = (*imports->EVP_CIPHER_CTX_new)(), cipher_ctx != (EVP_CIPHER_CTX *)0x0)))) {
    decrypt_init = funcs->EVP_DecryptInit_ex;
    chacha_cipher = (*funcs->EVP_chacha20)();
    // AutoDoc: Prime the context with EVP_chacha20 (no ENGINE override) before streaming bytes.
    decrypt_status = (*decrypt_init)(cipher_ctx,chacha_cipher,(ENGINE *)0x0,key,iv);
    if (decrypt_status == 1) {
      // AutoDoc: Process the entire ciphertext in one shot and remember how many bytes were produced so Final can append safely.
      decrypt_status = (*funcs->EVP_DecryptUpdate)(cipher_ctx,out,&bytes_written,in,inl);
      if (((decrypt_status == 1) && (-1 < bytes_written)) &&
         // AutoDoc: Finalise the decrypt and insist the trailing chunk neither underflows nor overruns the caller-supplied buffer.
         ((decrypt_status = (*funcs->EVP_DecryptFinal_ex)(cipher_ctx,out + bytes_written,&bytes_written), decrypt_status == 1
          && ((-1 < bytes_written && ((uint)bytes_written <= (uint)inl)))))) {
        (*funcs->EVP_CIPHER_CTX_free)(cipher_ctx);
        return TRUE;
      }
    }
    // AutoDoc: Best-effort cleanup: even on failure it tries to free the context when the import table exposes EVP_CIPHER_CTX_free.
    if (funcs->EVP_CIPHER_CTX_free != (pfn_EVP_CIPHER_CTX_free_t)0x0) {
      (*funcs->EVP_CIPHER_CTX_free)(cipher_ctx);
    }
  }
  return FALSE;
}

