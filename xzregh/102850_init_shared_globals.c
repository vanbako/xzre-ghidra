// /home/kali/xzre-ghidra/xzregh/102850_init_shared_globals.c
// Function: init_shared_globals @ 0x102850
// Calling convention: unknown
// Prototype: undefined init_shared_globals(void)


/*
 * AutoDoc: Seeds the shared global block with the mm/EVP hook entry points and a pointer to the lone
 * `global_ctx` instance. Every hook consults this block at runtime, so the function simply wires
 * the exported function pointers into the struct and returns success once the pointer checks
 * pass.
 */
#include "xzre_types.h"


undefined8 init_shared_globals(undefined8 *param_1)

{
  undefined8 uVar1;
  int status;
  
  uVar1 = 5;
  if (param_1 != (undefined8 *)0x0) {
    *param_1 = mm_answer_authpassword_hook;
    param_1[1] = hook_EVP_PKEY_set1_RSA;
    param_1[2] = &global_ctx;
    uVar1 = 0;
  }
  return uVar1;
}

