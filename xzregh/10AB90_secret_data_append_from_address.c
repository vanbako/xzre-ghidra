// /home/kali/xzre-ghidra/xzregh/10AB90_secret_data_append_from_address.c
// Function: secret_data_append_from_address @ 0x10AB90
// Calling convention: unknown
// Prototype: undefined secret_data_append_from_address(void)


/*
 * AutoDoc: Runs the singleton appender against either a provided code pointer or the caller's return address, letting hooks fingerprint themselves at runtime. The recorded bits contribute to the secret_data blob used for payload decryption.
 */
#include "xzre_types.h"


undefined1  [16]
secret_data_append_from_address
          (ulong param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined8 param_5
          )

{
  int iVar1;
  ulong uVar2;
  undefined1 auVar3 [16];
  ulong unaff_retaddr;
  
  uVar2 = param_1;
  if (param_1 < 2) {
    uVar2 = unaff_retaddr;
  }
  iVar1 = secret_data_append_singleton(param_1,uVar2,param_2,param_3,param_4);
  auVar3._1_7_ = 0;
  auVar3[0] = 0 < iVar1;
  auVar3._8_8_ = param_5;
  return auVar3;
}

