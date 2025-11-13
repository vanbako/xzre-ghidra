// /home/kali/xzre-ghidra/xzregh/1072B0_sha256.c
// Function: sha256 @ 0x1072B0
// Calling convention: unknown
// Prototype: undefined sha256(void)


/*
 * AutoDoc: Invokes EVP_Digest/Evp_sha256 through the imported function table to hash arbitrary buffers. It fingerprints host keys and payload components so the command verifier can prove authenticity without linking libcrypto statically.
 */
#include "xzre_types.h"


bool sha256(long param_1,long param_2,undefined8 param_3,ulong param_4,long param_5)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  bool bVar4;
  
  if ((((param_1 == 0) || (param_2 == 0)) || (param_4 < 0x20)) || (param_5 == 0)) {
    bVar4 = FALSE;
  }
  else {
    pcVar1 = *(code **)(param_5 + 0xf0);
    bVar4 = FALSE;
    if ((pcVar1 != (code *)0x0) && (*(code **)(param_5 + 0x58) != (code *)0x0)) {
      uVar3 = (**(code **)(param_5 + 0x58))();
      iVar2 = (*pcVar1)(param_1,param_2,param_3,0,uVar3,0);
      bVar4 = iVar2 == 1;
    }
  }
  return bVar4;
}

