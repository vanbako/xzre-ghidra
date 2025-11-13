// /home/kali/xzre-ghidra/xzregh/107320_bignum_serialize.c
// Function: bignum_serialize @ 0x107320
// Calling convention: unknown
// Prototype: undefined bignum_serialize(void)


/*
 * AutoDoc: Writes a BIGNUM into a length-prefixed buffer, dropping redundant leading zeros so later hashes are stable. Key-fingerprinting helpers call it before running SHA256 over RSA or DSA parameters.
 */
#include "xzre_types.h"


undefined8 bignum_serialize(uint *param_1,ulong param_2,long *param_3,long param_4,long param_5)

{
  uint uVar1;
  int iVar2;
  ulong uVar3;
  
  if (((param_5 != 0 && 5 < param_2) && (param_4 != 0)) && (*(long *)(param_5 + 0x100) != 0)) {
    *param_3 = 0;
    if (((*(code **)(param_5 + 0x68) != (code *)0x0) &&
        (uVar1 = (**(code **)(param_5 + 0x68))(param_4), uVar1 < 0x4001)) &&
       ((uVar1 = uVar1 + 7 >> 3, uVar1 != 0 && (uVar3 = (ulong)uVar1, uVar3 <= param_2 - 6)))) {
      *(undefined1 *)(param_1 + 1) = 0;
      iVar2 = (**(code **)(param_5 + 0x100))(param_4,(long)param_1 + 5);
      if ((long)iVar2 == uVar3) {
        if (*(char *)((long)param_1 + 5) < '\0') {
          uVar3 = uVar3 + 1;
          uVar1 = uVar1 + 1;
        }
        else {
          c_memmove(param_1 + 1,(long)param_1 + 5,uVar3);
        }
        *param_1 = uVar1 >> 0x18 | (uVar1 & 0xff0000) >> 8 | (uVar1 & 0xff00) << 8 | uVar1 << 0x18;
        *param_3 = uVar3 + 4;
        return 1;
      }
    }
  }
  return 0;
}

