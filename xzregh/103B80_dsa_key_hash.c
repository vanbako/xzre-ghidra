// /home/kali/xzre-ghidra/xzregh/103B80_dsa_key_hash.c
// Function: dsa_key_hash @ 0x103B80
// Calling convention: unknown
// Prototype: undefined dsa_key_hash(void)


/*
 * AutoDoc: Serialises the DSA public parameters and computes a SHA-256 digest using the resolved libcrypto helpers. The monitor hooks use that fingerprint to recognise host keys referenced by attacker commands without leaking the private material.
 */
#include "xzre_types.h"


bool dsa_key_hash(long param_1,undefined8 param_2,undefined8 param_3,long param_4)

{
  int iVar1;
  long lVar2;
  ulong uVar3;
  undefined4 *puVar4;
  long local_6a0;
  long local_698;
  long local_690;
  long local_688;
  long local_680 [4];
  undefined8 local_660 [2];
  undefined4 local_650 [392];
  
  puVar4 = local_650;
  for (lVar2 = 0x186; lVar2 != 0; lVar2 = lVar2 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  local_660[0] = 0;
  local_660[1] = 0;
  if ((((param_1 != 0) && (param_4 != 0)) && (lVar2 = *(long *)(param_4 + 8), lVar2 != 0)) &&
     ((*(code **)(lVar2 + 0x30) != (code *)0x0 && (*(long *)(lVar2 + 0x38) != 0)))) {
    local_6a0 = 0;
    local_698 = 0;
    local_690 = 0;
    (**(code **)(lVar2 + 0x30))(param_1,&local_6a0,&local_698,&local_690);
    local_680[3] = (**(code **)(*(long *)(param_4 + 8) + 0x38))();
    if (((local_6a0 != 0) && ((local_698 != 0 && (local_690 != 0)))) && (local_680[3] != 0)) {
      local_680[0] = local_6a0;
      local_688 = 0;
      local_680[1] = local_698;
      local_680[2] = local_690;
      if (*(long *)(param_4 + 8) != 0) {
        lVar2 = 0;
        uVar3 = 0;
        while( TRUE ) {
          iVar1 = bignum_serialize((long)local_660 + uVar3,0x628 - uVar3,&local_688,local_680[lVar2]
                                   ,*(undefined8 *)(param_4 + 8));
          if ((iVar1 == 0) || (uVar3 = uVar3 + local_688, 0x628 < uVar3)) break;
          lVar2 = lVar2 + 1;
          if (lVar2 == 4) {
            iVar1 = sha256(local_660,uVar3,param_2,param_3,*(undefined8 *)(param_4 + 8));
            return iVar1 != 0;
          }
        }
      }
    }
  }
  return FALSE;
}

