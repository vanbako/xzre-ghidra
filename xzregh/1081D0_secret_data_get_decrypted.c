// /home/kali/xzre-ghidra/xzregh/1081D0_secret_data_get_decrypted.c
// Function: secret_data_get_decrypted @ 0x1081D0
// Calling convention: unknown
// Prototype: undefined secret_data_get_decrypted(void)


/*
 * AutoDoc: Runs a two-stage ChaCha20 decrypt to recover the embedded secret-data blob using keys stored alongside the payload. Other helpers request it whenever they need the ED448 key or command constants.
 */
#include "xzre_types.h"


bool secret_data_get_decrypted(long param_1,long param_2)

{
  int iVar1;
  long lVar2;
  undefined4 *puVar3;
  key_buf *pkVar4;
  undefined4 auStack_b8 [8];
  key_buf buf1;
  key_buf buf2;
  undefined1 local_68 [80];
  
  if (param_1 == 0) {
    return FALSE;
  }
  if ((param_2 != 0) && (*(long *)(param_2 + 8) != 0)) {
    puVar3 = auStack_b8;
    for (lVar2 = 0xc; lVar2 != 0; lVar2 = lVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    pkVar4 = &buf2;
    for (lVar2 = 0x1c; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)pkVar4 = 0;
      pkVar4 = pkVar4 + 4;
    }
    iVar1 = chacha_decrypt(auStack_b8,0x30,auStack_b8,&buf1,&buf2);
    if (iVar1 != 0) {
      iVar1 = chacha_decrypt(param_2 + 0x108,0x39,&buf2,local_68,param_1,
                             *(undefined8 *)(param_2 + 8));
      return iVar1 != 0;
    }
  }
  return FALSE;
}

