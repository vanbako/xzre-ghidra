// /home/kali/xzre-ghidra/xzregh/10A880_get_string_id.c
// Function: get_string_id @ 0x10A880
// Calling convention: __stdcall
// Prototype: EncodedStringId __stdcall get_string_id(char * string_begin, char * string_end)


EncodedStringId get_string_id(char *string_begin,char *string_end)

{
  ushort *puVar1;
  long lVar2;
  ushort uVar3;
  ushort uVar4;
  BOOL BVar5;
  uint uVar6;
  byte bVar7;
  ushort uVar8;
  ulong *puVar9;
  byte *pbVar10;
  long lVar11;
  ulong uVar12;
  
  BVar5 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0xa,8,1);
  if (BVar5 != 0) {
    pbVar10 = (byte *)(string_begin + 0x2c);
    if ((string_end != (char *)0x0) && (string_end < pbVar10)) {
      pbVar10 = (byte *)string_end;
    }
    lVar11 = 0x10c2a8;
    puVar9 = (ulong *)(_Lcrc64_clmul_1 + 0x760);
    for (; (string_begin <= pbVar10 && (bVar7 = *string_begin, -1 < (char)bVar7));
        string_begin = (char *)((byte *)string_begin + 1)) {
      if (bVar7 < 0x40) {
        uVar12 = *puVar9;
        uVar6 = 0;
        if ((uVar12 >> (bVar7 & 0x3f) & 1) == 0) {
          return 0;
        }
      }
      else {
        uVar12 = puVar9[1];
        bVar7 = bVar7 - 0x40;
        if ((uVar12 >> (bVar7 & 0x3f) & 1) == 0) {
          return 0;
        }
        uVar6 = count_bits(*puVar9);
      }
      while( true ) {
        lVar2 = 0;
        if (uVar12 != 0) {
          for (; (uVar12 >> lVar2 & 1) == 0; lVar2 = lVar2 + 1) {
          }
        }
        if ((uint)lVar2 == (uint)bVar7) break;
        uVar6 = uVar6 + 1;
        uVar12 = uVar12 & uVar12 - 1;
      }
      puVar1 = (ushort *)(lVar11 + (ulong)uVar6 * 4);
      uVar8 = *puVar1;
      uVar4 = puVar1[1];
      if ((uVar8 & 4) != 0) {
        return (int)(short)uVar4;
      }
      if ((uVar8 & 2) == 0) {
        uVar4 = -uVar4;
      }
      else {
        uVar8 = uVar8 & 0xfffd;
      }
      uVar3 = uVar8 & 0xfffe;
      if ((uVar8 & 1) == 0) {
        uVar3 = -uVar8;
      }
      lVar11 = lVar11 + (short)(uVar4 - 4);
      puVar9 = (ulong *)((long)puVar9 + (long)(short)(uVar3 - 0x10));
    }
  }
  return 0;
}

