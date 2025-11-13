// /home/kali/xzre-ghidra/xzregh/1013D0_elf_parse.c
// Function: elf_parse @ 0x1013D0
// Calling convention: unknown
// Prototype: undefined elf_parse(void)


/*
 * AutoDoc: Initialises an `elf_info_t` from an in-memory ELF header: zeroes every field, records the lowest PT_LOAD virtual address, locates the PT_DYNAMIC segment, and caches pointers to the strtab, symtab, relocation tables (PLT, RELA, RELR), GNU hash buckets, version records, and GNU_RELRO metadata. Each pointer retrieved from the dynamic table is validated with `elf_contains_vaddr` so forged headers are rejected.
 *
 * It also enforces invariants such as 'only one PT_GNU_RELRO segment', derives the number of dynamic entries, and flips feature bits (`flags`) so later helpers know whether RELR, versym, or gnurelro data is present. Failure to locate the dynamic segment, find the required headers, or keep derived pointers inside mapped memory causes the parse to abort with FALSE.
 */
#include "xzre_types.h"


undefined8 elf_parse(ulong param_1,ulong *param_2)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  ulong uVar5;
  ulong uVar6;
  ulong uVar7;
  ulong uVar8;
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  byte bVar11;
  BOOL verdef_present;
  int iVar13;
  int iVar14;
  ulong *puVar15;
  long lVar16;
  int *piVar17;
  ulong uVar18;
  int *piVar19;
  uint uVar20;
  ulong uVar21;
  ulong uVar22;
  uint *puVar23;
  int dynamic_idx;
  int i;
  
  if (param_1 == 0) {
    return 0;
  }
  if (param_2 != (ulong *)0x0) {
    uVar18 = 0xffffffffffffffff;
    uVar20 = 0;
    puVar15 = param_2 + 1;
    for (lVar16 = 0x3e; lVar16 != 0; lVar16 = lVar16 + -1) {
      *(undefined4 *)puVar15 = 0;
      puVar15 = (ulong *)((long)puVar15 + 4);
    }
    *param_2 = param_1;
    lVar16 = -1;
    uVar22 = (ulong)*(ushort *)(param_1 + 0x38);
    piVar17 = (int *)(*(long *)(param_1 + 0x20) + param_1);
    *(ushort *)(param_2 + 3) = *(ushort *)(param_1 + 0x38);
    param_2[2] = (ulong)piVar17;
    piVar19 = piVar17;
    for (; uVar20 < (uint)uVar22; uVar20 = uVar20 + 1) {
      iVar13 = *piVar19;
      if (iVar13 == 1) {
        if (*(ulong *)(piVar19 + 4) < uVar18) {
          uVar18 = *(ulong *)(piVar19 + 4);
        }
      }
      else if (iVar13 == 2) {
        lVar16 = (long)(int)uVar20;
      }
      else {
        iVar13 = is_gnu_relro(iVar13,0xa0000000);
        if (iVar13 != 0) {
          if (*(int *)((long)param_2 + 0x4c) != 0) {
            return 0;
          }
          param_2[10] = *(ulong *)(piVar19 + 4);
          uVar21 = *(ulong *)(piVar19 + 10);
          *(undefined4 *)((long)param_2 + 0x4c) = 1;
          param_2[0xb] = uVar21;
        }
      }
      piVar19 = piVar19 + 0xe;
    }
    if ((uVar18 != 0xffffffffffffffff) && ((int)lVar16 != -1)) {
      param_2[1] = uVar18;
      uVar22 = *(ulong *)(piVar17 + lVar16 * 0xe + 10);
      uVar18 = (param_1 - uVar18) + *(long *)(piVar17 + lVar16 * 0xe + 4);
      param_2[4] = uVar18;
      iVar13 = (int)(uVar22 >> 4);
      *(int *)(param_2 + 5) = iVar13;
      iVar14 = elf_contains_vaddr();
      if (iVar14 != 0) {
        puVar15 = (ulong *)(uVar18 + 8);
        verdef_present = FALSE;
        uVar21 = 0xffffffffffffffff;
        uVar22 = 0xffffffffffffffff;
        uVar18 = 0xffffffffffffffff;
        puVar23 = (uint *)0x0;
        for (iVar14 = 0; iVar13 != iVar14; iVar14 = iVar14 + 1) {
          uVar5 = puVar15[-1];
          if (uVar5 == 0) {
            *(int *)(param_2 + 5) = iVar14;
            break;
          }
          if ((long)uVar5 < 0x25) {
            if ((long)uVar5 < 0x17) {
              switch(uVar5) {
              case 2:
                uVar18 = *puVar15;
                break;
              case 5:
                param_2[6] = *puVar15;
                break;
              case 6:
                param_2[7] = *puVar15;
                break;
              case 7:
                param_2[0xf] = *puVar15;
                break;
              case 8:
                uVar22 = *puVar15;
              }
            }
            else {
              switch(uVar5) {
              case 0x17:
                param_2[8] = *puVar15;
                break;
              case 0x18:
                goto switchD_0010157d_caseD_18;
              case 0x1e:
                bVar11 = (byte)*puVar15 & 8;
                goto LAB_00101650;
              case 0x23:
                uVar21 = *puVar15;
                break;
              case 0x24:
                param_2[0x11] = *puVar15;
              }
            }
          }
          else if (uVar5 == 0x6ffffffb) {
            bVar11 = (byte)*puVar15 & 1;
LAB_00101650:
            if (bVar11 != 0) {
switchD_0010157d_caseD_18:
              *(byte *)(param_2 + 0x1a) = (byte)param_2[0x1a] | 0x20;
            }
          }
          else if ((long)uVar5 < 0x6ffffffc) {
            if ((long)uVar5 < 0x6ffffefd) {
              if (0x6ffffefa < (long)uVar5) {
                return 0;
              }
              if (uVar5 == 0x6ffffef5) {
                puVar23 = (uint *)*puVar15;
              }
            }
            else if (uVar5 == 0x6ffffff0) {
              uVar5 = *puVar15;
              *(byte *)(param_2 + 0x1a) = (byte)param_2[0x1a] | 0x10;
              param_2[0xe] = uVar5;
            }
          }
          else if (uVar5 == 0x6ffffffd) {
            verdef_present = TRUE;
            param_2[0xd] = *puVar15;
          }
          else {
            if (uVar5 == 0x7fffffff) {
              return 0;
            }
            if (uVar5 == 0x6ffffffc) {
              param_2[0xc] = *puVar15;
            }
          }
          puVar15 = puVar15 + 2;
        }
        uVar5 = param_2[8];
        if (uVar5 != 0) {
          if (uVar18 == 0xffffffffffffffff) {
            return 0;
          }
          *(byte *)(param_2 + 0x1a) = (byte)param_2[0x1a] | 1;
          auVar9._8_8_ = 0;
          auVar9._0_8_ = uVar18;
          *(int *)(param_2 + 9) = SUB164(auVar9 / ZEXT816(0x18),0);
        }
        uVar6 = param_2[0xf];
        if (uVar6 != 0) {
          if (uVar22 == 0xffffffffffffffff) {
            return 0;
          }
          *(byte *)(param_2 + 0x1a) = (byte)param_2[0x1a] | 2;
          auVar10._8_8_ = 0;
          auVar10._0_8_ = uVar22;
          *(int *)(param_2 + 0x10) = SUB164(auVar10 / ZEXT816(0x18),0);
        }
        uVar7 = param_2[0x11];
        if (uVar7 != 0) {
          if (uVar21 == 0xffffffffffffffff) {
            return 0;
          }
          *(byte *)(param_2 + 0x1a) = (byte)param_2[0x1a] | 4;
          *(int *)(param_2 + 0x12) = (int)(uVar21 >> 3);
        }
        if (param_2[0xc] != 0) {
          if (verdef_present) {
            *(byte *)(param_2 + 0x1a) = (byte)param_2[0x1a] | 8;
          }
          else {
            param_2[0xc] = 0;
          }
        }
        uVar8 = param_2[6];
        if (((uVar8 != 0) && (puVar23 != (uint *)0x0)) && (param_2[7] != 0)) {
          if (uVar8 <= param_1) {
            param_2[6] = uVar8 + param_1;
            param_2[7] = param_2[7] + param_1;
            if (uVar5 != 0) {
              param_2[8] = uVar5 + param_1;
            }
            if (uVar6 != 0) {
              param_2[0xf] = uVar6 + param_1;
            }
            if (uVar7 != 0) {
              param_2[0x11] = uVar7 + param_1;
            }
            if (param_2[0xe] != 0) {
              param_2[0xe] = param_2[0xe] + param_1;
            }
            puVar23 = (uint *)((long)puVar23 + param_1);
          }
          uVar5 = param_2[0xc];
          if ((uVar5 != 0) && (uVar5 < param_1)) {
            param_2[0xc] = param_1 + uVar5;
          }
          if (((((param_2[8] == 0) ||
                (iVar13 = elf_contains_vaddr(param_2,param_2[8],uVar18,4), iVar13 != 0)) &&
               ((param_2[0xf] == 0 ||
                (iVar13 = elf_contains_vaddr(param_2,param_2[0xf],uVar22,4), iVar13 != 0)))) &&
              ((param_2[0x11] == 0 ||
               (iVar13 = elf_contains_vaddr(param_2,param_2[0x11],uVar21,4), iVar13 != 0)))) &&
             ((param_2[0xc] == 0 ||
              (iVar13 = elf_contains_vaddr(param_2,param_2[0xc],param_2[0xd] * 0x14,4), iVar13 != 0)
              ))) {
            uVar20 = *puVar23;
            *(uint *)(param_2 + 0x1b) = uVar20;
            uVar2 = puVar23[2];
            uVar3 = puVar23[1];
            *(uint *)((long)param_2 + 0xdc) = uVar2 - 1;
            puVar1 = puVar23 + 4;
            uVar4 = puVar23[3];
            param_2[0x1d] = (ulong)puVar1;
            *(uint *)(param_2 + 0x1c) = uVar4;
            param_2[0x1e] = (ulong)(puVar1 + uVar2 * 2);
            param_2[0x1f] = (ulong)(puVar1 + uVar2 * 2 + ((ulong)uVar20 - (ulong)uVar3));
            return 1;
          }
        }
      }
    }
  }
  return 0;
}

