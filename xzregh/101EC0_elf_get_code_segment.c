// /home/kali/xzre-ghidra/xzregh/101EC0_elf_get_code_segment.c
// Function: elf_get_code_segment @ 0x101EC0
// Calling convention: unknown
// Prototype: undefined elf_get_code_segment(void)


/*
 * AutoDoc: Finds and caches the first executable PT_LOAD segment. The routine walks the program headers until it sees a segment with PF_X set, computes the runtime address by subtracting the ELF's minimum virtual address from `p_vaddr`, page-aligns both ends, stores the start/size inside `elf_info_t`, and returns the aligned base while writing the computed size through `pSize`. Subsequent calls use the cached values to avoid rescanning the headers.
 */
#include "xzre_types.h"


undefined1  [16]
elf_get_code_segment(long *param_1,long *param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  ulong uVar2;
  int *piVar3;
  ulong uVar4;
  long lVar5;
  undefined1 auVar6 [16];
  
  iVar1 = secret_data_append_from_address(0,0xcb,7,0xc);
  uVar2 = 0;
  if (iVar1 != 0) {
    uVar2 = param_1[0x13];
    if (uVar2 == 0) {
      for (lVar5 = 0; (uint)lVar5 < (uint)*(ushort *)(param_1 + 3); lVar5 = lVar5 + 1) {
        piVar3 = (int *)(lVar5 * 0x38 + param_1[2]);
        if ((*piVar3 == 1) && ((*(byte *)(piVar3 + 1) & 1) != 0)) {
          uVar2 = (*param_1 - param_1[1]) + *(long *)(piVar3 + 4);
          uVar4 = *(long *)(piVar3 + 10) + uVar2;
          uVar2 = uVar2 & 0xfffffffffffff000;
          if ((uVar4 & 0xfff) != 0) {
            uVar4 = (uVar4 & 0xfffffffffffff000) + 0x1000;
          }
          lVar5 = uVar4 - uVar2;
          param_1[0x13] = uVar2;
          param_1[0x14] = lVar5;
          goto LAB_00101f65;
        }
      }
    }
    else {
      lVar5 = param_1[0x14];
LAB_00101f65:
      *param_2 = lVar5;
    }
  }
  auVar6._8_8_ = param_4;
  auVar6._0_8_ = uVar2;
  return auVar6;
}

