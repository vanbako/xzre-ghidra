// /home/kali/xzre-ghidra/xzregh/1020A0_elf_find_string.c
// Function: elf_find_string @ 0x1020A0
// Calling convention: unknown
// Prototype: undefined elf_find_string(void)


/*
 * AutoDoc: Iterates through the cached `.rodata` window, calling `get_string_id` on each byte offset until it encounters a recognizable encoded string. If `*stringId_inOut` is zero the first discovered string wins and its id is written back; otherwise the search continues until an exact id match is found. The optional `rodata_start_ptr` lets callers resume from a previous location or constrain the search to a suffix of the segment.
 */
#include "xzre_types.h"


ulong elf_find_string(undefined8 param_1,int *param_2,ulong param_3)

{
  int iVar1;
  ulong uVar2;
  ulong uVar3;
  ulong local_30 [2];
  
  iVar1 = secret_data_append_from_call_site(0xb6,7,10,0);
  if (iVar1 != 0) {
    local_30[0] = 0;
    uVar2 = elf_get_rodata_segment(param_1,local_30);
    if ((uVar2 != 0) && (0x2b < local_30[0])) {
      uVar3 = local_30[0] + uVar2;
      if (param_3 != 0) {
        if (uVar3 <= param_3) {
          return 0;
        }
        if (uVar2 < param_3) {
          uVar2 = param_3;
        }
      }
      for (; uVar2 < uVar3; uVar2 = uVar2 + 1) {
        iVar1 = get_string_id(uVar2,uVar3);
        if (iVar1 != 0) {
          if (*param_2 == 0) {
            *param_2 = iVar1;
            return uVar2;
          }
          if (*param_2 == iVar1) {
            return uVar2;
          }
        }
      }
    }
  }
  return 0;
}

