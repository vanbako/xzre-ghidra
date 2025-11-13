// /home/kali/xzre-ghidra/xzregh/101B90_elf_find_rela_reloc.c
// Function: elf_find_rela_reloc @ 0x101B90
// Calling convention: unknown
// Prototype: undefined elf_find_rela_reloc(void)


/*
 * AutoDoc: Searches the RELA relocation array for an entry tied to a given code pointer. When `encoded_string_id` is non-zero it is treated as an absolute address inside the module: the helper subtracts `elfbase` to match against `r_addend` and, on success, returns the relocated slot at `r_offset`. When the argument is zero the caller instead wants the raw addend pointer, so the helper immediately returns `elfbase + r_addend`.
 *
 * A pair of optional range bounds and a resumption index can be supplied in the additional SysV argument registers; if present they force the returned address to fall inside `[low, high]` and let the caller continue scanning from the previous index. Failing to find a match (or discovering that the module never exposed RELA relocations) yields NULL and, if a cursor pointer was provided, stores the position it stopped at.
 */
#include "xzre_types.h"


ulong elf_find_rela_reloc(long *param_1,long param_2,ulong param_3,ulong param_4,ulong *param_5)

{
  long lVar1;
  ulong uVar2;
  long *plVar3;
  ulong uVar4;
  
  if (((*(byte *)(param_1 + 0x1a) & 2) == 0) || (*(uint *)(param_1 + 0x10) == 0)) {
    return 0;
  }
  uVar4 = 0;
  if (param_5 != (ulong *)0x0) {
    uVar4 = *param_5;
  }
  lVar1 = *param_1;
  do {
    if (*(uint *)(param_1 + 0x10) <= uVar4) {
      if (param_5 != (ulong *)0x0) {
        *param_5 = uVar4;
      }
      return 0;
    }
    plVar3 = (long *)(uVar4 * 0x18 + param_1[0xf]);
    if ((int)plVar3[1] == 8) {
      if (param_2 == 0) {
        uVar2 = plVar3[2] + lVar1;
      }
      else {
        if (plVar3[2] != param_2 - lVar1) goto LAB_00101c07;
        uVar2 = *plVar3 + lVar1;
        if (param_3 == 0) goto LAB_00101c18;
      }
      if ((param_3 <= uVar2) && (uVar2 <= param_4)) {
LAB_00101c18:
        if (param_5 == (ulong *)0x0) {
          return uVar2;
        }
        *param_5 = uVar4 + 1;
        return uVar2;
      }
    }
LAB_00101c07:
    uVar4 = uVar4 + 1;
  } while( TRUE );
}

