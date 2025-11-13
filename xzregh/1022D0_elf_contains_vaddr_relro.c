// /home/kali/xzre-ghidra/xzregh/1022D0_elf_contains_vaddr_relro.c
// Function: elf_contains_vaddr_relro @ 0x1022D0
// Calling convention: unknown
// Prototype: undefined elf_contains_vaddr_relro(void)


/*
 * AutoDoc: Combines `elf_contains_vaddr` with the GNU_RELRO metadata harvested during `elf_parse`. The range must sit inside a read-only PT_LOAD (PF_R), and the module must have advertised a RELRO segment; if so the helper also verifies that `[vaddr, vaddr+size)` falls within the page-aligned RELRO window cached in `elf_info_t`. Anything outside that protected span returns FALSE, which prevents the loader from treating writable data as RELRO by mistake.
 */
#include "xzre_types.h"


undefined1  [16]
elf_contains_vaddr_relro(long *param_1,ulong param_2,long param_3,int param_4,undefined8 param_5)

{
  ulong uVar1;
  ulong uVar2;
  ulong uVar3;
  undefined1 auVar4 [16];
  
  uVar1 = elf_contains_vaddr();
  if ((((int)uVar1 != 0) && (uVar1 = 1, param_4 != 0)) && (*(int *)((long)param_1 + 0x4c) != 0)) {
    uVar3 = (*param_1 - param_1[1]) + param_1[10];
    uVar2 = param_1[0xb] + uVar3;
    uVar3 = uVar3 & 0xfffffffffffff000;
    if ((uVar2 & 0xfff) != 0) {
      uVar2 = (uVar2 & 0xfffffffffffff000) + 0x1000;
    }
    if ((uVar2 <= param_2) || (uVar1 = 0, param_2 < uVar3)) {
      uVar1 = (ulong)(param_2 + param_3 <= uVar3 && param_2 < uVar3 || uVar2 < param_2 + param_3);
    }
  }
  auVar4._8_8_ = param_5;
  auVar4._0_8_ = uVar1;
  return auVar4;
}

