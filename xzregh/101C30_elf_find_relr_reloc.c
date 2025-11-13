// /home/kali/xzre-ghidra/xzregh/101C30_elf_find_relr_reloc.c
// Function: elf_find_relr_reloc @ 0x101C30
// Calling convention: unknown
// Prototype: undefined elf_find_relr_reloc(void)


/*
 * AutoDoc: Performs the same search as `elf_find_rela_reloc` but against the packed RELR format. It replays the RELR decoding algorithm (literal entry vs bitmap entry), sanity-checks each decoded pointer with `elf_contains_vaddr`, compares the pointed-to value against the requested target address, and optionally enforces a lower/upper bound plus an iteration cursor via the extra argument registers. Returning NULL means there were no RELR records, the address never appeared in the run, or one of the decoded pointers failed validation.
 */
#include "xzre_types.h"


long * elf_find_relr_reloc(long *param_1,long param_2,long *param_3,long *param_4,ulong *param_5)

{
  uint uVar1;
  long lVar2;
  int iVar3;
  ulong uVar4;
  long *plVar5;
  long lVar6;
  ulong uVar7;
  
  lVar2 = *param_1;
  if ((*(byte *)(param_1 + 0x1a) & 4) != 0) {
    uVar1 = *(uint *)(param_1 + 0x12);
    if ((param_2 != 0) && (uVar1 != 0)) {
      uVar4 = 0;
      if (param_5 != (ulong *)0x0) {
        uVar4 = *param_5;
      }
      lVar6 = 0;
      for (; uVar4 < uVar1; uVar4 = uVar4 + 1) {
        plVar5 = (long *)(lVar2 + lVar6);
        uVar7 = *(ulong *)(param_1[0x11] + uVar4 * 8);
        if ((uVar7 & 1) == 0) {
          plVar5 = (long *)(lVar2 + uVar7);
          iVar3 = elf_contains_vaddr(param_1,plVar5,8,4);
          if (iVar3 == 0) {
            return (long *)0x0;
          }
          if ((*plVar5 == param_2 - lVar2) &&
             ((param_3 == (long *)0x0 || ((param_3 <= plVar5 && (plVar5 <= param_4)))))) {
LAB_00101d98:
            if (param_5 != (ulong *)0x0) {
              *param_5 = uVar4 + 1;
              return plVar5;
            }
            return plVar5;
          }
          lVar6 = uVar7 + 8;
        }
        else {
          while (uVar7 = uVar7 >> 1, uVar7 != 0) {
            if ((uVar7 & 1) != 0) {
              iVar3 = elf_contains_vaddr(param_1,plVar5,8,4);
              if (iVar3 == 0) {
                return (long *)0x0;
              }
              if ((*plVar5 == param_2 - lVar2) &&
                 ((param_3 == (long *)0x0 || ((param_3 <= plVar5 && (plVar5 <= param_4))))))
              goto LAB_00101d98;
            }
            plVar5 = plVar5 + 1;
          }
          lVar6 = lVar6 + 0x1f8;
        }
      }
      if (param_5 != (ulong *)0x0) {
        *param_5 = uVar4;
      }
    }
  }
  return (long *)0x0;
}

