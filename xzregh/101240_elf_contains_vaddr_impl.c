// /home/kali/xzre-ghidra/xzregh/101240_elf_contains_vaddr_impl.c
// Function: elf_contains_vaddr_impl @ 0x101240
// Calling convention: unknown
// Prototype: undefined elf_contains_vaddr_impl(void)


/*
 * AutoDoc: Validates that `[vaddr, vaddr + size)` is entirely covered by one or more PT_LOAD segments whose `p_flags` mask includes the requested bits. The helper page-aligns both ends of the interval, walks every loadable program header, and recurses when the range straddles multiple segments so partial overlaps are rechecked piecemeal.
 *
 * It refuses to run more than 0x3ea iterations (preventing runaway recursion), insists that the candidate addresses live inside the mapped ELF image, and short-circuits to TRUE when `size` is zero. Callers pass `p_flags` values such as PF_X or PF_W to differentiate text, data, and RELRO spans.
 */
#include "xzre_types.h"


ulong elf_contains_vaddr_impl(ulong *param_1,ulong param_2,long param_3,uint param_4,int param_5)

{
  int iVar1;
  int *piVar2;
  ulong uVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  
LAB_00101254:
  param_5 = param_5 + 1;
  uVar3 = param_2 + param_3;
  if (param_3 == 0) {
LAB_0010138e:
    uVar3 = 1;
  }
  else {
    uVar4 = uVar3;
    if (param_2 <= uVar3) {
      uVar4 = param_2;
    }
    if ((*param_1 <= uVar4) && (param_5 != 0x3ea)) {
      lVar6 = 0;
      do {
        if ((uint)(ushort)param_1[3] <= (uint)lVar6) break;
        piVar2 = (int *)(lVar6 * 0x38 + param_1[2]);
        if ((*piVar2 == 1) && ((piVar2[1] & param_4) == param_4)) {
          uVar4 = (*param_1 - param_1[1]) + *(long *)(piVar2 + 4);
          uVar5 = *(long *)(piVar2 + 10) + uVar4;
          uVar4 = uVar4 & 0xfffffffffffff000;
          if ((uVar5 & 0xfff) != 0) {
            uVar5 = (uVar5 & 0xfffffffffffff000) + 0x1000;
          }
          if ((param_2 >= uVar4) && (uVar3 <= uVar5)) goto LAB_0010138e;
          if ((uVar3 > uVar5) || (uVar4 <= param_2)) {
            if ((uVar5 <= param_2) || (param_2 < uVar4)) {
              if ((uVar5 < uVar3) && (uVar4 > param_2)) {
                uVar4 = elf_contains_vaddr_impl(param_1,param_2,uVar4 - param_2,param_4);
                if ((int)uVar4 == 0) {
                  return uVar4;
                }
                iVar1 = elf_contains_vaddr_impl
                                  (param_1,uVar5 + 1,(uVar3 - 1) - uVar5,param_4,param_5);
                return (ulong)(iVar1 != 0);
              }
            }
            else if (uVar5 < uVar3) {
              param_2 = uVar5 + 1;
              param_3 = uVar3 - param_2;
              goto LAB_00101254;
            }
          }
          else if (uVar4 < uVar3) goto code_r0x00101313;
        }
        lVar6 = lVar6 + 1;
      } while( TRUE );
    }
    uVar3 = 0;
  }
  return uVar3;
code_r0x00101313:
  param_3 = (uVar4 - param_2) + -1;
  goto LAB_00101254;
}

