// /home/kali/xzre-ghidra/xzregh/101EC0_elf_get_text_segment.c
// Function: elf_get_text_segment @ 0x101EC0
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_text_segment(elf_info_t * elf_info, u64 * pSize)


/*
 * AutoDoc: Finds and caches the first executable PT_LOAD segment. The helper emits a telemetry breadcrumb, walks the program
 * headers until it sees PF_X set, converts `p_vaddr` into a runtime pointer (subtracting the ELF load base), page
 * aligns the `[start, end)` window, and records both the base and span in `elf_info_t`. Subsequent calls reuse the
 * cached `text_segment_start/size` so the expensive scan only happens once.
 */

#include "xzre_types.h"

void * elf_get_text_segment(elf_info_t *elf_info,u64 *pSize)

{
  BOOL telemetry_ok;
  u64 segment_start;
  u8 *code_segment_start;
  Elf64_Phdr *phdr;
  u64 segment_end;
  u64 segment_size;
  ulong phdr_index;
  
  // AutoDoc: Emit a secret-data breadcrumb before touching program headers so text discovery stays audited.
  telemetry_ok = secret_data_append_bits_from_addr_or_ret
                    ((void *)0x0,(secret_data_shift_cursor_t)0xcb,7,0xc);
  code_segment_start = (void *)0x0;
  if (telemetry_ok != FALSE) {
    // AutoDoc: Once the text range is cached, future callers reuse it instead of rescanning the headers.
    code_segment_start = (void *)elf_info->text_segment_start;
    if (code_segment_start == (void *)0x0) {
      for (phdr_index = 0; (uint)phdr_index < (uint)(ushort)elf_info->phdr_count; phdr_index = phdr_index + 1) {
        phdr = elf_info->phdrs + phdr_index;
        // AutoDoc: Pick the first executable PT_LOAD entry and align its `[start, end)` window to page boundaries.
        if ((phdr->p_type == PT_LOAD) && ((phdr->p_flags & PF_X) != 0)) {
          segment_start = (long)elf_info->elfbase + (phdr->p_vaddr - elf_info->load_base_vaddr);
          segment_end = phdr->p_memsz + segment_start;
          code_segment_start = (void *)(segment_start & PAGE_ALIGN_MASK_4K);
          if ((segment_end & 0xfff) != 0) {
            segment_end = (segment_end & PAGE_ALIGN_MASK_4K) + 0x1000;
          }
          segment_size = segment_end - (long)code_segment_start;
          elf_info->text_segment_start = (u64)code_segment_start;
          elf_info->text_segment_size = segment_size;
          goto LAB_00101f65;
        }
      }
    }
    else {
      segment_size = elf_info->text_segment_size;
LAB_00101f65:
      *pSize = segment_size;
    }
  }
  return code_segment_start;
}

