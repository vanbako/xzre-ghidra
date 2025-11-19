// /home/kali/xzre-ghidra/xzregh/101EC0_elf_get_code_segment.c
// Function: elf_get_code_segment @ 0x101EC0
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_code_segment(elf_info_t * elf_info, u64 * pSize)


/*
 * AutoDoc: Finds and caches the first executable PT_LOAD segment. The routine walks the program headers until it sees a segment with PF_X set, computes the runtime address by subtracting the ELF's minimum virtual address from `p_vaddr`, page-aligns both ends, stores the start/size inside `elf_info_t`, and returns the aligned base while writing the computed size through `pSize`. Subsequent calls use the cached values to avoid rescanning the headers.
 *
 * Before touching the headers it emits a `secret_data_append_from_address` telemetry record and refuses to proceed if that hook fails, keeping the text-range discovery tied to the secret-data accounting path.
 */

#include "xzre_types.h"

void * elf_get_code_segment(elf_info_t *elf_info,u64 *pSize)

{
  BOOL telemetry_ok;
  u64 segment_start;
  u8 *code_segment_start;
  Elf64_Phdr *phdr;
  u64 segment_end;
  u64 segment_size;
  ulong phdr_index;
  
  telemetry_ok = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0xcb,7,0xc);
  code_segment_start = (void *)0x0;
  if (telemetry_ok != FALSE) {
    code_segment_start = (void *)elf_info->text_segment_start;
    if (code_segment_start == (void *)0x0) {
      for (phdr_index = 0; (uint)phdr_index < (uint)(ushort)elf_info->phdr_count; phdr_index = phdr_index + 1) {
        phdr = elf_info->phdrs + phdr_index;
        if ((phdr->p_type == 1) && ((phdr->p_flags & 1) != 0)) {
          segment_start = (long)elf_info->elfbase + (phdr->p_vaddr - elf_info->load_base_vaddr);
          segment_end = phdr->p_memsz + segment_start;
          code_segment_start = (void *)(segment_start & 0xfffffffffffff000);
          if ((segment_end & 0xfff) != 0) {
            segment_end = (segment_end & 0xfffffffffffff000) + 0x1000;
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

