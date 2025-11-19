// /home/kali/xzre-ghidra/xzregh/101F70_elf_get_rodata_segment.c
// Function: elf_get_rodata_segment @ 0x101F70
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_rodata_segment(elf_info_t * elf_info, u64 * pSize)


/*
 * AutoDoc: Locates the first read-only PT_LOAD segment that lives entirely after the executable code. It first asks `elf_get_code_segment` for the text range so it can ignore overlapping pages, then scans for PF_R-only segments, page-aligns their bounds, and picks the lowest segment whose start is beyond the end of `.text`. The result is cached in `elf_info_t` and handed to callers alongside its size so later routines (string searches, RELRO probes) can reuse the computed window.
 *
 * The helper begins by logging a `secret_data_append_from_call_site` record; failure to emit that telemetry causes the search to abort, so the rodata queries only run when the secret-data recorder is active.
 */

#include "xzre_types.h"

void * elf_get_rodata_segment(elf_info_t *elf_info,u64 *pSize)

{
  Elf64_Ehdr *ehdr;
  BOOL rodata_segment_found;
  BOOL telemetry_ok;
  void *cached_rodata;
  void *selected_rodata_start;
  Elf64_Phdr *phdr;
  ulong segment_runtime_start;
  void *segment_page_start;
  u64 selected_size;
  ulong phdr_index;
  ulong segment_runtime_end;
  u64 code_segment_size;
  
  telemetry_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xbd,0xe,0xb,FALSE);
  if (telemetry_ok != FALSE) {
    cached_rodata = (void *)elf_info->rodata_segment_start;
    ehdr = elf_info->elfbase;
    code_segment_size = 0;
    if (cached_rodata != (void *)0x0) {
      *pSize = elf_info->rodata_segment_size;
      return cached_rodata;
    }
    cached_rodata = elf_get_code_segment(elf_info,&code_segment_size);
    if (cached_rodata != (void *)0x0) {
      rodata_segment_found = FALSE;
      selected_size = 0;
      selected_rodata_start = (void *)0x0;
      for (phdr_index = 0; (uint)phdr_index < (uint)(ushort)elf_info->phdr_count; phdr_index = phdr_index + 1) {
        phdr = elf_info->phdrs + phdr_index;
        if ((phdr->p_type == 1) && ((phdr->p_flags & 7) == 4)) {
          segment_runtime_start = (long)ehdr + (phdr->p_vaddr - elf_info->load_base_vaddr);
          segment_runtime_end = phdr->p_memsz + segment_runtime_start;
          segment_page_start = (void *)(segment_runtime_start & 0xfffffffffffff000);
          if ((segment_runtime_end & 0xfff) != 0) {
            segment_runtime_end = (segment_runtime_end & 0xfffffffffffff000) + 0x1000;
          }
          if ((void *)((long)cached_rodata + code_segment_size) <= segment_page_start) {
            if (rodata_segment_found) {
              if (segment_page_start < selected_rodata_start) {
                selected_size = segment_runtime_end - (long)segment_page_start;
                selected_rodata_start = segment_page_start;
              }
            }
            else {
              rodata_segment_found = TRUE;
              selected_size = segment_runtime_end - (long)segment_page_start;
              selected_rodata_start = segment_page_start;
            }
          }
        }
      }
      if (rodata_segment_found) {
        elf_info->rodata_segment_start = (u64)selected_rodata_start;
        elf_info->rodata_segment_size = selected_size;
        *pSize = selected_size;
        return selected_rodata_start;
      }
    }
  }
  return (void *)0x0;
}

