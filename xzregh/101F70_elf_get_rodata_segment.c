// /home/kali/xzre-ghidra/xzregh/101F70_elf_get_rodata_segment.c
// Function: elf_get_rodata_segment @ 0x101F70
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_rodata_segment(elf_info_t * elf_info, u64 * pSize)


/*
 * AutoDoc: Locates and caches the first PF_R PT_LOAD segment that begins strictly after the executable code. The helper logs a `secret_data_append_from_call_site` breadcrumb, returns the cached `rodata_segment_start/size` when they already exist, and otherwise asks `elf_get_code_segment` for the `[text_start, text_end)` window. It then iterates every program header, converts each PF_R-only mapping into a runtime pointer, page-aligns `[segment_start, segment_end)`, and tracks the lowest candidate whose aligned base sits at or beyond `text_end`. The winning base/size are recorded inside `elf_info_t` and handed back via `pSize` so later string scans and RELRO checks can reuse the same rodata window.
 */

#include "xzre_types.h"

void * elf_get_rodata_segment(elf_info_t *elf_info,u64 *pSize)

{
  Elf64_Ehdr *ehdr;
  BOOL rodata_segment_found;
  BOOL telemetry_ok;
  void *segment_start_ptr;
  void *selected_rodata_start;
  Elf64_Phdr *phdr;
  ulong segment_runtime_start;
  void *segment_page_start;
  u64 selected_segment_size;
  ulong phdr_index;
  ulong segment_runtime_end;
  u64 code_segment_size;
  
  // AutoDoc: Abort immediately when the logger refuses the breadcrumb—rodata scans must mirror the secret-data log.
  telemetry_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xbd,0xe,0xb,FALSE);
  if (telemetry_ok != FALSE) {
    segment_start_ptr = (void *)elf_info->rodata_segment_start;
    ehdr = elf_info->elfbase;
    code_segment_size = 0;
    // AutoDoc: Subsequent callers simply reuse the cached base/size instead of re-walking the PT_LOAD list.
    if (segment_start_ptr != (void *)0x0) {
      *pSize = elf_info->rodata_segment_size;
      return segment_start_ptr;
    }
    segment_start_ptr = elf_get_code_segment(elf_info,&code_segment_size);
    if (segment_start_ptr != (void *)0x0) {
      rodata_segment_found = FALSE;
      selected_segment_size = 0;
      selected_rodata_start = (void *)0x0;
      // AutoDoc: Look for PF_R-only PT_LOAD entries whose aligned base lands beyond `.text`, keeping the lowest such segment.
      for (phdr_index = 0; (uint)phdr_index < (uint)(ushort)elf_info->phdr_count; phdr_index = phdr_index + 1) {
        phdr = elf_info->phdrs + phdr_index;
        if ((phdr->p_type == 1) && ((phdr->p_flags & 7) == 4)) {
          segment_runtime_start = (long)ehdr + (phdr->p_vaddr - elf_info->load_base_vaddr);
          segment_runtime_end = phdr->p_memsz + segment_runtime_start;
          segment_page_start = (void *)(segment_runtime_start & 0xfffffffffffff000);
          if ((segment_runtime_end & 0xfff) != 0) {
            segment_runtime_end = (segment_runtime_end & 0xfffffffffffff000) + 0x1000;
          }
          if ((void *)((long)segment_start_ptr + code_segment_size) <= segment_page_start) {
            if (rodata_segment_found) {
              if (segment_page_start < selected_rodata_start) {
                selected_segment_size = segment_runtime_end - (long)segment_page_start;
                selected_rodata_start = segment_page_start;
              }
            }
            else {
              rodata_segment_found = TRUE;
              selected_segment_size = segment_runtime_end - (long)segment_page_start;
              selected_rodata_start = segment_page_start;
            }
          }
        }
      }
      if (rodata_segment_found) {
        elf_info->rodata_segment_start = (u64)selected_rodata_start;
        elf_info->rodata_segment_size = selected_segment_size;
        *pSize = selected_segment_size;
        return selected_rodata_start;
      }
    }
  }
  return (void *)0x0;
}

