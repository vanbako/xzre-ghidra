// /home/kali/xzre-ghidra/xzregh/1022D0_elf_contains_vaddr_relro.c
// Function: elf_contains_vaddr_relro @ 0x1022D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_contains_vaddr_relro(elf_info_t * elf_info, u64 vaddr, u64 size, u32 p_flags)


/*
 * AutoDoc: Extends `elf_contains_vaddr` with GNU_RELRO bounds checking. The helper first reuses the normal containment test (forcing PF_R) so `[vaddr, vaddr+size)` is known to live inside a readable PT_LOAD. When `p_flags` is non-zero and the ELF exported PT_GNU_RELRO metadata it converts the RELRO segment into runtime pointers, page-aligns the window, and verifies the caller's span is fully enclosed. Requests outside the RELRO range (or binaries that never exposed RELRO) return FALSE so later hooks never mis-tag writable memory.
 */

#include "xzre_types.h"

BOOL elf_contains_vaddr_relro(elf_info_t *elf_info,u64 vaddr,u64 size,u32 p_flags)

{
  BOOL range_is_protected;
  ulong relro_window_end;
  ulong relro_window_start;
  
  // AutoDoc: Leverage the generic helper to ensure the range already lives inside a readable PT_LOAD segment.
  range_is_protected = elf_contains_vaddr(elf_info,(void *)vaddr,size,2);
  // AutoDoc: `p_flags` acts as a caller-supplied "must be RELRO" bit—only then do we enforce the PT_GNU_RELRO bounds.
  if (((range_is_protected != FALSE) && (range_is_protected = TRUE, p_flags != 0)) && (elf_info->gnurelro_present != FALSE)) {
    relro_window_start = (long)elf_info->elfbase + (elf_info->gnurelro_vaddr - elf_info->load_base_vaddr);
    relro_window_end = elf_info->gnurelro_memsize + relro_window_start;
    relro_window_start = relro_window_start & 0xfffffffffffff000;
    if ((relro_window_end & 0xfff) != 0) {
      relro_window_end = (relro_window_end & 0xfffffffffffff000) + 0x1000;
    }
    // AutoDoc: Clamp to the page-aligned RELRO span; any byte outside `[relro_window_start, relro_window_end)` fails the containment test.
    if ((relro_window_end <= vaddr) || (range_is_protected = FALSE, vaddr < relro_window_start)) {
      range_is_protected = (BOOL)(vaddr + size <= relro_window_start && vaddr < relro_window_start || relro_window_end < vaddr + size);
    }
  }
  return range_is_protected;
}

