// /home/kali/xzre-ghidra/xzregh/101E90_elf_find_got_reloc_slot.c
// Function: elf_find_got_reloc_slot @ 0x101E90
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_find_got_reloc_slot(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Mirrors `elf_find_plt_reloc_slot` but targets the main RELA table. It requires feature bit 2 (RELA metadata), then calls
 * `elf_find_import_reloc_slot` with R_X86_64_GLOB_DAT to retrieve the writable GOT slot for the
 * requested import. Failure means the module never imported the symbol through a standard GOT relocation.
 */

#include "xzre_types.h"

void * elf_find_got_reloc_slot(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  void *symbol_slot;
  
  // AutoDoc: Skip immediately when the RELA table was missing.
  if (((elf_info->feature_flags & X_ELF_RELA) != 0) && (elf_info->rela_reloc_count != 0)) {
    // AutoDoc: Reuse the generic helper with R_X86_64_GLOB_DAT to land on the writable GOT slot.
    symbol_slot = elf_find_import_reloc_slot
                       (elf_info,elf_info->rela_relocs,elf_info->rela_reloc_count,R_X86_64_GLOB_DAT,
                        encoded_string_id);
    return symbol_slot;
  }
  return (void *)0x0;
}

