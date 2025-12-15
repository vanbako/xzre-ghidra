// /home/kali/xzre-ghidra/xzregh/101E90_elf_get_got_symbol.c
// Function: elf_get_got_symbol @ 0x101E90
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_got_symbol(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Mirrors `elf_get_plt_symbol` but targets the main RELA table. It requires feature bit 2 (RELA metadata), then calls
 * `elf_get_reloc_symbol` with relocation type 6 (R_X86_64_GLOB_DAT) to retrieve the writable GOT slot for the
 * requested import. Failure means the module never imported the symbol through a standard GOT relocation.
 */
#include "xzre_types.h"

void * elf_get_got_symbol(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  void *symbol_slot;
  
  // AutoDoc: Skip immediately when the RELA table was missing.
  if (((elf_info->feature_flags & 2) != 0) && (elf_info->rela_reloc_count != 0)) {
    // AutoDoc: Reuse the generic helper with R_X86_64_GLOB_DAT to land on the writable GOT slot.
    symbol_slot = elf_get_reloc_symbol
                       (elf_info,elf_info->rela_relocs,elf_info->rela_reloc_count,6,
                        encoded_string_id);
    return symbol_slot;
  }
  return (void *)0x0;
}

