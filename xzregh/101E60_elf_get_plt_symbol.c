// /home/kali/xzre-ghidra/xzregh/101E60_elf_get_plt_symbol.c
// Function: elf_get_plt_symbol @ 0x101E60
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_plt_symbol(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Looks up the PLT thunk for a given symbol by delegating to `elf_get_reloc_symbol` with relocation type 7
 * (R_X86_64_JUMP_SLOT). It first verifies that PLT relocations exist (feature bit 1 plus a non-zero count) and then
 * returns the GOT/PLT entry that will be rewritten during hook installation. NULL indicates the table was absent or
 * the symbol never appeared in it.
 */
#include "xzre_types.h"

void * elf_get_plt_symbol(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  void *symbol_slot;
  
  // AutoDoc: Fast fail when the binary never exposed PLT relocation metadata.
  if (((elf_info->feature_flags & 1) != 0) && (elf_info->plt_reloc_count != 0)) {
    // AutoDoc: Delegate to the generic helper with R_X86_64_JUMP_SLOT so we capture the PLT thunk.
    symbol_slot = elf_get_reloc_symbol
                       (elf_info,elf_info->plt_relocs,elf_info->plt_reloc_count,7,encoded_string_id)
    ;
    return symbol_slot;
  }
  return (void *)0x0;
}

