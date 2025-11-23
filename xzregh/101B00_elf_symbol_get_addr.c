// /home/kali/xzre-ghidra/xzregh/101B00_elf_symbol_get_addr.c
// Function: elf_symbol_get_addr @ 0x101B00
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_symbol_get_addr(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Convenience layer on top of `elf_symbol_get`: look up the symbol, make sure it is defined (both `st_value` and `st_shndx` are
 * non-zero), and then turn the symbol value into a process address by adding it to `elf_info->elfbase`. Returning NULL indicates
 * either the symbol does not exist or it represents an import/resolver stub that lacks a concrete address.
 */

#include "xzre_types.h"

void * elf_symbol_get_addr(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  Elf64_Sym *sym_entry;
  
  // AutoDoc: Delegate to the GNU-hash resolver first—there’s nothing to add if the lookup already failed.
  sym_entry = elf_symbol_get(elf_info,encoded_string_id,0);
  if (sym_entry != (Elf64_Sym *)0x0) {
    // AutoDoc: Undefined or import-only records never produce a concrete address, so bail out immediately.
    if ((sym_entry->st_value == 0) || (sym_entry->st_shndx == 0)) {
      sym_entry = (Elf64_Sym *)0x0;
    }
    else {
      // AutoDoc: Add the symbol value to the module base to obtain its process address.
      sym_entry = (Elf64_Sym *)(elf_info->elfbase->e_ident + sym_entry->st_value);
    }
  }
  return sym_entry;
}

