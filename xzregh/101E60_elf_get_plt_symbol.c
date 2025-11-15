// /home/kali/xzre-ghidra/xzregh/101E60_elf_get_plt_symbol.c
// Function: elf_get_plt_symbol @ 0x101E60
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_plt_symbol(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Looks up the PLT thunk for a given symbol by delegating to `elf_get_reloc_symbol` with relocation type 7 (R_X86_64_JUMP_SLOT).
 * It first makes sure the module actually advertised a PLT relocation table (flag bit 1) and caches its size, then returns the
 * GOT/PLT entry that will be overwritten during hook installation. NULL means either the relocation table was absent or the
 * requested symbol never appeared there.
 */

#include "xzre_types.h"

void * elf_get_plt_symbol(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  void *pvVar1;
  
  if (((elf_info->flags & 1) != 0) && (elf_info->plt_relocs_num != 0)) {
    pvVar1 = elf_get_reloc_symbol
                       (elf_info,elf_info->plt_relocs,elf_info->plt_relocs_num,7,encoded_string_id);
    return pvVar1;
  }
  return (void *)0x0;
}

