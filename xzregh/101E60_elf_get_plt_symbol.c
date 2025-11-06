// /home/kali/xzre-ghidra/xzregh/101E60_elf_get_plt_symbol.c
// Function: elf_get_plt_symbol @ 0x101E60
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_plt_symbol(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Gets the PLT symbol with name @p encoded_string_id from the parsed ELF file
 *
 *   @param elf_info the parsed ELF context
 *   @param encoded_string_id symbol to look for (encoded)
 *   @return void* the address of the symbol, or NULL if not found
 */

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

