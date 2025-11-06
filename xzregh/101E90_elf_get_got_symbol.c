// /home/kali/xzre-ghidra/xzregh/101E90_elf_get_got_symbol.c
// Function: elf_get_got_symbol @ 0x101E90
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_got_symbol(elf_info_t * elf_info, EncodedStringId encoded_string_id)


void * elf_get_got_symbol(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  void *pvVar1;
  
  if (((elf_info->flags & 2) != 0) && (elf_info->rela_relocs_num != 0)) {
    pvVar1 = elf_get_reloc_symbol
                       (elf_info,elf_info->rela_relocs,elf_info->rela_relocs_num,6,encoded_string_id
                       );
    return pvVar1;
  }
  return (void *)0x0;
}

