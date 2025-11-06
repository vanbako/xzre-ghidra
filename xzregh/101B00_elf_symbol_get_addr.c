// /home/kali/xzre-ghidra/xzregh/101B00_elf_symbol_get_addr.c
// Function: elf_symbol_get_addr @ 0x101B00
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_symbol_get_addr(elf_info_t * elf_info, EncodedStringId encoded_string_id)


void * elf_symbol_get_addr(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  Elf64_Sym *sym;
  
  sym = (Elf64_Sym *)elf_symbol_get(elf_info,encoded_string_id,0);
  if (sym != (Elf64_Sym *)0x0) {
    if ((sym->st_value == 0) || (sym->st_shndx == 0)) {
      sym = (Elf64_Sym *)0x0;
    }
    else {
      sym = (Elf64_Sym *)(elf_info->elfbase->e_ident + sym->st_value);
    }
  }
  return sym;
}

