// /home/kali/xzre-ghidra/xzregh/101DC0_elf_get_reloc_symbol.c
// Function: elf_get_reloc_symbol @ 0x101DC0
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_reloc_symbol(elf_info_t * elf_info, Elf64_Rela * relocs, u32 num_relocs, u64 reloc_type, EncodedStringId encoded_string_id)


void * elf_get_reloc_symbol
                 (elf_info_t *elf_info,Elf64_Rela *relocs,u32 num_relocs,u64 reloc_type,
                 EncodedStringId encoded_string_id)

{
  BOOL BVar1;
  EncodedStringId EVar2;
  ulong uVar3;
  
  BVar1 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x67,5,4);
  uVar3 = 0;
  if (BVar1 != 0) {
    for (; uVar3 < num_relocs; uVar3 = uVar3 + 1) {
      if ((((relocs->r_info & 0xffffffff) == reloc_type) &&
          (elf_info->symtab[relocs->r_info >> 0x20].st_shndx == 0)) &&
         (EVar2 = get_string_id(elf_info->strtab + elf_info->symtab[relocs->r_info >> 0x20].st_name,
                                (char *)0x0), EVar2 == encoded_string_id)) {
        return elf_info->elfbase->e_ident + relocs->r_offset;
      }
      relocs = relocs + 1;
    }
  }
  return (void *)0x0;
}

