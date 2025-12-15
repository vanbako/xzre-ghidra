// /home/kali/xzre-ghidra/xzregh/1072B0_sha256.c
// Function: sha256 @ 0x1072B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sha256(void * data, size_t count, u8 * mdBuf, u64 mdBufSize, imported_funcs_t * funcs)


/*
 * AutoDoc: Thin wrapper around EVP_Digest/Evp_sha256: it rejects NULL buffers, zero lengths, or output buffers smaller than 32 bytes, looks up OpenSSL's SHA-256 descriptor, and hashes the payload through EVP_Digest.
 */
#include "xzre_types.h"

BOOL sha256(void *data,size_t count,u8 *mdBuf,u64 mdBufSize,imported_funcs_t *funcs)

{
  pfn_EVP_Digest_t digest_fn;
  int digest_status;
  BOOL success;
  const EVP_MD *sha256_md;
  EVP_MD *digest_impl;
  
  // AutoDoc: Bail out when the caller hands us nothing to hash, an undersized digest buffer, or a missing import table.
  if ((((data == (void *)0x0) || (count == 0)) || (mdBufSize < 0x20)) ||
     (funcs == (imported_funcs_t *)0x0)) {
    success = FALSE;
  }
  else {
    // AutoDoc: Fetch the EVP_Digest entry point once so repeated hashing never has to chase the import table.
    digest_fn = funcs->EVP_Digest;
    success = FALSE;
    if ((digest_fn != (pfn_EVP_Digest_t)0x0) &&
       (success = FALSE, funcs->EVP_sha256 != (pfn_EVP_sha256_t)0x0)) {
      // AutoDoc: Resolve OpenSSL's SHA-256 descriptor and treat a NULL return as a fatal error.
      sha256_md = (*funcs->EVP_sha256)();
      // AutoDoc: Delegate to EVP_Digest with a NULL ENGINE/context so the helper mirrors libcrypto's canonical SHA-256 call.
      digest_status = (*digest_fn)(data,count,mdBuf,(uint *)0x0,sha256_md,(ENGINE *)0x0);
      success = (BOOL)(digest_status == 1);
    }
  }
  return success;
}

