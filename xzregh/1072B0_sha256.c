// /home/kali/xzre-ghidra/xzregh/1072B0_sha256.c
// Function: sha256 @ 0x1072B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sha256(void * data, size_t count, u8 * mdBuf, u64 mdBufSize, imported_funcs_t * funcs)


/*
 * AutoDoc: Thin wrapper around EVP_Digest/Evp_sha256: it rejects empty buffers, refuses to write unless mdBuf has at least 32 bytes of
 * space, looks up OpenSSL’s SHA-256 implementation via the import table, and hashes the supplied payload in place.
 */

#include "xzre_types.h"

BOOL sha256(void *data,size_t count,u8 *mdBuf,u64 mdBufSize,imported_funcs_t *funcs)

{
  pfn_EVP_Digest_t digest_fn;
  int iVar2;
  BOOL success;
  EVP_MD *sha256_md;
  EVP_MD *md;
  
  if ((((data == (void *)0x0) || (count == 0)) || (mdBufSize < 0x20)) ||
     (funcs == (imported_funcs_t *)0x0)) {
    success = FALSE;
  }
  else {
    digest_fn = funcs->EVP_Digest;
    success = FALSE;
    if ((digest_fn != (pfn_EVP_Digest_t)0x0) &&
       (success = FALSE, funcs->EVP_sha256 != (pfn_EVP_sha256_t)0x0)) {
      sha256_md = (*funcs->EVP_sha256)();
      iVar2 = (*digest_fn)(data,count,mdBuf,(uint *)0x0,sha256_md,(ENGINE *)0x0);
      success = (BOOL)(iVar2 == 1);
    }
  }
  return success;
}

