// /home/kali/xzre-ghidra/xzregh/1072B0_sha256.c
// Function: sha256 @ 0x1072B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sha256(void * data, size_t count, u8 * mdBuf, u64 mdBufSize, imported_funcs_t * funcs)


/*
 * AutoDoc: Invokes EVP_Digest/Evp_sha256 through the imported function table to hash arbitrary buffers. It fingerprints host keys and payload components so the command verifier can prove authenticity without linking libcrypto statically.
 */
#include "xzre_types.h"


BOOL sha256(void *data,size_t count,u8 *mdBuf,u64 mdBufSize,imported_funcs_t *funcs)

{
  _func_56 *p_Var1;
  int iVar2;
  BOOL BVar3;
  EVP_MD *type;
  EVP_MD *md;
  
  if ((((data == (void *)0x0) || (count == 0)) || (mdBufSize < 0x20)) ||
     (funcs == (imported_funcs_t *)0x0)) {
    BVar3 = FALSE;
  }
  else {
    p_Var1 = funcs->EVP_Digest;
    BVar3 = FALSE;
    if ((p_Var1 != (_func_56 *)0x0) && (BVar3 = FALSE, funcs->EVP_sha256 != (_func_38 *)0x0)) {
      type = (*funcs->EVP_sha256)();
      iVar2 = (*p_Var1)(data,count,mdBuf,(uint *)0x0,type,(ENGINE *)0x0);
      BVar3 = (BOOL)(iVar2 == 1);
    }
  }
  return BVar3;
}

