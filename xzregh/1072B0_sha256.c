// /home/kali/xzre-ghidra/xzregh/1072B0_sha256.c
// Function: sha256 @ 0x1072B0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sha256(void * data, size_t count, u8 * mdBuf, u64 mdBufSize, imported_funcs_t * funcs)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief computes the SHA256 hash of the supplied data
 *
 *   @param data buffer containing the data to hash
 *   @param count number of bytes to hash from @p data
 *   @param mdBuf buffer to write the resulting digest to
 *   @param mdBufSize size of the buffer indicated by @p mdBuf
 *   @param funcs
 *   @return BOOL
 *
 * Upstream implementation excerpt (xzre/xzre_code/sha256.c):
 *     BOOL sha256(
 *     	const void *data,
 *     	size_t count,
 *     	u8 *mdBuf,
 *     	u64 mdBufSize,
 *     	imported_funcs_t *funcs
 *     ){
 *     	if(!data || !count || mdBufSize < SHA256_DIGEST_SIZE || !funcs){
 *     		return FALSE;
 *     	}
 *     	if(!funcs->EVP_Digest || !funcs->EVP_sha256){
 *     		return FALSE;
 *     	}
 *     	const EVP_MD *md = funcs->EVP_sha256();
 *     	if(!md){
 *     		return FALSE;
 *     	}
 *     	return funcs->EVP_Digest(data, count, mdBuf, NULL, md, NULL) == TRUE;
 *     }
 */

BOOL sha256(void *data,size_t count,u8 *mdBuf,u64 mdBufSize,imported_funcs_t *funcs)

{
  _func_56 *p_Var1;
  int iVar2;
  uint uVar3;
  EVP_MD *md;
  
  if ((((data == (void *)0x0) || (count == 0)) || (mdBufSize < 0x20)) ||
     (funcs == (imported_funcs_t *)0x0)) {
    uVar3 = 0;
  }
  else {
    p_Var1 = funcs->EVP_Digest;
    uVar3 = 0;
    if ((p_Var1 != (_func_56 *)0x0) && (uVar3 = 0, funcs->EVP_sha256 != (_func_38 *)0x0)) {
      md = (*funcs->EVP_sha256)();
      iVar2 = (*p_Var1)(data,count,mdBuf,(uint *)0x0,md,(ENGINE *)0x0);
      uVar3 = (uint)(iVar2 == 1);
    }
  }
  return uVar3;
}

