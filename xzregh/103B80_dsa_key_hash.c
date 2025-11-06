// /home/kali/xzre-ghidra/xzregh/103B80_dsa_key_hash.c
// Function: dsa_key_hash @ 0x103B80
// Calling convention: __stdcall
// Prototype: BOOL __stdcall dsa_key_hash(DSA * dsa, u8 * mdBuf, u64 mdBufSize, global_context_t * ctx)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief obtains a SHA256 hash of the supplied RSA key
 *
 *   @param dsa the DSA key to hash
 *   @param mdBuf buffer to write the resulting digest to
 *   @param mdBufSize size of the buffer indicated by @p mdBuf
 *   @param ctx
 *   @return BOOL TRUE if the hash was successfully generated, FALSE otherwise
 */

BOOL dsa_key_hash(DSA *dsa,u8 *mdBuf,u64 mdBufSize,global_context_t *ctx)

{
  imported_funcs_t *piVar1;
  BOOL BVar2;
  long lVar3;
  ulong count;
  undefined4 *puVar4;
  BIGNUM *local_6a0;
  BIGNUM *local_698;
  BIGNUM *local_690;
  u64 local_688;
  BIGNUM *local_680 [4];
  u8 local_660 [16];
  undefined4 local_650 [392];
  
  puVar4 = local_650;
  for (lVar3 = 0x186; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  local_660[0] = '\0';
  local_660[1] = '\0';
  local_660[2] = '\0';
  local_660[3] = '\0';
  local_660[4] = '\0';
  local_660[5] = '\0';
  local_660[6] = '\0';
  local_660[7] = '\0';
  local_660[8] = '\0';
  local_660[9] = '\0';
  local_660[10] = '\0';
  local_660[0xb] = '\0';
  local_660[0xc] = '\0';
  local_660[0xd] = '\0';
  local_660[0xe] = '\0';
  local_660[0xf] = '\0';
  if ((((dsa != (DSA *)0x0) && (ctx != (global_context_t *)0x0)) &&
      (piVar1 = ctx->imported_funcs, piVar1 != (imported_funcs_t *)0x0)) &&
     ((piVar1->DSA_get0_pqg != (_func_33 *)0x0 && (piVar1->DSA_get0_pub_key != (_func_34 *)0x0)))) {
    local_6a0 = (BIGNUM *)0x0;
    local_698 = (BIGNUM *)0x0;
    local_690 = (BIGNUM *)0x0;
    (*piVar1->DSA_get0_pqg)(dsa,&local_6a0,&local_698,&local_690);
    local_680[3] = (*ctx->imported_funcs->DSA_get0_pub_key)(dsa);
    if (((local_6a0 != (BIGNUM *)0x0) &&
        ((local_698 != (BIGNUM *)0x0 && (local_690 != (BIGNUM *)0x0)))) &&
       (local_680[3] != (BIGNUM *)0x0)) {
      local_680[0] = local_6a0;
      local_688 = 0;
      local_680[1] = local_698;
      local_680[2] = local_690;
      if (ctx->imported_funcs != (imported_funcs_t *)0x0) {
        lVar3 = 0;
        count = 0;
        while( true ) {
          BVar2 = bignum_serialize(local_660 + count,0x628 - count,&local_688,local_680[lVar3],
                                   ctx->imported_funcs);
          if ((BVar2 == 0) || (count = count + local_688, 0x628 < count)) break;
          lVar3 = lVar3 + 1;
          if (lVar3 == 4) {
            BVar2 = sha256(local_660,count,mdBuf,mdBufSize,ctx->imported_funcs);
            return (uint)(BVar2 != 0);
          }
        }
      }
    }
  }
  return 0;
}

