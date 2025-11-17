// /home/kali/xzre-ghidra/xzregh/103B80_dsa_key_hash.c
// Function: dsa_key_hash @ 0x103B80
// Calling convention: __stdcall
// Prototype: BOOL __stdcall dsa_key_hash(DSA * dsa, u8 * mdBuf, u64 mdBufSize, global_context_t * ctx)


/*
 * AutoDoc: Pulls the p/q/g parameters and public key (y) out of the DSA handle via DSA_get0_pqg/DSA_get0_pub_key, serialises each with
 * bignum_serialize into a 0x628-byte scratch buffer, and hashes the concatenation with sha256. Any missing pointer, oversized
 * BIGNUM, or serialization failure aborts immediately so only genuine DSA host keys feed the fingerprint.
 */

#include "xzre_types.h"

BOOL dsa_key_hash(DSA *dsa,u8 *mdBuf,u64 mdBufSize,global_context_t *ctx)

{
  imported_funcs_t *imports;
  BOOL success;
  size_t component_idx;
  size_t serialized_len;
  u32 *scratch_cursor;
  BIGNUM *param_p;
  BIGNUM *param_q;
  BIGNUM *param_g;
  u64 component_len;
  BIGNUM *components[4];
  u8 local_660 [16];
  undefined4 local_650 [392];
  
  scratch_cursor = local_650;
  for (component_idx = 0x186; component_idx != 0; component_idx = component_idx + -1) {
    *scratch_cursor = 0;
    scratch_cursor = scratch_cursor + 1;
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
      (imports = ctx->imported_funcs, imports != (imported_funcs_t *)0x0)) &&
     ((imports->DSA_get0_pqg != (pfn_DSA_get0_pqg_t)0x0 &&
      (imports->DSA_get0_pub_key != (pfn_DSA_get0_pub_key_t)0x0)))) {
    param_p = (BIGNUM *)0x0;
    param_q = (BIGNUM *)0x0;
    param_g = (BIGNUM *)0x0;
    (*imports->DSA_get0_pqg)(dsa,&param_p,&param_q,&param_g);
    components[3] = (*ctx->imported_funcs->DSA_get0_pub_key)(dsa);
    if (((param_p != (BIGNUM *)0x0) &&
        ((param_q != (BIGNUM *)0x0 && (param_g != (BIGNUM *)0x0)))) &&
       (components[3] != (BIGNUM *)0x0)) {
      components[0] = param_p;
      component_len = 0;
      components[1] = param_q;
      components[2] = param_g;
      if (ctx->imported_funcs != (imported_funcs_t *)0x0) {
        component_idx = 0;
        serialized_len = 0;
        while( TRUE ) {
          success = bignum_serialize(local_660 + serialized_len,0x628 - serialized_len,&component_len,components[component_idx],
                                   ctx->imported_funcs);
          if ((success == FALSE) || (serialized_len = serialized_len + component_len, 0x628 < serialized_len)) break;
          component_idx = component_idx + 1;
          if (component_idx == 4) {
            success = sha256(local_660,serialized_len,mdBuf,mdBufSize,ctx->imported_funcs);
            return (uint)(success != FALSE);
          }
        }
      }
    }
  }
  return FALSE;
}

