// /home/kali/xzre-ghidra/xzregh/103B80_dsa_key_hash.c
// Function: dsa_key_hash @ 0x103B80
// Calling convention: __stdcall
// Prototype: BOOL __stdcall dsa_key_hash(DSA * dsa, u8 * mdBuf, u64 mdBufSize, global_context_t * ctx)


/*
 * AutoDoc: Pulls the p/q/g parameters and public key (y) out of the DSA handle via DSA_get0_pqg/DSA_get0_pub_key, serialises each with bignum_serialize into a 0x628-byte scratch buffer, and hashes the concatenation with sha256. Any missing pointer, oversized BIGNUM, or serialization failure aborts immediately so only genuine DSA host keys feed the fingerprint.
 */

#include "xzre_types.h"

BOOL dsa_key_hash(DSA *dsa,u8 *mdBuf,u64 mdBufSize,global_context_t *ctx)

{
  imported_funcs_t *imports;
  BOOL success;
  size_t component_idx;
  size_t serialized_bytes;
  u32 *scratch_wipe_cursor;
  BIGNUM *param_p;
  BIGNUM *param_q;
  BIGNUM *param_g;
  u64 component_bytes;
  BIGNUM *bn_components[4];
  u8 fingerprint_stream[0x628];
  u32 wipe_words[392];
  
  scratch_wipe_cursor = wipe_words;
  // AutoDoc: Manually zero the 0x628-byte workspace up front so no residual bytes leak into the fingerprint stream.
  for (component_idx = 0x186; component_idx != 0; component_idx = component_idx + -1) {
    *scratch_wipe_cursor = 0;
    scratch_wipe_cursor = scratch_wipe_cursor + 1;
  }
  fingerprint_stream[0] = '\0';
  fingerprint_stream[1] = '\0';
  fingerprint_stream[2] = '\0';
  fingerprint_stream[3] = '\0';
  fingerprint_stream[4] = '\0';
  fingerprint_stream[5] = '\0';
  fingerprint_stream[6] = '\0';
  fingerprint_stream[7] = '\0';
  fingerprint_stream[8] = '\0';
  fingerprint_stream[9] = '\0';
  fingerprint_stream[10] = '\0';
  fingerprint_stream[0xb] = '\0';
  fingerprint_stream[0xc] = '\0';
  fingerprint_stream[0xd] = '\0';
  fingerprint_stream[0xe] = '\0';
  fingerprint_stream[0xf] = '\0';
  // AutoDoc: Require a valid DSA handle, populated global context, and both DSA_get0 helpers before reading any BIGNUMs.
  if ((((dsa != (DSA *)0x0) && (ctx != (global_context_t *)0x0)) &&
      (imports = ctx->imported_funcs, imports != (imported_funcs_t *)0x0)) &&
     ((imports->DSA_get0_pqg != (pfn_DSA_get0_pqg_t)0x0 &&
      (imports->DSA_get0_pub_key != (pfn_DSA_get0_pub_key_t)0x0)))) {
    param_p = (BIGNUM *)0x0;
    param_q = (BIGNUM *)0x0;
    param_g = (BIGNUM *)0x0;
    (*imports->DSA_get0_pqg)(dsa,&param_p,&param_q,&param_g);
    // AutoDoc: Capture the public key y alongside p/q/g so all four components are hashed in a consistent order.
    bn_components[3] = (*ctx->imported_funcs->DSA_get0_pub_key)(dsa);
    if (((param_p != (BIGNUM *)0x0) &&
        ((param_q != (BIGNUM *)0x0 && (param_g != (BIGNUM *)0x0)))) &&
       (bn_components[3] != (BIGNUM *)0x0)) {
      bn_components[0] = param_p;
      component_bytes = 0;
      bn_components[1] = param_q;
      bn_components[2] = param_g;
      if (ctx->imported_funcs != (imported_funcs_t *)0x0) {
        component_idx = 0;
        serialized_bytes = 0;
        while( TRUE ) {
          // AutoDoc: Serialise each component back-to-back, aborting if any write fails or would run past the 0x628-byte scratch buffer.
          success = bignum_serialize(fingerprint_stream + serialized_bytes,0x628 - serialized_bytes,&component_bytes,bn_components[component_idx],
                                   ctx->imported_funcs);
          if ((success == FALSE) || (serialized_bytes = serialized_bytes + component_bytes, 0x628 < serialized_bytes)) break;
          component_idx = component_idx + 1;
          if (component_idx == 4) {
            // AutoDoc: Hash the concatenated `[p||q||g||y]` blob with sha256; the caller only sees TRUE when the digest lands cleanly.
            success = sha256(fingerprint_stream,serialized_bytes,mdBuf,mdBufSize,ctx->imported_funcs);
            return (uint)(success != FALSE);
          }
        }
      }
    }
  }
  return FALSE;
}

