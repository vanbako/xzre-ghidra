// /home/kali/xzre-ghidra/xzregh/107510_rsa_key_hash.c
// Function: rsa_key_hash @ 0x107510
// Calling convention: __stdcall
// Prototype: BOOL __stdcall rsa_key_hash(RSA * rsa, u8 * mdBuf, u64 mdBufSize, imported_funcs_t * funcs)


/*
 * AutoDoc: Grabs the exponent and modulus via RSA_get0_key, serialises the exponent first and the modulus second with bignum_serialize into a ~4 KiB stack buffer, and runs sha256 over the exact number of bytes produced. Any missing component or overflow of the 0x100a-byte scratch cancels the fingerprint.
 */
#include "xzre_types.h"

BOOL rsa_key_hash(RSA *rsa,u8 *mdBuf,u64 mdBufSize,imported_funcs_t *funcs)

{
  u64 exp_serialized_len;
  BOOL success;
  long scratch_wipe_count;
  u8 *scratch_wipe_cursor;
  u64 fingerprint_bytes;
  BIGNUM *rsa_exponent;
  BIGNUM *rsa_modulus;
  u8 fingerprint_stream[0x100a];
  BOOL result;
  
  scratch_wipe_cursor = &result;
  // AutoDoc: Pre-wipe the 0x100a-byte scratch arena so no stack garbage contaminates the serialized fingerprint.
  for (scratch_wipe_count = 0xffa; scratch_wipe_count != 0; scratch_wipe_count = scratch_wipe_count + -1) {
    *scratch_wipe_cursor = FALSE;
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
  fingerprint_bytes = 0;
  // AutoDoc: Guard every lookup behind the resolved import table and a non-NULL RSA pointer before touching the key material.
  if (((funcs != (imported_funcs_t *)0x0) && (rsa != (RSA *)0x0)) &&
     (funcs->RSA_get0_key_resolved != (pfn_RSA_get0_key_t)0x0)) {
    rsa_exponent = (BIGNUM *)0x0;
    rsa_modulus = (BIGNUM *)0x0;
    // AutoDoc: Extract the modulus/exponent pair that will be serialized; missing components abort immediately.
    (*funcs->RSA_get0_key_resolved)(rsa,&rsa_modulus,&rsa_exponent,(BIGNUM **)0x0);
    if ((rsa_exponent != (BIGNUM *)0x0) && (rsa_modulus != (BIGNUM *)0x0)) {
      // AutoDoc: Write the public exponent first so the fingerprint starts with its `[len||value]` header.
      success = bignum_serialize(fingerprint_stream,0x100a,&fingerprint_bytes,rsa_exponent,funcs);
      exp_serialized_len = fingerprint_bytes;
      if (((success != FALSE) &&
          ((fingerprint_bytes < 0x100a &&
           // AutoDoc: Append the modulus immediately after the exponent and refuse any write that would exhaust the 0x100a-byte buffer.
           (success = bignum_serialize(fingerprint_stream + fingerprint_bytes,0x100a - fingerprint_bytes,
                                     &fingerprint_bytes,rsa_modulus,funcs), success != FALSE)))) &&
         (exp_serialized_len + fingerprint_bytes < 0x100b)) {
        // AutoDoc: Hash the exact number of serialized bytes (`exponent_len + modulus_len`) and bubble the SHA-256 status back to the caller.
        success = sha256(fingerprint_stream,exp_serialized_len + fingerprint_bytes,mdBuf,mdBufSize,funcs);
        return success;
      }
    }
  }
  return FALSE;
}

