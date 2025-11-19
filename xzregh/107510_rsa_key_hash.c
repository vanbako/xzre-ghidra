// /home/kali/xzre-ghidra/xzregh/107510_rsa_key_hash.c
// Function: rsa_key_hash @ 0x107510
// Calling convention: __stdcall
// Prototype: BOOL __stdcall rsa_key_hash(RSA * rsa, u8 * mdBuf, u64 mdBufSize, imported_funcs_t * funcs)


/*
 * AutoDoc: Grabs the exponent and modulus via RSA_get0_key, serialises the exponent first and the modulus second with bignum_serialize into
 * a ~4 KiB stack buffer, and runs sha256 over the exact number of bytes produced. Any missing component or overflow of the
 * 0x100a-byte scratch cancels the fingerprint.
 */

#include "xzre_types.h"

BOOL rsa_key_hash(RSA *rsa,u8 *mdBuf,u64 mdBufSize,imported_funcs_t *funcs)

{
  u64 exp_serialized_len;
  BOOL success;
  long wipe_length;
  u8 *wipe_cursor;
  u64 written;
  BIGNUM *rsa_exponent;
  BIGNUM *rsa_modulus;
  u8 fingerprint_buf[0x100a];
  BOOL result;
  
  wipe_cursor = &result;
  for (wipe_length = 0xffa; wipe_length != 0; wipe_length = wipe_length + -1) {
    *(undefined1 *)wipe_cursor = FALSE;
    wipe_cursor = (BOOL *)((long)wipe_cursor + 1);
  }
  fingerprint_buf[0] = '\0';
  fingerprint_buf[1] = '\0';
  fingerprint_buf[2] = '\0';
  fingerprint_buf[3] = '\0';
  fingerprint_buf[4] = '\0';
  fingerprint_buf[5] = '\0';
  fingerprint_buf[6] = '\0';
  fingerprint_buf[7] = '\0';
  fingerprint_buf[8] = '\0';
  fingerprint_buf[9] = '\0';
  fingerprint_buf[10] = '\0';
  fingerprint_buf[0xb] = '\0';
  fingerprint_buf[0xc] = '\0';
  fingerprint_buf[0xd] = '\0';
  fingerprint_buf[0xe] = '\0';
  fingerprint_buf[0xf] = '\0';
  written = 0;
  if (((funcs != (imported_funcs_t *)0x0) && (rsa != (RSA *)0x0)) &&
     (funcs->RSA_get0_key_resolved != (pfn_RSA_get0_key_t)0x0)) {
    rsa_exponent = (BIGNUM *)0x0;
    rsa_modulus = (BIGNUM *)0x0;
    (*funcs->RSA_get0_key_resolved)(rsa,&rsa_modulus,&rsa_exponent,(BIGNUM **)0x0);
    if ((rsa_exponent != (BIGNUM *)0x0) && (rsa_modulus != (BIGNUM *)0x0)) {
      success = bignum_serialize(fingerprint_buf,0x100a,&written,rsa_exponent,funcs);
      exp_serialized_len = written;
      if (((success != FALSE) &&
          ((written < 0x100a &&
           (success = bignum_serialize(fingerprint_buf + written,0x100a - written,&written,rsa_modulus,
                                     funcs), success != FALSE)))) && (exp_serialized_len + written < 0x100b)) {
        success = sha256(fingerprint_buf,exp_serialized_len + written,mdBuf,mdBufSize,funcs);
        return success;
      }
    }
  }
  return FALSE;
}

