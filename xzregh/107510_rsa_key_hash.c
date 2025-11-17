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
  u8 buf [4106];
  u64 written;
  BIGNUM *rsa_exponent;
  BIGNUM *rsa_modulus;
  u8 local_1042 [16];
  BOOL result;
  
  wipe_cursor = &result;
  for (wipe_length = 0xffa; wipe_length != 0; wipe_length = wipe_length + -1) {
    *(undefined1 *)wipe_cursor = FALSE;
    wipe_cursor = (BOOL *)((long)wipe_cursor + 1);
  }
  local_1042[0] = '\0';
  local_1042[1] = '\0';
  local_1042[2] = '\0';
  local_1042[3] = '\0';
  local_1042[4] = '\0';
  local_1042[5] = '\0';
  local_1042[6] = '\0';
  local_1042[7] = '\0';
  local_1042[8] = '\0';
  local_1042[9] = '\0';
  local_1042[10] = '\0';
  local_1042[0xb] = '\0';
  local_1042[0xc] = '\0';
  local_1042[0xd] = '\0';
  local_1042[0xe] = '\0';
  local_1042[0xf] = '\0';
  written = 0;
  if (((funcs != (imported_funcs_t *)0x0) && (rsa != (RSA *)0x0)) &&
     (funcs->RSA_get0_key != (pfn_RSA_get0_key_t)0x0)) {
    rsa_exponent = (BIGNUM *)0x0;
    rsa_modulus = (BIGNUM *)0x0;
    (*funcs->RSA_get0_key)(rsa,&rsa_modulus,&rsa_exponent,(BIGNUM **)0x0);
    if ((rsa_exponent != (BIGNUM *)0x0) && (rsa_modulus != (BIGNUM *)0x0)) {
      success = bignum_serialize(local_1042,0x100a,&written,rsa_exponent,funcs);
      exp_serialized_len = written;
      if (((success != FALSE) &&
          ((written < 0x100a &&
           (success = bignum_serialize(local_1042 + written,0x100a - written,&written,rsa_modulus,
                                     funcs), success != FALSE)))) && (exp_serialized_len + written < 0x100b)) {
        success = sha256(local_1042,exp_serialized_len + written,mdBuf,mdBufSize,funcs);
        return success;
      }
    }
  }
  return FALSE;
}

