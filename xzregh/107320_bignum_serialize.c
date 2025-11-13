// /home/kali/xzre-ghidra/xzregh/107320_bignum_serialize.c
// Function: bignum_serialize @ 0x107320
// Calling convention: __stdcall
// Prototype: BOOL __stdcall bignum_serialize(u8 * buffer, u64 bufferSize, u64 * pOutSize, BIGNUM * bn, imported_funcs_t * funcs)


/*
 * AutoDoc: Writes a BIGNUM into a length-prefixed buffer, dropping redundant leading zeros so later hashes are stable. Key-fingerprinting helpers call it before running SHA256 over RSA or DSA parameters.
 */
#include "xzre_types.h"


BOOL bignum_serialize(u8 *buffer,u64 bufferSize,u64 *pOutSize,BIGNUM *bn,imported_funcs_t *funcs)

{
  uint uVar1;
  int iVar2;
  ulong cnt;
  
  if (((funcs != (imported_funcs_t *)0x0 && 5 < bufferSize) && (bn != (BIGNUM *)0x0)) &&
     (funcs->BN_bn2bin != (pfn_BN_bn2bin_t)0x0)) {
    *pOutSize = 0;
    if (((funcs->BN_num_bits != (pfn_BN_num_bits_t)0x0) &&
        (uVar1 = (*funcs->BN_num_bits)(bn), uVar1 < 0x4001)) &&
       ((uVar1 = uVar1 + 7 >> 3, uVar1 != 0 && (cnt = (ulong)uVar1, cnt <= bufferSize - 6)))) {
      buffer[4] = '\0';
      iVar2 = (*funcs->BN_bn2bin)(bn,buffer + 5);
      if ((long)iVar2 == cnt) {
        if ((char)buffer[5] < '\0') {
          cnt = cnt + 1;
          uVar1 = uVar1 + 1;
        }
        else {
          c_memmove((char *)(buffer + 4),(char *)(buffer + 5),cnt);
        }
        *(uint *)buffer =
             uVar1 >> 0x18 | (uVar1 & 0xff0000) >> 8 | (uVar1 & 0xff00) << 8 | uVar1 << 0x18;
        *pOutSize = cnt + 4;
        return TRUE;
      }
    }
  }
  return FALSE;
}

