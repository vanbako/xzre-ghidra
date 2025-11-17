// /home/kali/xzre-ghidra/xzregh/107320_bignum_serialize.c
// Function: bignum_serialize @ 0x107320
// Calling convention: __stdcall
// Prototype: BOOL __stdcall bignum_serialize(u8 * buffer, u64 bufferSize, u64 * pOutSize, BIGNUM * bn, imported_funcs_t * funcs)


/*
 * AutoDoc: Normalises a BIGNUM into the [len||value] format used by the fingerprinting code. It caps inputs at 0x4000 bits, emits a 4-byte
 * big-endian length, copies the magnitude, and prepends a zero byte (or memmoves the data) whenever the top bit would otherwise
 * make the number negative so SHA-256 sees a canonical stream.
 */

#include "xzre_types.h"

BOOL bignum_serialize(u8 *buffer,u64 bufferSize,u64 *pOutSize,BIGNUM *bn,imported_funcs_t *funcs)

{
  uint bit_length;
  int written_bytes;
  ulong value_len;
  
  if (((funcs != (imported_funcs_t *)0x0 && 5 < bufferSize) && (bn != (BIGNUM *)0x0)) &&
     (funcs->BN_bn2bin != (pfn_BN_bn2bin_t)0x0)) {
    *pOutSize = 0;
    if (((funcs->BN_num_bits != (pfn_BN_num_bits_t)0x0) &&
        (bit_length = (*funcs->BN_num_bits)(bn), bit_length < 0x4001)) &&
       ((bit_length = bit_length + 7 >> 3, bit_length != 0 && (value_len = (ulong)bit_length, value_len <= bufferSize - 6)))) {
      buffer[4] = '\0';
      written_bytes = (*funcs->BN_bn2bin)(bn,buffer + 5);
      if ((long)written_bytes == value_len) {
        if ((char)buffer[5] < '\0') {
          value_len = value_len + 1;
          bit_length = bit_length + 1;
        }
        else {
          c_memmove((char *)(buffer + 4),(char *)(buffer + 5),value_len);
        }
        *(uint *)buffer =
             bit_length >> 0x18 | (bit_length & 0xff0000) >> 8 | (bit_length & 0xff00) << 8 | bit_length << 0x18;
        *pOutSize = value_len + 4;
        return TRUE;
      }
    }
  }
  return FALSE;
}

