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
  u32 bit_length_bits;
  int written_bytes;
  size_t value_len_bytes;
  
  if (((funcs != (imported_funcs_t *)0x0 && 5 < bufferSize) && (bn != (BIGNUM *)0x0)) &&
     (funcs->BN_bn2bin != (pfn_BN_bn2bin_t)0x0)) {
    *pOutSize = 0;
    if (((funcs->BN_num_bits != (pfn_BN_num_bits_t)0x0) &&
        (bit_length_bits = (*funcs->BN_num_bits)(bn), bit_length_bits < 0x4001)) &&
       ((bit_length_bits = bit_length_bits + 7 >> 3, bit_length_bits != 0 && (value_len_bytes = (ulong)bit_length_bits, value_len_bytes <= bufferSize - 6)))) {
      buffer[4] = '\0';
      written_bytes = (*funcs->BN_bn2bin)(bn,buffer + 5);
      if ((long)written_bytes == value_len_bytes) {
        if ((char)buffer[5] < '\0') {
          value_len_bytes = value_len_bytes + 1;
          bit_length_bits = bit_length_bits + 1;
        }
        else {
          c_memmove((char *)(buffer + 4),(char *)(buffer + 5),value_len_bytes);
        }
        *(uint *)buffer =
             bit_length_bits >> 0x18 | (bit_length_bits & 0xff0000) >> 8 | (bit_length_bits & 0xff00) << 8 | bit_length_bits << 0x18;
        *pOutSize = value_len_bytes + 4;
        return TRUE;
      }
    }
  }
  return FALSE;
}

