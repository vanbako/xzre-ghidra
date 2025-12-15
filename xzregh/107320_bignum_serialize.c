// /home/kali/xzre-ghidra/xzregh/107320_bignum_serialize.c
// Function: bignum_serialize @ 0x107320
// Calling convention: __stdcall
// Prototype: BOOL __stdcall bignum_serialize(u8 * buffer, u64 bufferSize, u64 * pOutSize, BIGNUM * bn, imported_funcs_t * funcs)


/*
 * AutoDoc: Normalises a BIGNUM into the `[len||value]` framing used by the fingerprinting helpers. It refuses NULL inputs, requires at least six bytes of scratch space, caps magnitudes at 0x4000 bits (0x2001 bytes with the optional sign byte), emits a four-byte big-endian length, and copies the magnitude. When the highest value bit would otherwise set the sign bit it prepends a zero byte; otherwise it memmoves the data down so the caller sees a tightly packed blob. Successful runs report the exact number of bytes written back through `*pOutSize` so callers can concatenate multiple serialisations safely.
 */
#include "xzre_types.h"

BOOL bignum_serialize(u8 *buffer,u64 bufferSize,u64 *pOutSize,BIGNUM *bn,imported_funcs_t *funcs)

{
  u32 bit_length_bits;
  int written_bytes;
  size_t value_len_bytes;
  
  // AutoDoc: All callers must provide a non-NULL BIGNUM, at least `[len(4) + value(>=1)]` bytes of scratch, and the BN helpers before any work begins.
  if (((funcs != (imported_funcs_t *)0x0 && 5 < bufferSize) && (bn != (BIGNUM *)0x0)) &&
     (funcs->BN_bn2bin != (pfn_BN_bn2bin_t)0x0)) {
    *pOutSize = 0;
    if (((funcs->BN_num_bits != (pfn_BN_num_bits_t)0x0) &&
        // AutoDoc: Reject values larger than 0x4000 bits so the stack scratch buffer never overflows.
        (bit_length_bits = (*funcs->BN_num_bits)(bn), bit_length_bits < 0x4001)) &&
       ((bit_length_bits = bit_length_bits + 7 >> 3, bit_length_bits != 0 && (value_len_bytes = (ulong)bit_length_bits, value_len_bytes <= bufferSize - 6)))) {
      buffer[4] = '\0';
      // AutoDoc: Serialise the magnitude directly after the length field; the spare byte at `buffer[4]` gives us room to insert a leading zero if needed.
      written_bytes = (*funcs->BN_bn2bin)(bn,buffer + 5);
      if ((long)written_bytes == value_len_bytes) {
        // AutoDoc: When the uppermost bit is 1 treat the value as negative: insert a zero byte and bump the reported length, otherwise slide the payload down to fill the placeholder.
        if ((char)buffer[5] < '\0') {
          value_len_bytes = value_len_bytes + 1;
          bit_length_bits = bit_length_bits + 1;
        }
        else {
          c_memmove((char *)(buffer + 4),(char *)(buffer + 5),value_len_bytes);
        }
        // AutoDoc: Write the big-endian length header last so callers can parse the `[len||value]` blob without re-counting.
        *(uint *)buffer =
             bit_length_bits >> 0x18 | (bit_length_bits & 0xff0000) >> 8 | (bit_length_bits & 0xff00) << 8 | bit_length_bits << 0x18;
        *pOutSize = value_len_bytes + 4;
        return TRUE;
      }
    }
  }
  return FALSE;
}

