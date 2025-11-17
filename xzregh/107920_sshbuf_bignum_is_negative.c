// /home/kali/xzre-ghidra/xzregh/107920_sshbuf_bignum_is_negative.c
// Function: sshbuf_bignum_is_negative @ 0x107920
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshbuf_bignum_is_negative(sshbuf * buf)


/*
 * AutoDoc: Treats an sshbuf as a serialized big integer. When the payload is between 0x20 and 0x40 bytes it scans forward until it finds a
 * byte with the sign bit set; encountering such a byte before hitting the end marks the buffer as “negative” and therefore
 * suitable for modulus harvesting.
 */

#include "xzre_types.h"

BOOL sshbuf_bignum_is_negative(sshbuf *buf)

{
  BOOL is_negative;
  size_t index;
  
  is_negative = FALSE;
  if (buf->size - 0x20 < 0x21) {
    index = 0;
    while (-1 < (char)buf->d[index]) {
      index = index + 1;
      if (buf->size == index) {
        return FALSE;
      }
    }
    is_negative = TRUE;
  }
  return is_negative;
}

