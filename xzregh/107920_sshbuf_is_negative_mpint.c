// /home/kali/xzre-ghidra/xzregh/107920_sshbuf_is_negative_mpint.c
// Function: sshbuf_is_negative_mpint @ 0x107920
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshbuf_is_negative_mpint(sshbuf * buf)


/*
 * AutoDoc: Treats an `sshbuf` as a serialized big integer. Only buffers between 0x20 and 0x40 bytes qualify; the helper scans until it
 * finds a byte with the sign bit set and tags the buffer as a "negative" modulus candidate. Any buffer that never trips the MSB
 * probe (or sits outside the size window) is rejected.
 */

#include "xzre_types.h"

BOOL sshbuf_is_negative_mpint(sshbuf *buf)

{
  BOOL has_negative_mark;
  size_t payload_offset;
  
  has_negative_mark = FALSE;
  // AutoDoc: Enforce the expected `[0x20, 0x40]` payload span—anything shorter/longer clearly is not the forged modulus.
  if (buf->size - 0x20 < 0x21) {
    payload_offset = 0;
    // AutoDoc: Walk forward until a byte with bit 7 set appears; if we hit the end first the buffer is not considered negative.
    while (-1 < (char)buf->d[payload_offset]) {
      payload_offset = payload_offset + 1;
      if (buf->size == payload_offset) {
        return FALSE;
      }
    }
    has_negative_mark = TRUE;
  }
  return has_negative_mark;
}

