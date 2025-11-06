// /home/kali/xzre-ghidra/xzregh/107920_sshbuf_bignum_is_negative.c
// Function: sshbuf_bignum_is_negative @ 0x107920
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshbuf_bignum_is_negative(sshbuf * buf)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief checks if the given serialized BIGNUM is negative
 *
 *   @param buf buffer containing a serialized BIGNUM
 *   @return BOOL TRUE if the serialized BIGNUM is negative, FALSE otherwise
 */

BOOL sshbuf_bignum_is_negative(sshbuf *buf)

{
  BOOL BVar1;
  size_t sVar2;
  
  BVar1 = 0;
  if (buf->size - 0x20 < 0x21) {
    sVar2 = 0;
    while (-1 < (char)buf->d[sVar2]) {
      sVar2 = sVar2 + 1;
      if (buf->size == sVar2) {
        return 0;
      }
    }
    BVar1 = 1;
  }
  return BVar1;
}

