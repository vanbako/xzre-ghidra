// /home/kali/xzre-ghidra/xzregh/107920_sshbuf_bignum_is_negative.c
// Function: sshbuf_bignum_is_negative @ 0x107920
// Calling convention: unknown
// Prototype: undefined sshbuf_bignum_is_negative(void)


/*
 * AutoDoc: Checks whether a serialized BIGNUM is negative by inspecting its buffer layout. Secret-data scanners invoke it to ignore malformed key material pulled from sshd buffers.
 */
#include "xzre_types.h"


undefined8 sshbuf_bignum_is_negative(long *param_1)

{
  long lVar1;
  undefined8 uVar2;
  
  uVar2 = 0;
  if (param_1[3] - 0x20U < 0x21) {
    lVar1 = 0;
    while (-1 < *(char *)(*param_1 + lVar1)) {
      lVar1 = lVar1 + 1;
      if (param_1[3] == lVar1) {
        return 0;
      }
    }
    uVar2 = 1;
  }
  return uVar2;
}

