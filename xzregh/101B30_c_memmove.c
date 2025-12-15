// /home/kali/xzre-ghidra/xzregh/101B30_c_memmove.c
// Function: c_memmove @ 0x101B30
// Calling convention: __stdcall
// Prototype: void * __stdcall c_memmove(char * dest, char * src, size_t cnt)


/*
 * AutoDoc: Private implementation of `memmove` so the object never has to import libc for something this trivial. It detects backwards
 * overlap (`src < dest < src+cnt`) and copies from the end towards the beginning in that case; every other scenario devolves into
 * a forward copy loop. Either way the original `dest` pointer is returned so callers can chain copies just like they would with
 * the libc version.
 */

#include "xzre_types.h"

void * c_memmove(char *dest,char *src,size_t cnt)

{
  ssize_t reverse_idx;
  size_t forward_idx;
  
  // AutoDoc: Backward overlap means copy from the tail first so the source bytes are not clobbered mid-move.
  if ((src < dest) && (dest < src + cnt)) {
    reverse_idx = cnt - 1;
    if (cnt != 0) {
      do {
        dest[reverse_idx] = src[reverse_idx];
        reverse_idx = reverse_idx + -1;
      } while (reverse_idx != -1);
      return dest;
    }
  }
  else {
    forward_idx = 0;
    if (cnt == 0) {
      return dest;
    }
    do {
      // AutoDoc: Linear forward copy covers every other configuration where the ranges do not overlap.
      dest[forward_idx] = src[forward_idx];
      forward_idx = forward_idx + 1;
    } while (cnt != forward_idx);
  }
  return dest;
}

