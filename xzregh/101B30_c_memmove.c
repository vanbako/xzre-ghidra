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
  ssize_t backward_idx;
  size_t forward_idx;
  
  if ((src < dest) && (dest < src + cnt)) {
    backward_idx = cnt - 1;
    if (cnt != 0) {
      do {
        dest[backward_idx] = src[backward_idx];
        backward_idx = backward_idx + -1;
      } while (backward_idx != -1);
      return dest;
    }
  }
  else {
    forward_idx = 0;
    if (cnt == 0) {
      return dest;
    }
    do {
      dest[forward_idx] = src[forward_idx];
      forward_idx = forward_idx + 1;
    } while (cnt != forward_idx);
  }
  return dest;
}

