// /home/kali/xzre-ghidra/xzregh/101B30_c_memmove.c
// Function: c_memmove @ 0x101B30
// Calling convention: __stdcall
// Prototype: void * __stdcall c_memmove(char * dest, char * src, size_t cnt)


/*
 * AutoDoc: Private implementation of `memmove` so the object never has to import libc for something this trivial. It detects backwards overlap (`src < dest < src+cnt`) and copies from the end towards the beginning in that case; every other scenario devolves into a forward copy loop. Either way the original `dest` pointer is returned so callers can chain copies just like they would with the libc version.
 */
#include "xzre_types.h"


void * c_memmove(char *dest,char *src,size_t cnt)

{
  long lVar1;
  size_t sVar2;
  size_t curr;
  
  if ((src < dest) && (dest < src + cnt)) {
    lVar1 = cnt - 1;
    if (cnt != 0) {
      do {
        dest[lVar1] = src[lVar1];
        lVar1 = lVar1 + -1;
      } while (lVar1 != -1);
      return dest;
    }
  }
  else {
    sVar2 = 0;
    if (cnt == 0) {
      return dest;
    }
    do {
      dest[sVar2] = src[sVar2];
      sVar2 = sVar2 + 1;
    } while (cnt != sVar2);
  }
  return dest;
}

