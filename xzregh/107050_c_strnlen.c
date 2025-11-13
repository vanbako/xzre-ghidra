// /home/kali/xzre-ghidra/xzregh/107050_c_strnlen.c
// Function: c_strnlen @ 0x107050
// Calling convention: unknown
// Prototype: undefined c_strnlen(void)


/*
 * AutoDoc: Bounded strlen variant used when scanning attacker-controlled buffers. It stops as soon as it
 * sees a NUL or reaches `max_len`, returning the limit unchanged if the string is unterminated so
 * callers can treat that as an error.
 */
#include "xzre_types.h"


long c_strnlen(long param_1,long param_2)

{
  long lVar1;
  
  lVar1 = 0;
  if (param_2 == 0) {
    return param_2;
  }
  do {
    if (*(char *)(param_1 + lVar1) == '\0') {
      return lVar1;
    }
    lVar1 = lVar1 + 1;
  } while (param_2 != lVar1);
  return param_2;
}

