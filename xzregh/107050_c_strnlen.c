// /home/kali/xzre-ghidra/xzregh/107050_c_strnlen.c
// Function: c_strnlen @ 0x107050
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strnlen(char * str, size_t max_len)


/*
 * AutoDoc: Bounded strlen variant used when scanning attacker-controlled buffers. It stops as soon as it
 * sees a NUL or reaches `max_len`, returning the limit unchanged if the string is unterminated so
 * callers can treat that as an error.
 */
#include "xzre_types.h"


ssize_t c_strnlen(char *str,size_t max_len)

{
  size_t sVar1;
  ssize_t len;
  
  sVar1 = 0;
  if (max_len == 0) {
    return max_len;
  }
  do {
    if (str[sVar1] == '\0') {
      return sVar1;
    }
    sVar1 = sVar1 + 1;
  } while (max_len != sVar1);
  return max_len;
}

