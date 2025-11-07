// /home/kali/xzre-ghidra/xzregh/107050_c_strnlen.c
// Function: c_strnlen @ 0x107050
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strnlen(char * str, size_t max_len)


/*
 * AutoDoc: Bounded strlen helper used to cap string walks inside untrusted buffers. The backdoor leans on it while parsing ssh login structures so a malformed packet cannot drive the length probes out of bounds.
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

