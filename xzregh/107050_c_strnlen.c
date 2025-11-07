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
  ssize_t len;
  
  len = 0;
  if (max_len == 0) {
    return max_len;
  }
  do {
    if (str[len] == '\0') {
      return len;
    }
    len = len + 1;
  } while (max_len != len);
  return max_len;
}

