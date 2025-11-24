// /home/kali/xzre-ghidra/xzregh/107030_c_strlen.c
// Function: c_strlen @ 0x107030
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strlen(char * str)


/*
 * AutoDoc: Stage-two strlen replacement that runs before libc is trustworthy. It assumes `str` already points to a readable buffer,
 * short-circuits when the first byte is NUL, and otherwise increments a counter until it encounters `\0`, returning the byte count
 * as a signed size.
 */

#include "xzre_types.h"

ssize_t c_strlen(char *str)

{
  ssize_t bytes_counted;
  
  // AutoDoc: Skip the scan entirely when the buffer already begins with a terminator so empty strings return 0 immediately.
  if (*str != '\0') {
    bytes_counted = 0;
    do {
      bytes_counted = bytes_counted + 1;
    // AutoDoc: Walk byte-by-byte until a NUL sentinel shows up; the total bytes seen becomes the returned length.
    } while (str[bytes_counted] != '\0');
    return bytes_counted;
  }
  return 0;
}

