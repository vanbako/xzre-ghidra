// /home/kali/xzre-ghidra/xzregh/107030_c_strlen.c
// Function: c_strlen @ 0x107030
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strlen(char * str)


/*
 * AutoDoc: Tiny strlen implementation that stage two uses before libc is trustworthy. It simply walks the buffer one byte at a time and
 * returns the length as a signed size, allowing other helpers to sanity-check argv/envp strings without resolving libc symbols.
 */

#include "xzre_types.h"

ssize_t c_strlen(char *str)

{
  ssize_t len;
  
  if (*str != '\0') {
    len = 0;
    do {
      len = len + 1;
    } while (str[len] != '\0');
    return len;
  }
  return 0;
}

