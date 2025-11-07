// /home/kali/xzre-ghidra/xzregh/107030_c_strlen.c
// Function: c_strlen @ 0x107030
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall c_strlen(char * str)


/*
 * AutoDoc: Minimal strlen implementation that the loader can call before libc is safe to use. It shows up when scanning sshd buffers for protocol markers during the backdoor's environment checks.
 */
#include "xzre_types.h"


ssize_t c_strlen(char *str)

{
  long lVar1;
  ssize_t len;
  
  if (*str != '\0') {
    lVar1 = 0;
    do {
      lVar1 = lVar1 + 1;
    } while (str[lVar1] != '\0');
    return lVar1;
  }
  return 0;
}

