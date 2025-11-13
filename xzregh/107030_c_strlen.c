// /home/kali/xzre-ghidra/xzregh/107030_c_strlen.c
// Function: c_strlen @ 0x107030
// Calling convention: unknown
// Prototype: undefined c_strlen(void)


/*
 * AutoDoc: Tiny strlen implementation that stage two uses before libc is trustworthy. It simply walks the
 * buffer one byte at a time and returns the length as a signed size, allowing other helpers to
 * sanity-check argv/envp strings without resolving libc symbols.
 */
#include "xzre_types.h"


long c_strlen(char *param_1)

{
  long lVar1;
  
  if (*param_1 != '\0') {
    lVar1 = 0;
    do {
      lVar1 = lVar1 + 1;
    } while (param_1[lVar1] != '\0');
    return lVar1;
  }
  return 0;
}

