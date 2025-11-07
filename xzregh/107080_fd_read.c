// /home/kali/xzre-ghidra/xzregh/107080_fd_read.c
// Function: fd_read @ 0x107080
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall fd_read(int fd, void * buffer, size_t count, libc_imports_t * funcs)
/*
 * AutoDoc: Wrapper around libc's read that retries on EINTR and honours the resolver-provided imports table. All socket reads during monitor spoofing go through it so the implant never depends on glibc symbols directly.
 */

#include "xzre_types.h"


ssize_t fd_read(int fd,void *buffer,size_t count,libc_imports_t *funcs)

{
  ssize_t sVar1;
  int *piVar2;
  size_t count_00;
  
  if (count == 0) {
    return 0;
  }
  if ((((fd < 0) || (funcs == (libc_imports_t *)0x0)) || (funcs->read == (_func_25 *)0x0)) ||
     (count_00 = count, funcs->__errno_location == (_func_26 *)0x0)) {
LAB_0010709e:
    count = 0xffffffffffffffff;
  }
  else {
    do {
      while( true ) {
        sVar1 = (*funcs->read)(fd,buffer,count_00);
        if (-1 < sVar1) break;
        piVar2 = (*funcs->__errno_location)();
        if (*piVar2 != 4) goto LAB_0010709e;
      }
      if (sVar1 == 0) goto LAB_0010709e;
      buffer = (void *)((long)buffer + sVar1);
      count_00 = count_00 - sVar1;
    } while (count_00 != 0);
  }
  return count;
}

