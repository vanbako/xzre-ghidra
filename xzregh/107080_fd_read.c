// /home/kali/xzre-ghidra/xzregh/107080_fd_read.c
// Function: fd_read @ 0x107080
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall fd_read(int fd, void * buffer, size_t count, libc_imports_t * funcs)


/*
 * AutoDoc: Wraps libc’s read with retry logic. It refuses to run without both `read` and `__errno_location`, loops on EINTR, and aborts
 * with -1 when the helper sees EOF before the requested byte count. Successful reads consume the entire length so callers can
 * treat any non-zero return as "buffer filled".
 */

#include "xzre_types.h"

ssize_t fd_read(int fd,void *buffer,size_t count,libc_imports_t *funcs)

{
  ssize_t sVar1;
  int *piVar2;
  size_t count_00;
  size_t remaining;
  int *errno_slot;
  ssize_t read_chunk;
  
  if (count == 0) {
    return 0;
  }
  if ((((fd < 0) || (funcs == (libc_imports_t *)0x0)) || (funcs->read == (pfn_read_t)0x0)) ||
     (count_00 = count, funcs->__errno_location == (pfn___errno_location_t)0x0)) {
LAB_0010709e:
    count = 0xffffffffffffffff;
  }
  else {
    do {
      while( TRUE ) {
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

