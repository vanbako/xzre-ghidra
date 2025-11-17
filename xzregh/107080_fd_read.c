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
  ssize_t read_chunk;
  int *errno_slot;
  size_t remaining;
  
  if (count == 0) {
    return 0;
  }
  if ((((fd < 0) || (funcs == (libc_imports_t *)0x0)) || (funcs->read == (pfn_read_t)0x0)) ||
     (remaining = count, funcs->__errno_location == (pfn___errno_location_t)0x0)) {
LAB_0010709e:
    count = 0xffffffffffffffff;
  }
  else {
    do {
      while( TRUE ) {
        read_chunk = (*funcs->read)(fd,buffer,remaining);
        if (-1 < read_chunk) break;
        errno_slot = (*funcs->__errno_location)();
        if (*errno_slot != 4) goto LAB_0010709e;
      }
      if (read_chunk == 0) goto LAB_0010709e;
      buffer = (void *)((long)buffer + read_chunk);
      remaining = remaining - read_chunk;
    } while (remaining != 0);
  }
  return count;
}

