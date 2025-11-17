// /home/kali/xzre-ghidra/xzregh/1070F0_fd_write.c
// Function: fd_write @ 0x1070F0
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall fd_write(int fd, void * buffer, size_t count, libc_imports_t * funcs)


/*
 * AutoDoc: Mirror of `fd_read`: it requires valid write/errno pointers, retries on EINTR, and treats short writes as fatal so callers
 * either send the entire buffer or receive -1. It is the plumbing used whenever the implant forges monitor messages.
 */

#include "xzre_types.h"

ssize_t fd_write(int fd,void *buffer,size_t count,libc_imports_t *funcs)

{
  ssize_t write_chunk;
  int *errno_slot;
  size_t remaining;
  
  if (count == 0) {
    return 0;
  }
  if ((((funcs == (libc_imports_t *)0x0 || fd < 0) || (buffer == (void *)0x0)) ||
      (funcs->write == (pfn_write_t)0x0)) ||
     (remaining = count, funcs->__errno_location == (pfn___errno_location_t)0x0)) {
LAB_0010711f:
    count = 0xffffffffffffffff;
  }
  else {
    do {
      while( TRUE ) {
        write_chunk = (*funcs->write)(fd,buffer,remaining);
        if (-1 < write_chunk) break;
        errno_slot = (*funcs->__errno_location)();
        if (*errno_slot != 4) goto LAB_0010711f;
      }
      if (write_chunk == 0) goto LAB_0010711f;
      buffer = (void *)((long)buffer + write_chunk);
      remaining = remaining - write_chunk;
    } while (remaining != 0);
  }
  return count;
}

