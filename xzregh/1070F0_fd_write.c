// /home/kali/xzre-ghidra/xzregh/1070F0_fd_write.c
// Function: fd_write @ 0x1070F0
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall fd_write(int fd, void * buffer, size_t count, libc_imports_t * funcs)


/*
 * AutoDoc: Write-side twin of `fd_read`. It demands working `write`/`__errno_location` imports, retries short-term EINTR failures, and
 * falls back to -1 if the kernel reports 0 bytes or any other error before the requested `count` is flushed.
 */

#include "xzre_types.h"

ssize_t fd_write(int fd,void *buffer,size_t count,libc_imports_t *funcs)

{
  ssize_t chunk_size;
  int *errno_value_ptr;
  size_t bytes_left;
  
  if (count == 0) {
    return 0;
  }
  if ((((funcs == (libc_imports_t *)0x0 || fd < 0) || (buffer == (void *)0x0)) ||
      (funcs->write == (pfn_write_t)0x0)) ||
     // AutoDoc: Guard against bad descriptors, NULL buffers, or missing libc shims before attempting the write.
     (bytes_left = count, funcs->__errno_location == (pfn___errno_location_t)0x0)) {
LAB_0010711f:
    count = 0xffffffffffffffff;
  }
  else {
    do {
      while( TRUE ) {
        // AutoDoc: Issue blocking writes until the entire buffer is sent or an unrecoverable error appears.
        chunk_size = (*funcs->write)(fd,buffer,bytes_left);
        if (-1 < chunk_size) break;
        errno_value_ptr = (*funcs->__errno_location)();
        // AutoDoc: Only EINTR causes a retry; any other errno aborts and returns -1.
        if (*errno_value_ptr != 4) goto LAB_0010711f;
      }
      // AutoDoc: A zero-byte write means the peer closed early, so propagate -1 to signal the failure.
      if (chunk_size == 0) goto LAB_0010711f;
      // AutoDoc: Advance the source pointer and remaining byte count after every successful chunk.
      buffer = (void *)((long)buffer + chunk_size);
      bytes_left = bytes_left - chunk_size;
    } while (bytes_left != 0);
  }
  return count;
}

