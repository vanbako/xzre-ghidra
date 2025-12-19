// /home/kali/xzre-ghidra/xzregh/1070F0_fd_write_full.c
// Function: fd_write_full @ 0x1070F0
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall fd_write_full(int fd, void * buffer, size_t count, libc_imports_t * funcs)


/*
 * AutoDoc: Write-side twin of `fd_read_full`. It demands working `write`/`__errno_location` imports, retries short-term EINTR failures, and
 * falls back to -1 if the kernel reports 0 bytes or any other error before the requested `count` is flushed.
 */

#include "xzre_types.h"

ssize_t fd_write_full(int fd,void *buffer,size_t count,libc_imports_t *funcs)

{
  ssize_t bytes_written;
  int *errno_ptr;
  size_t bytes_remaining;
  
  // AutoDoc: Zero-length writes short-circuit successfully without touching the import table.
  if (count == 0) {
    return 0;
  }
  if ((((funcs == (libc_imports_t *)0x0 || fd < 0) || (buffer == (void *)0x0)) ||
      (funcs->write == (pfn_write_t)0x0)) ||
     // AutoDoc: Guard against bad descriptors, NULL buffers, or missing libc shims before attempting the write.
     (bytes_remaining = count, funcs->__errno_location == (pfn___errno_location_t)0x0)) {
LAB_0010711f:
    // AutoDoc: All validation failures, zero-byte writes, and unrecoverable errno values collapse to -1.
    count = 0xffffffffffffffff;
  }
  else {
    do {
      while( TRUE ) {
        // AutoDoc: Issue blocking writes until the entire buffer is sent or an unrecoverable error appears.
        bytes_written = (*funcs->write)(fd,buffer,bytes_remaining);
        if (-1 < bytes_written) break;
        errno_ptr = (*funcs->__errno_location)();
        // AutoDoc: Only EINTR causes a retry; any other errno aborts and returns -1.
        if (*errno_ptr != 4) goto LAB_0010711f;
      }
      // AutoDoc: A zero-byte write means the peer closed early, so propagate -1 to signal the failure.
      if (bytes_written == 0) goto LAB_0010711f;
      // AutoDoc: Advance the source pointer and remaining byte count after every successful chunk.
      buffer = (void *)((long)buffer + bytes_written);
      bytes_remaining = bytes_remaining - bytes_written;
    } while (bytes_remaining != 0);
  }
  return count;
}

