// /home/kali/xzre-ghidra/xzregh/107080_fd_read.c
// Function: fd_read @ 0x107080
// Calling convention: __stdcall
// Prototype: ssize_t __stdcall fd_read(int fd, void * buffer, size_t count, libc_imports_t * funcs)


/*
 * AutoDoc: Libc `read` wrapper with strict import validation. It refuses to run unless both `read` and `__errno_location` are present,
 * loops on EINTR, and treats EOF/short reads as fatal so callers either receive -1 or know the entire `count` bytes were filled.
 */

#include "xzre_types.h"

ssize_t fd_read(int fd,void *buffer,size_t count,libc_imports_t *funcs)

{
  ssize_t bytes_read;
  int *errno_ptr;
  size_t bytes_remaining;
  
  // AutoDoc: Zero-length reads short-circuit successfully without touching the import table.
  if (count == 0) {
    return 0;
  }
  if ((((fd < 0) || (funcs == (libc_imports_t *)0x0)) || (funcs->read == (pfn_read_t)0x0)) ||
     // AutoDoc: Bail out unless the caller supplied valid `libc_imports_t` hooks and a non-negative fd.
     (bytes_remaining = count, funcs->__errno_location == (pfn___errno_location_t)0x0)) {
LAB_0010709e:
    // AutoDoc: All validation failures, EOF, and unrecoverable errno values collapse to -1.
    count = 0xffffffffffffffff;
  }
  else {
    do {
      while( TRUE ) {
        // AutoDoc: Retry the read until it succeeds or an error other than EINTR surfaces.
        bytes_read = (*funcs->read)(fd,buffer,bytes_remaining);
        if (-1 < bytes_read) break;
        errno_ptr = (*funcs->__errno_location)();
        // AutoDoc: Only EINTR (errno == 4) causes a retry; every other errno trips the failure path.
        if (*errno_ptr != 4) goto LAB_0010709e;
      }
      // AutoDoc: Treat EOF before `count` bytes have been read as a fatal short read.
      if (bytes_read == 0) goto LAB_0010709e;
      // AutoDoc: Advance the moving buffer pointer and remaining byte counter after every successful chunk.
      buffer = (void *)((long)buffer + bytes_read);
      bytes_remaining = bytes_remaining - bytes_read;
    } while (bytes_remaining != 0);
  }
  return count;
}

