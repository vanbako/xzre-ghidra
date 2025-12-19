// /home/kali/xzre-ghidra/xzregh/107EA0_payload_stream_validate_or_poison.c
// Function: payload_stream_validate_or_poison @ 0x107EA0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall payload_stream_validate_or_poison(global_context_t * ctx)


/*
 * AutoDoc: Enforces the payload assembly state machine kept in `global_context_t`: states 1 and 2 require a populated
 * `sshd_payload_ctx`, at least 0xae bytes buffered, and a sane body_length lifted from the decrypted header (including
 * room for the 0x60-byte trailer). State 0 insists that the staging buffer stays smaller than 0xae bytes, while state 3/4
 * accept only those literal values. Any mismatch resets `payload_state` to PAYLOAD_STREAM_POISONED so the caller knows to discard
 * partially buffered data.
 */

#include "xzre_types.h"

BOOL payload_stream_validate_or_poison(global_context_t *ctx)

{
  payload_stream_state_t payload_state;
  ulong payload_total_length;
  BOOL state_in_expected_range;
  BOOL state_matches_exact;
  sshd_payload_ctx_t *payload_ctx;
  u32 payload_length;
  
  if (ctx == (global_context_t *)0x0) {
    return FALSE;
  }
  payload_state = ctx->payload_state;
  if (payload_state < PAYLOAD_STREAM_COMMAND_READY) {
    if (PAYLOAD_STREAM_EXPECT_HEADER < payload_state) {
      // AutoDoc: States 1 and 2 only pass when the decrypted header exists, >= 0xae bytes are buffered, and the advertised payload (plus the 0x60-byte trailer) fits inside `payload_buffer_size`.
      if (((ctx->payload_ctx != (sshd_payload_ctx_t *)0x0) && (0xad < ctx->payload_bytes_buffered))
         && (payload_total_length = (ulong)ctx->payload_ctx->payload_total_size,
            ctx->payload_bytes_buffered <= payload_total_length)) {
        if (payload_total_length <= payload_total_length + 0x60) {
          payload_total_length = payload_total_length + 0x60;
        }
        if (payload_total_length <= ctx->payload_buffer_size) {
          return TRUE;
        }
      }
      goto LAB_00107f11;
    }
    if (payload_state != PAYLOAD_STREAM_EXPECT_HEADER) goto LAB_00107f11;
    // AutoDoc: State 0 is just a guardrail—once the staging buffer hits 0xae bytes the caller must graduate into state 1.
    state_in_expected_range = ctx->payload_bytes_buffered < 0xae;
    state_matches_exact = ctx->payload_bytes_buffered == 0xae;
  }
  else {
    // AutoDoc: States 3 and 4 are literal sentinels; any other value immediately fails the check.
    state_in_expected_range = payload_state == PAYLOAD_STREAM_COMMAND_READY;
    state_matches_exact = payload_state == PAYLOAD_STREAM_DISPATCHED;
  }
  if (state_in_expected_range || state_matches_exact) {
    return TRUE;
  }
LAB_00107f11:
  // AutoDoc: Any violation poisons the state machine so callers drop the partially buffered ciphertext and restart.
  ctx->payload_state = PAYLOAD_STREAM_POISONED;
  return FALSE;
}

