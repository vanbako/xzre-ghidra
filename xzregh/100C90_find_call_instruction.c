// /home/kali/xzre-ghidra/xzregh/100C90_find_call_instruction.c
// Function: find_call_instruction @ 0x100C90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_call_instruction(u8 * code_start, u8 * code_end, u8 * call_target, dasm_ctx_t * dctx)


/*
 * AutoDoc: Appends a secret-data breadcrumb, zeros the caller-supplied (or temporary) `dasm_ctx_t`, and walks `[code_start, code_end)` with `x86_dasm`. Decode failures advance by one byte, while successes advance by `instruction_size` until the normalised CALL opcode (`0x168`) is seen. When `call_target` is non-NULL it further requires the rel32 destination (`instruction + instruction_size + imm_signed`) to match before returning TRUE. On success the context still describes the CALL so callers can immediately rewrite or inspect it.
 */

#include "xzre_types.h"

BOOL find_call_instruction(u8 *code_start,u8 *code_end,u8 *call_target,dasm_ctx_t *dctx)

{
  BOOL decode_ok;
  long clear_idx;
  dasm_ctx_t *ctx_zero_cursor;
  byte ctx_zero_stride;
  dasm_ctx_t scratch_ctx;
  
  ctx_zero_stride = 0;
  decode_ok = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x81,4,7);
  if (decode_ok != FALSE) {
    ctx_zero_cursor = &scratch_ctx;
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(undefined4 *)&ctx_zero_cursor->instruction = 0;
      ctx_zero_cursor = (dasm_ctx_t *)((long)ctx_zero_cursor + ((ulong)ctx_zero_stride * -2 + 1) * 4);
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

