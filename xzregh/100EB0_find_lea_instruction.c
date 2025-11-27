// /home/kali/xzre-ghidra/xzregh/100EB0_find_lea_instruction.c
// Function: find_lea_instruction @ 0x100EB0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_lea_instruction(u8 * code_start, u8 * code_end, u64 displacement)


/*
 * AutoDoc: Telemetry-backed search for LEA instructions that materialise a specific displacement.
 * It emits `secret_data_append_from_call_site`, clears the stack-resident decoder via the `ctx_clear_idx` / `ctx_clear_cursor` loop (the odd `ctx_stride_sign` artefact simply keeps the stride positive), and then decodes forward one byte at a time until it sees opcode `0x10d` with DF2 reporting a plain displacement operand.
 * Either `displacement` or its negated twin qualifies, letting mirrored scans succeed, and the populated `lea_ctx` is left in place so callers can immediately interrogate the operands.
 */

#include "xzre_types.h"

BOOL find_lea_instruction(u8 *code_start,u8 *code_end,u64 displacement)

{
  BOOL decoded;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  byte ctx_stride_sign;
  dasm_ctx_t lea_ctx;
  
  ctx_stride_sign = 0;
  decoded = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x7c,5,6,FALSE);
  // AutoDoc: Breadcrumb the scan so we know which helper touched each code window.
  if (decoded != FALSE) {
    ctx_clear_cursor = &lea_ctx;
    // AutoDoc: Reset the decoder context between attempts (the stride sign flip is a compiler artefact).
    for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
      *(u32 *)&ctx_clear_cursor->instruction = 0;
      ctx_clear_cursor = (dasm_ctx_t *)((long)ctx_clear_cursor + ((ulong)ctx_stride_sign * -2 + 1) * 4);
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      // AutoDoc: Decode byte-by-byte until a LEA with a bare displacement materialises.
      decoded = x86_dasm(&lea_ctx,code_start,code_end);
      if ((((decoded != FALSE) && (*(u32 *)&lea_ctx.opcode_window[3] == 0x10d)) &&
      // AutoDoc: Accept mirrored displacements so searches anchored at ±delta both succeed.
          ((lea_ctx.prefix.decoded.flags2 & 7) == 1)) &&
         ((lea_ctx.mem_disp == displacement || (lea_ctx.mem_disp == -displacement)))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

