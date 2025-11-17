// /home/kali/xzre-ghidra/xzregh/101020_find_string_reference.c
// Function: find_string_reference @ 0x101020
// Calling convention: __stdcall
// Prototype: u8 * __stdcall find_string_reference(u8 * code_start, u8 * code_end, char * str)


/*
 * AutoDoc: Convenience wrapper that returns the instruction which first references a given string literal.
 * It simply calls `find_lea_instruction_with_mem_operand` across `[code_start, code_end)` with `str` as the desired absolute address and, when successful, yields the LEA’s address so later heuristics can treat it as the anchor for the surrounding function.
 */

#include "xzre_types.h"

u8 * find_string_reference(u8 *code_start,u8 *code_end,char *str)

{
  BOOL decode_ok;
  u8 *xref;
  long clear_idx;
  dasm_ctx_t *zero_ctx;
  dasm_ctx_t scratch_ctx;
  
  zero_ctx = &scratch_ctx;
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(undefined4 *)&zero_ctx->instruction = 0;
    zero_ctx = (dasm_ctx_t *)((long)&zero_ctx->instruction + 4);
  }
  decode_ok = find_lea_instruction_with_mem_operand(code_start,code_end,&scratch_ctx,str);
  xref = (u8 *)0x0;
  if (decode_ok != FALSE) {
    xref = scratch_ctx.instruction;
  }
  return xref;
}

