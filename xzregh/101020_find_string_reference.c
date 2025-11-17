// /home/kali/xzre-ghidra/xzregh/101020_find_string_reference.c
// Function: find_string_reference @ 0x101020
// Calling convention: __stdcall
// Prototype: u8 * __stdcall find_string_reference(u8 * code_start, u8 * code_end, char * str)


/*
 * AutoDoc: Zeroes a scratch decoder and asks `find_lea_instruction_with_mem_operand` to locate the first LEA in `[code_start, code_end)` that materialises the absolute address `str`.
 * Returns the LEA's address as the xref anchor or NULL when no such reference exists.
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

