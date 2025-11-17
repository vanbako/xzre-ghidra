// /home/kali/xzre-ghidra/xzregh/100B10_find_function_prologue.c
// Function: find_function_prologue @ 0x100B10
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_function_prologue(u8 * code_start, u8 * code_end, u8 * * output, FuncFindType find_mode)


/*
 * AutoDoc: Validates that a cursor points at the requested prologue style.
 * When `find_mode` asks for CET entries it runs `x86_dasm`, insists the opcode matches the ENDBR64 sequence, and only succeeds if the landing pad ends on a 16-byte boundary (returning the first post-pad instruction through `output`).
 * In the legacy/NOP mode it falls back to `is_endbr64_instruction` with the simpler mask and returns the address itself, allowing callers to keep sweeping until one of the checks passes.
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

