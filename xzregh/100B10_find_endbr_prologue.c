// /home/kali/xzre-ghidra/xzregh/100B10_find_endbr_prologue.c
// Function: find_endbr_prologue @ 0x100B10
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_endbr_prologue(u8 * code_start, u8 * code_end, u8 * * output, FuncFindType find_mode)


/*
 * AutoDoc: Recognises CET-style prologues. In `FIND_ENDBR64` mode it zeroes a scratch `dasm_ctx_t`, asks `x86_decode_instruction` to decode at `code_start`, requires the normalised opcode to be ENDBR64, and only succeeds if the ENDBR padding ends on a 16-byte boundary (optionally returning the instruction immediately after the pad through `output`). Legacy mode skips the decoder and reuses `is_endbr32_or_64` with the simple mask; when it hits it reports the exact byte it just tested so callers can keep walking until they find the landing pad they need.
 */

#include "xzre_types.h"

BOOL find_endbr_prologue(u8 *code_start,u8 *code_end,u8 **output,FuncFindType find_mode)

{
  BOOL prologue_found;
  BOOL decoded;
  long clear_idx;
  dasm_ctx_t *ctx_zero_cursor;
  dasm_ctx_t prologue_ctx;
  
  if (find_mode == FIND_ENDBR64) {
    ctx_zero_cursor = &prologue_ctx;
    // AutoDoc: Zero a scratch decoder context so we can peek at the opcode without mutating caller state.
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(u32 *)&ctx_zero_cursor->instruction = 0;
      ctx_zero_cursor = (dasm_ctx_t *)((u8 *)ctx_zero_cursor + 4);
    }
    decoded = x86_decode_instruction(&prologue_ctx,code_start,code_end);
    prologue_found = FALSE;
    if (((decoded != FALSE) && (prologue_ctx.opcode_window_dword == 3999)) &&
    // AutoDoc: Valid ENDBR pads must end on a 16-byte boundary; optionally hand the caller the next byte.
       (((ulong)(prologue_ctx.instruction + prologue_ctx.instruction_size) & 0xf) == 0)) {
      if (output != (u8 **)0x0) {
        *output = prologue_ctx.instruction + prologue_ctx.instruction_size;
      }
      prologue_found = TRUE;
    }
  }
  else {
    prologue_found = is_endbr32_or_64(code_start,code_end,0xe230);
    // AutoDoc: Legacy mode simply reports the matching byte so the caller can keep searching.
    if (prologue_found != FALSE) {
      if (output != (u8 **)0x0) {
        *output = code_start;
      }
      prologue_found = TRUE;
    }
  }
  return prologue_found;
}

