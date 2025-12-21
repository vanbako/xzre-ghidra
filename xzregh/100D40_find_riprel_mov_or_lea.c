// /home/kali/xzre-ghidra/xzregh/100D40_find_riprel_mov_or_lea.c
// Function: find_riprel_mov_or_lea @ 0x100D40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_riprel_mov_or_lea(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: Hybrid MOV/LEA predicate that underpins the pointer scanners.
 * It clears the stack fallback decoder (via `ctx_clear_idx` / `ctx_clear_cursor`) and uses it when `dctx` is NULL, then marches forward either by one byte (decode failure) or by `instruction_size` (success).
 * Matches require the RIP-relative ModRM form (`mod=0`, `rm=5`) plus either LEA (`0x10d`, raw `0x8d`) or the MOV opcode selected by `load_flag` (`0x10b` load / `0x109` store; raw `0x8b`/`0x89` after the decoder’s +0x80 normalization). Loads enforce REX.W presence to match `is_64bit_operand`; stores skip the width check. Returning TRUE leaves `dctx` describing the matching instruction for downstream helpers.
 */

#include "xzre_types.h"

BOOL find_riprel_mov_or_lea
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  u32 decoded_opcode;
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
      decoded = x86_decode_instruction(dctx,code_start,code_end);
      if (decoded != FALSE) break;
      // AutoDoc: Failed decodes advance byte-by-byte until the next valid opcode appears.
      code_start = code_start + 1;
    }
    if ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) &&
    // AutoDoc: Only accept RIP-relative disp32 (ModRM `mod=0`, `rm=5`) plus the caller-requested width (unless we are hunting stores).
       (((((dctx->prefix).modrm_bytes.rex_byte & 0x48) == 0x48) == is_64bit_operand ||
        (load_flag == FALSE)))) {
      decoded_opcode = dctx->opcode_window_dword;
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

