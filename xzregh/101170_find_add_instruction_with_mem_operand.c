// /home/kali/xzre-ghidra/xzregh/101170_find_add_instruction_with_mem_operand.c
// Function: find_add_instruction_with_mem_operand @ 0x101170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_add_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: Specialised search for ADDs that modify a memory location.
 * The helper runs the decoder until opcode `0x103` (the loader’s normalised add [mem],reg form) shows up, ensures the ModRM bits encode a memory destination, and, when `mem_address` is provided, recomputes the effective address via `mem_disp` to make sure it matches.
 * It returns TRUE with `dctx` still referencing the ADD so callers can read back the increment constant.
 */

#include "xzre_types.h"

BOOL find_add_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL decode_ok;
  long clear_idx;
  dasm_ctx_t *zero_ctx;
  dasm_ctx_t scratch_ctx;
  
  zero_ctx = &scratch_ctx;
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(undefined4 *)&zero_ctx->instruction = 0;
    zero_ctx = (dasm_ctx_t *)((long)&zero_ctx->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &scratch_ctx;
  }
  while( TRUE ) {
    if (code_end <= code_start) {
      return FALSE;
    }
    decode_ok = x86_dasm(dctx,code_start,code_end);
    if ((((decode_ok != FALSE) && (*(int *)(dctx->opcode_window + 3) == 0x103)) &&
        (((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000)) &&
       ((mem_address == (void *)0x0 ||
        ((((dctx->prefix).decoded.flags2 & 1) != 0 &&
         ((u8 *)mem_address == dctx->instruction + dctx->instruction_size + dctx->mem_disp))))))
    break;
    code_start = code_start + 1;
  }
  return TRUE;
}

