// /home/kali/xzre-ghidra/xzregh/101060_find_instruction_with_mem_operand_ex.c
// Function: find_instruction_with_mem_operand_ex @ 0x101060
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand_ex(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, int opcode, void * mem_address)


/*
 * AutoDoc: Generic predicate used by the pointer scanners to match one opcode that actually touches memory.
 * It logs the probe via `secret_data_append_from_call_site`, wipes a scratch decoder when the caller passes NULL, and then slides a one-byte window from `code_start` to `code_end` until `x86_dasm` decodes the requested opcode.
 * Each hit still has to present a memory ModRM form and, when `mem_address` is provided, set DF2 and produce a RIP-relative displacement that recomputes to that address before the helper returns TRUE with `dctx` left on the instruction.
 */
#include "xzre_types.h"

BOOL find_instruction_with_mem_operand_ex
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,int opcode,void *mem_address)

{
  BOOL search_ok;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  byte ctx_stride_selector;
  dasm_ctx_t scratch_ctx;
  
  ctx_stride_selector = 0;
  // AutoDoc: Feed the instrumentation/log buffer so we can recover which opcode sweep triggered this search.
  search_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xd6,4,0xe,FALSE);
  if (search_ok != FALSE) {
    ctx_clear_cursor = &scratch_ctx;
    // AutoDoc: Zero the scratch decoder whenever the caller does not supply one.
    for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
      *(u32 *)&ctx_clear_cursor->instruction = 0;
      ctx_clear_cursor = (dasm_ctx_t *)((long)ctx_clear_cursor + ((ulong)ctx_stride_selector * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &scratch_ctx;
    }
    // AutoDoc: Slide a single-byte window forward so failed decodes simply advance to the next offset.
    for (; code_start < code_end; code_start = code_start + 1) {
      search_ok = x86_dasm(dctx,code_start,code_end);
      // AutoDoc: Require the decoded opcode plus a memory ModRM form before considering the DF2/RIP tests.
      if ((((search_ok != FALSE) && (*(int *)(dctx->opcode_window + 3) == opcode)) &&
          (((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000)) &&
         ((mem_address == (void *)0x0 ||
         // AutoDoc: When the caller provides a target pointer, insist DF2 is set and the RIP-relative recomputation lands exactly on it.
          ((((dctx->prefix).decoded.flags2 & 1) != 0 &&
           ((u8 *)mem_address == dctx->instruction + dctx->instruction_size + dctx->mem_disp)))))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

