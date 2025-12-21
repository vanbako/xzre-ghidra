// /home/kali/xzre-ghidra/xzregh/101060_find_riprel_opcode_memref_ex.c
// Function: find_riprel_opcode_memref_ex @ 0x101060
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_riprel_opcode_memref_ex(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, X86_OPCODE opcode, void * mem_address)


/*
 * AutoDoc: Generic predicate used by the pointer scanners to match one opcode that actually touches memory.
 * It logs the probe via `secret_data_append_bits_from_call_site`, wipes a scratch decoder when the caller passes NULL, and then slides a one-byte window from `code_start` to `code_end` until `x86_decode_instruction` decodes the requested opcode.
 * Candidates must use the RIP-relative disp32 ModRM form (`mod=0`, `rm=5`). When `mem_address` is provided the helper also requires `flags2` to carry `DF2_MEM_DISP` and that `instruction + instruction_size + mem_disp` equals the requested pointer before returning TRUE with `dctx` left on the hit instruction.
 */

#include "xzre_types.h"

BOOL find_riprel_opcode_memref_ex
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,X86_OPCODE opcode,void *mem_address)

{
  BOOL search_ok;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  byte ctx_stride_sign;
  dasm_ctx_t scratch_ctx;
  
  ctx_stride_sign = 0;
  // AutoDoc: Feed the instrumentation/log buffer so we can recover which opcode sweep triggered this search.
  search_ok = secret_data_append_bits_from_call_site((secret_data_shift_cursor_t)0xd6,4,0xe,FALSE);
  if (search_ok != FALSE) {
    ctx_clear_cursor = &scratch_ctx;
    // AutoDoc: Zero the scratch decoder whenever the caller does not supply one.
    for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
      *(u32 *)&ctx_clear_cursor->instruction = 0;
      ctx_clear_cursor = (dasm_ctx_t *)((u8 *)ctx_clear_cursor + 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &scratch_ctx;
    }
    // AutoDoc: Slide a single-byte window forward so failed decodes simply advance to the next offset.
    for (; code_start < code_end; code_start = code_start + 1) {
      search_ok = x86_decode_instruction(dctx,code_start,code_end);
      // AutoDoc: Require the decoded opcode plus the RIP-relative disp32 form (ModRM `mod=0`, `rm=5`) before considering the displacement recompute.
      if ((((search_ok != FALSE) && ((dctx->opcode_window).opcode_window_dword == opcode)) &&
          (((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000)) &&
         ((mem_address == (void *)0x0 ||
         // AutoDoc: When the caller provides a target pointer, insist `DF2_MEM_DISP` is set and the RIP-relative recomputation (`instruction + size + disp32`) lands exactly on it.
          ((((dctx->prefix).decoded.flags2 & 1) != 0 &&
           ((u8 *)mem_address == dctx->instruction + dctx->instruction_size + dctx->mem_disp)))))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

