// /home/kali/xzre-ghidra/xzregh/100E00_find_riprel_mov.c
// Function: find_riprel_mov @ 0x100E00
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_riprel_mov(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: MOV-only variant of the pointer scan.
 * It clears the stack `scratch_ctx` with the `ctx_clear_idx` / `ctx_clear_cursor` walkers and uses it when `dctx` is NULL, then advances by one byte on decode failure or by `instruction_size` on success.
 * Matches require the RIP-relative ModRM form (`mod=0`, `rm=5`) plus MOV load/store (`0x10b`/`0x109`, i.e. raw `0x8b`/`0x89` after the decoder’s +0x80 normalization); loads also require the decoded REX.W presence to match `is_64bit_operand` (stores skip the width check). On success the populated decoder is left on the MOV so pointer-tracking helpers can read the operands immediately.
 */

#include "xzre_types.h"

BOOL find_riprel_mov(u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,
                    dasm_ctx_t *dctx)

{
  BOOL decoded;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  BOOL is_expected_opcode;
  dasm_ctx_t scratch_ctx;
  
  ctx_clear_cursor = &scratch_ctx;
  // AutoDoc: Keep the decoder context pristine so predicates only see the current instruction.
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
      // AutoDoc: Retry at the next byte boundary when the decoder chokes on garbage.
      code_start = code_start + 1;
    }
    if ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) &&
    // AutoDoc: Require RIP-relative disp32 (ModRM `mod=0`, `rm=5`) and the caller-requested operand width.
       (((((dctx->prefix).modrm_bytes.rex_byte & 0x48) == 0x48) == is_64bit_operand ||
        (load_flag == FALSE)))) {
      if (load_flag == FALSE) {
        is_expected_opcode = (dctx->opcode_window).opcode_window_dword == X86_OPCODE_1B_MOV_STORE;
      }
      else {
        is_expected_opcode = (dctx->opcode_window).opcode_window_dword == X86_OPCODE_1B_MOV_LOAD;
      }
      if (is_expected_opcode) {
        return TRUE;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( TRUE );
}

