// /home/kali/xzre-ghidra/xzregh/101170_find_riprel_grp1_imm8_memref.c
// Function: find_riprel_grp1_imm8_memref @ 0x101170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_riprel_grp1_imm8_memref(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: GRP1-imm8 predicate for RIP-relative memory updates.
 * It wipes a scratch decoder whenever `dctx` is NULL, advances by a single byte on failed decodes, and looks for normalised opcode `0x103` (raw `0x83`, the GRP1 imm8 family where ModRM.reg selects ADD/OR/ADC/SBB/AND/SUB/XOR/CMP) paired with the RIP-relative disp32 ModRM form (`mod=0`, `rm=5`).
 * If `mem_address` is set it also requires `DF2_MEM_DISP` and that `instruction + instruction_size + mem_disp` equals the requested pointer before returning TRUE.
 */

#include "xzre_types.h"

BOOL find_riprel_grp1_imm8_memref(u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL add_found;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  dasm_ctx_t scratch_ctx;
  
  ctx_clear_cursor = &scratch_ctx;
  // AutoDoc: Keep the scratch decoder clean so each scan starts from a known state.
  for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
    *(u32 *)&ctx_clear_cursor->instruction = 0;
    ctx_clear_cursor = (dasm_ctx_t *)((u8 *)ctx_clear_cursor + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &scratch_ctx;
  }
  while( TRUE ) {
    if (code_end <= code_start) {
      return FALSE;
    }
    add_found = x86_decode_instruction(dctx,code_start,code_end);
    // AutoDoc: Only accept normalised opcode 0x103 (raw 0x83, GRP1 imm8) when it targets RIP-relative memory.
    if ((((add_found != FALSE) && ((dctx->opcode_window).opcode_window_dword == X86_OPCODE_1B_GRP1_IMM8)
         ) && (((dctx->prefix).decoded.modrm.modrm_word & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32)) &&
       ((mem_address == (void *)0x0 ||
       // AutoDoc: Optionally demand `DF2_MEM_DISP` plus the RIP-relative displacement that lands on the requested pointer.
        ((((dctx->prefix).decoded.flags2 & DF2_MEM_DISP) != 0 &&
         ((u8 *)mem_address == dctx->instruction + dctx->instruction_size + dctx->mem_disp))))))
    break;
    code_start = code_start + 1;
  }
  return TRUE;
}

