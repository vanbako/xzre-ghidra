// /home/kali/xzre-ghidra/xzregh/100F60_find_riprel_lea.c
// Function: find_riprel_lea @ 0x100F60
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_riprel_lea(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: LEA finder that insists the instruction truly references memory and, optionally, a concrete absolute address.
 * After logging the call site via `secret_data_append_bits_from_call_site` it clears a stack fallback decoder (`ctx_clear_idx` / `ctx_clear_cursor`) and uses it when `dctx` is NULL, then decodes forward one byte at a time until it sees a REX.W LEA (`0x10d`, raw `0x8d`) with a RIP-relative disp32 ModRM form (`mod=0`, `rm=5`).
 * If `mem_address` is non-null it recomputes the RIP-relative target (`instruction + instruction_size + mem_disp`) and only succeeds on an exact match; otherwise any qualifying LEA returns TRUE with `dctx` still on the instruction.
 */

#include "xzre_types.h"

BOOL find_riprel_lea(u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL decoded;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_clear_cursor;
  byte ctx_stride_sign;
  dasm_ctx_t scratch_ctx;
  
  ctx_stride_sign = 0;
  decoded = secret_data_append_bits_from_call_site((secret_data_shift_cursor_t)0x1c8,0,0x1e,FALSE);
  // AutoDoc: Log the caller so later telemetry can explain which helper touched a given memory range.
  if (decoded != FALSE) {
    ctx_clear_cursor = &scratch_ctx;
    // AutoDoc: Zero the scratch decoder so we only evaluate the LEA we just decoded.
    for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
      *(u32 *)&ctx_clear_cursor->instruction = 0;
      ctx_clear_cursor = (dasm_ctx_t *)((long)ctx_clear_cursor + ((ulong)ctx_stride_sign * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &scratch_ctx;
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      // AutoDoc: Keep decoding until we see a 64-bit RIP-relative LEA (REX.W + disp32) that materialises a pointer.
      decoded = x86_decode_instruction(dctx,code_start,code_end);
      if ((((decoded != FALSE) && (dctx->opcode_window_dword == 0x10d)) &&
      // AutoDoc: Optional RIP target comparison lets callers lock onto a single absolute pointer.
          (((dctx->prefix).modrm_bytes.rex_byte & 0x48) == 0x48)) &&
         ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000 &&
          ((mem_address == (void *)0x0 ||
           (dctx->instruction + dctx->mem_disp + dctx->instruction_size == (u8 *)mem_address)))))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

