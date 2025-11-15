// /home/kali/xzre-ghidra/xzregh/101120_find_instruction_with_mem_operand.c
// Function: find_instruction_with_mem_operand @ 0x101120
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: Funnel that hides the distinction between LEA- and MOV-based references.
 * It first asks `find_lea_instruction_with_mem_operand` to locate a LEA that materialises `mem_address`; if that fails it calls `find_instruction_with_mem_operand_ex` with opcode `0x10b` so a plain MOV load qualifies.
 * Either path returning TRUE guarantees that `dctx` now describes an instruction that touches the supplied absolute address.
 */

#include "xzre_types.h"

BOOL find_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL BVar1;
  
  BVar1 = find_lea_instruction_with_mem_operand(code_start,code_end,dctx,mem_address);
  if (BVar1 == FALSE) {
    BVar1 = find_instruction_with_mem_operand_ex(code_start,code_end,dctx,0x10b,mem_address);
    return BVar1;
  }
  return TRUE;
}

