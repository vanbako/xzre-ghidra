// /home/kali/xzre-ghidra/xzregh/101120_find_instruction_with_mem_operand.c
// Function: find_instruction_with_mem_operand @ 0x101120
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: Chases an absolute address without exposing the LEA vs MOV distinction: first tries `find_lea_instruction_with_mem_operand`, then falls back to `find_instruction_with_mem_operand_ex` for opcode `0x10b` (MOV load) if the LEA path fails.
 * TRUE means `dctx` now describes an instruction that touches `mem_address`.
 */

#include "xzre_types.h"

BOOL find_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL decode_ok;
  
  decode_ok = find_lea_instruction_with_mem_operand(code_start,code_end,dctx,mem_address);
  if (decode_ok == FALSE) {
    decode_ok = find_instruction_with_mem_operand_ex(code_start,code_end,dctx,0x10b,mem_address);
    return decode_ok;
  }
  return TRUE;
}

