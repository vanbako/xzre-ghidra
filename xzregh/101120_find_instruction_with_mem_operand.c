// /home/kali/xzre-ghidra/xzregh/101120_find_instruction_with_mem_operand.c
// Function: find_instruction_with_mem_operand @ 0x101120
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: Two-stage absolute-pointer predicate shared by the recon helpers.
 * It prefers LEA results (via `find_lea_instruction_with_mem_operand`) so RIP-relative references never touch memory, and only falls back to the MOV-load predicate (`find_instruction_with_mem_operand_ex` with opcode `0x10b`) once the LEA attempt fails.
 * TRUE means `dctx` is still positioned on the instruction that materialised `mem_address`.
 */
#include "xzre_types.h"

BOOL find_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  BOOL match_found;
  
  match_found = find_lea_instruction_with_mem_operand(code_start,code_end,dctx,mem_address);
  if (match_found == FALSE) {
    // AutoDoc: Fallback to MOV loads when the LEA scan cannot find the requested pointer.
    match_found = find_instruction_with_mem_operand_ex(code_start,code_end,dctx,0x10b,mem_address);
    return match_found;
  }
  return TRUE;
}

