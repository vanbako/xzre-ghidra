// /home/kali/xzre-ghidra/xzregh/101120_find_instruction_with_mem_operand.c
// Function: find_instruction_with_mem_operand @ 0x101120
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief finds a LEA or MOV instruction with an immediate memory operand
 *
 *   @param code_start address to start searching from
 *   @param code_end address to stop searching at
 *   @param dctx disassembler context to hold the state
 *   @param mem_address the address of the memory fetch (where the instruction will fetch from)
 *   @return BOOL TRUE if an instruction was found, FALSE otherwise
 */

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

