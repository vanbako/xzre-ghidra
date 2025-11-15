// /home/kali/xzre-ghidra/xzregh/101020_find_string_reference.c
// Function: find_string_reference @ 0x101020
// Calling convention: __stdcall
// Prototype: u8 * __stdcall find_string_reference(u8 * code_start, u8 * code_end, char * str)


/*
 * AutoDoc: Convenience wrapper that returns the instruction which first references a given string literal.
 * It simply calls `find_lea_instruction_with_mem_operand` across `[code_start, code_end)` with `str` as the desired absolute address and, when successful, yields the LEA’s address so later heuristics can treat it as the anchor for the surrounding function.
 */

#include "xzre_types.h"

u8 * find_string_reference(u8 *code_start,u8 *code_end,char *str)

{
  BOOL BVar1;
  u8 *puVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  dasm_ctx_t dctx;
  dasm_ctx_t local_60;
  
  pdVar4 = &local_60;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)&pdVar4->instruction = 0;
    pdVar4 = (dasm_ctx_t *)((long)&pdVar4->instruction + 4);
  }
  BVar1 = find_lea_instruction_with_mem_operand(code_start,code_end,&local_60,str);
  puVar2 = (u8 *)0x0;
  if (BVar1 != FALSE) {
    puVar2 = local_60.instruction;
  }
  return puVar2;
}

