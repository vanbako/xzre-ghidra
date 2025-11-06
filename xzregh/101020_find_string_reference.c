// /home/kali/xzre-ghidra/xzregh/101020_find_string_reference.c
// Function: find_string_reference @ 0x101020
// Calling convention: __stdcall
// Prototype: u8 * __stdcall find_string_reference(u8 * code_start, u8 * code_end, char * str)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief finds an instruction that references the given string
 *
 *   @param code_start address to start searching from
 *   @param code_end address to stop searching at
 *   @param str the target of the string reference (i.e. the target of the LEA instruction)
 *   @return u8* the address of the first instruction that references the given string, or NULL if not found
 *
 * Upstream implementation excerpt (xzre/xzre_code/find_string_reference.c):
 *     u8 *find_string_reference(
 *     	u8 *code_start,
 *     	u8 *code_end,
 *     	const char *str
 *     ){
 *     	dasm_ctx_t dctx = {0};
 *     	if(find_lea_instruction_with_mem_operand(code_start, code_end, &dctx, (void *)str)){
 *     		return dctx.instruction;
 *     	}
 *     	return NULL;
 *     }
 */

u8 * find_string_reference(u8 *code_start,u8 *code_end,char *str)

{
  BOOL BVar1;
  u8 *puVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  dasm_ctx_t dctx;
  
  pdVar4 = &dctx;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)&pdVar4->instruction = 0;
    pdVar4 = (dasm_ctx_t *)((long)&pdVar4->instruction + 4);
  }
  BVar1 = find_lea_instruction_with_mem_operand(code_start,code_end,&dctx,str);
  puVar2 = (u8 *)0x0;
  if (BVar1 != 0) {
    puVar2 = dctx.instruction;
  }
  return puVar2;
}

