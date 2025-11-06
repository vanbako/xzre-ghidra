// /home/kali/xzre-ghidra/xzregh/101020_find_string_reference.c
// Function: find_string_reference @ 0x101020
// Calling convention: __stdcall
// Prototype: u8 * __stdcall find_string_reference(u8 * code_start, u8 * code_end, char * str)


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

