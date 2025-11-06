// /home/kali/xzre-ghidra/xzregh/10A990_secret_data_append_from_instruction.c
// Function: secret_data_append_from_instruction @ 0x10A990
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_instruction(dasm_ctx_t * dctx, secret_data_shift_cursor_t * cursor)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Upstream implementation excerpt (xzre/xzre_code/secret_data_append_from_instruction.c):
 *     BOOL secret_data_append_from_instruction(dasm_ctx_t *dctx, secret_data_shift_cursor_t *cursor){
 *     	if(cursor->index <= 0x1C7
 *     	&& XZDASM_OPC(dctx->opcode) != X86_OPCODE_MOV
 *     	&& XZDASM_OPC(dctx->opcode) != X86_OPCODE_CMP
 *     	&& !XZDASM_TEST_MASK(0x410100000101, 3, dctx->opcode)
 *     	){
 *     		global_ctx->secret_data[cursor->byte_index] |= 1 << (cursor->bit_index);
 *     	}
 *     	++cursor->index;
 *     	return TRUE;
 *     }
 */

BOOL secret_data_append_from_instruction(dasm_ctx_t *dctx,secret_data_shift_cursor_t *cursor)

{
  byte *pbVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = cursor->index;
  if (uVar2 < 0x1c8) {
    iVar3 = *(int *)dctx->_unknown810;
    if (((iVar3 != 0x109) && (iVar3 != 0xbb)) &&
       ((0x2e < iVar3 - 0x83U || ((0x410100000101U >> ((byte)(iVar3 - 0x83U) & 0x3f) & 1) == 0)))) {
      pbVar1 = (byte *)(global_ctx + 0x108 + (ulong)(uVar2 >> 3));
      *pbVar1 = *pbVar1 | (byte)(1 << ((byte)uVar2 & 7));
    }
    cursor->index = uVar2 + 1;
  }
  return 1;
}

