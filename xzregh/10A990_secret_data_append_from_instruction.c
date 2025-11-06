// /home/kali/xzre-ghidra/xzregh/10A990_secret_data_append_from_instruction.c
// Function: secret_data_append_from_instruction @ 0x10A990
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_instruction(dasm_ctx_t * dctx, secret_data_shift_cursor_t * cursor)


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

