// /home/kali/xzre-ghidra/xzregh/10AC40_find_reg2reg_instruction.c
// Function: find_reg2reg_instruction @ 0x10AC40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_reg2reg_instruction(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief finds a reg2reg instruction
 *
 *   a reg2reg instruction is an x64 instruction with one of the following characteristics:
 *   - a primary opcode of 0x89 (MOV/JNS)
 *   or, alternatively, passing the following filter:
 *   - ((0x505050500000505uLL >> (((dctx->opcode) & 0xFF) + 0x7F)) & 1) != 0
 *   NOTE: the opcode in 'dctx->opcode' is the actual opcode +0x80
 *   TODO: inspect x64 manual to find the exact filter
 *
 *   the instruction must also satisfy the following conditions:
 *   - NOT have REX.B and REX.R set (no extension bits)
 *   - MODRM.mod must be 3 (register-direct addressing mode)
 *
 *   @param code_start address to start searching from
 *   @param code_end address to stop searching at
 *   @param dctx disassembler context to hold the state
 *   @return BOOL TRUE if found, FALSE otherwise
 */

BOOL find_reg2reg_instruction(u8 *code_start,u8 *code_end,dasm_ctx_t *dctx)

{
  BOOL BVar1;
  uint uVar2;
  
  if (dctx == (dasm_ctx_t *)0x0) {
    return 0;
  }
  while( true ) {
    if ((code_end <= code_start) || (BVar1 = x86_dasm(dctx,code_start,code_end), BVar1 == 0)) {
      return 0;
    }
    if (((((*(uint *)dctx->_unknown810 & 0xfffffffd) == 0x109) ||
         ((uVar2 = *(uint *)dctx->_unknown810 - 0x81, uVar2 < 0x3b &&
          ((0x505050500000505U >> ((byte)uVar2 & 0x3f) & 1) != 0)))) &&
        (((dctx->field2_0x10).flags_u16 & 0xf80) == 0)) &&
       ((((dctx->field2_0x10).field0.field10_0xb.rex_byte & 5) == 0 &&
        (*(char *)((long)&dctx->field2_0x10 + 0xd) == '\x03')))) break;
    code_start = dctx->instruction + dctx->instruction_size;
  }
  return 1;
}

