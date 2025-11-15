// /home/kali/xzre-ghidra/xzregh/10AC40_find_reg2reg_instruction.c
// Function: find_reg2reg_instruction @ 0x10AC40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_reg2reg_instruction(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx)


/*
 * AutoDoc: Requires a valid decoder context and walks instructions until it finds a pure register-to-register transfer.
 * The opcode filter accepts MOV reg↔reg plus a small mask of arithmetic immediates, but the helper rejects any instruction with lock/rep prefixes, REX.W/B bits, or a ModRM mode other than 3 (register operands).
 * When it returns TRUE the caller’s `dctx` still describes that register shuffle so pointer-propagation routines can continue without worrying about hidden memory accesses.
 */

#include "xzre_types.h"

BOOL find_reg2reg_instruction(u8 *code_start,u8 *code_end,dasm_ctx_t *dctx)

{
  BOOL BVar1;
  uint uVar2;
  
  if (dctx == (dasm_ctx_t *)0x0) {
    return FALSE;
  }
  while( TRUE ) {
    if ((code_end <= code_start) || (BVar1 = x86_dasm(dctx,code_start,code_end), BVar1 == FALSE)) {
      return FALSE;
    }
    if (((((*(uint *)(dctx->opcode_window + 3) & 0xfffffffd) == 0x109) ||
         ((uVar2 = *(uint *)(dctx->opcode_window + 3) - 0x81, uVar2 < 0x3b &&
          ((0x505050500000505U >> ((byte)uVar2 & 0x3f) & 1) != 0)))) &&
        (((dctx->prefix).flags_u16 & 0xf80) == 0)) &&
       ((((dctx->prefix).decoded.rex.rex_byte & 5) == 0 &&
        (*(char *)((long)&dctx->prefix + 0xd) == '\x03')))) break;
    code_start = dctx->instruction + dctx->instruction_size;
  }
  return TRUE;
}

