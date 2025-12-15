// /home/kali/xzre-ghidra/xzregh/10AC40_find_reg2reg_instruction.c
// Function: find_reg2reg_instruction @ 0x10AC40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_reg2reg_instruction(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx)


/*
 * AutoDoc: Requires a caller-supplied decoder context and walks forward one instruction at a time until it sees a register-only transfer.
 * It rejects every decode that carries lock/rep prefixes, sets REX.W/B, or uses a ModRM mode other than 3, and then checks whether the opcode is either MOV reg↔reg or one of the arithmetic-immediate opcodes addressed via `opcode_lookup_index = opcode - 0x81` (the precomputed bitmask tracks the admissible subset).
 * Decode failures or reaching `code_end` return FALSE; success leaves `dctx` still pointing at the qualifying instruction so register-propagation helpers know the value never touched memory.
 */

#include "xzre_types.h"

BOOL find_reg2reg_instruction(u8 *code_start,u8 *code_end,dasm_ctx_t *dctx)

{
  BOOL decoded;
  uint opcode_lookup_index;
  
  if (dctx == (dasm_ctx_t *)0x0) {
  // AutoDoc: Unlike the other helpers we require a persistent decoder supplied by the caller.
    return FALSE;
  }
  while( TRUE ) {
    if ((code_end <= code_start) || (decoded = x86_dasm(dctx,code_start,code_end), decoded == FALSE)) {
      return FALSE;
    }
    // AutoDoc: Accept MOV reg↔reg or whitelisted arithmetic immediates with no prefixes and ModRM mode 3.
    if (((((*(uint *)(dctx->opcode_window + 3) & 0xfffffffd) == 0x109) ||
         ((opcode_lookup_index = *(uint *)(dctx->opcode_window + 3) - 0x81, opcode_lookup_index < 0x3b &&
          ((0x505050500000505U >> ((byte)opcode_lookup_index & 0x3f) & 1) != 0)))) &&
        (((dctx->prefix).flags_u16 & 0xf80) == 0)) &&
       ((((dctx->prefix).decoded.rex.rex_byte & 5) == 0 &&
        (*(char *)((long)&dctx->prefix + 0xd) == '\x03')))) break;
    // AutoDoc: Skip past any instruction that still touches memory or flips prefixes we care about.
    code_start = dctx->instruction + dctx->instruction_size;
  }
  return TRUE;
}

