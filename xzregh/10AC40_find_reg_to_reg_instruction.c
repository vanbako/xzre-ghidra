// /home/kali/xzre-ghidra/xzregh/10AC40_find_reg_to_reg_instruction.c
// Function: find_reg_to_reg_instruction @ 0x10AC40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_reg_to_reg_instruction(u8 * code_start, u8 * code_end, dasm_ctx_t * dctx)


/*
 * AutoDoc: Requires a caller-supplied decoder context and walks forward one instruction at a time until it sees a register-only operation.
 * Candidates must use ModRM mode 3, carry no SIB/displacement/immediate state (`prefix.flags_u16 & 0xf80`), and avoid extended registers by requiring `rex_byte` to have neither REX.R nor REX.B set (`rex_byte & 0x05`). The opcode gate then accepts MOV reg↔reg (`0x109`/`0x10b`, raw `0x89`/`0x8b`) plus a small ALU whitelist (ADD/OR/ADC/SBB/SUB/XOR/CMP) indexed via `opcode_lookup_index = opcode - 0x81` and a bitmask.
 * Decode failures or reaching `code_end` return FALSE; success leaves `dctx` still pointing at the qualifying instruction so register-propagation helpers know the value never touched memory.
 */

#include "xzre_types.h"

BOOL find_reg_to_reg_instruction(u8 *code_start,u8 *code_end,dasm_ctx_t *dctx)

{
  BOOL decoded;
  uint opcode_lookup_index;
  
  if (dctx == (dasm_ctx_t *)0x0) {
  // AutoDoc: Unlike the other helpers we require a persistent decoder supplied by the caller.
    return FALSE;
  }
  while( TRUE ) {
    if ((code_end <= code_start) ||
       (decoded = x86_decode_instruction(dctx,code_start,code_end), decoded == FALSE)) {
      return FALSE;
    }
    // AutoDoc: Accept MOV reg↔reg or whitelisted ALU reg↔reg ops (ADD/OR/ADC/SBB/SUB/XOR/CMP) with no SIB/disp/imm and ModRM mode 3.
    if ((((((dctx->opcode_window).opcode_window_dword & 0xfffffffd) == 0x109) ||
         ((opcode_lookup_index = (dctx->opcode_window).opcode_window_dword - 0x81, opcode_lookup_index < 0x3b &&
          ((0x505050500000505U >> ((byte)opcode_lookup_index & 0x3f) & 1) != 0)))) &&
        (((dctx->prefix).flags_u16 & 0xf80) == 0)) &&
       ((((dctx->prefix).modrm_bytes.rex_byte & 5) == 0 &&
        ((dctx->prefix).modrm_bytes.modrm_mod == '\x03')))) break;
    // AutoDoc: Skip past any instruction that still touches memory or flips prefixes we care about.
    code_start = dctx->instruction + dctx->instruction_size;
  }
  return TRUE;
}

