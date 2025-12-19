// /home/kali/xzre-ghidra/xzregh/10AA00_secret_data_append_code_bits.c
// Function: secret_data_append_code_bits @ 0x10AA00
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_code_bits(void * code_start, void * code_end, secret_data_shift_cursor_t shift_cursor, uint shift_count, BOOL start_from_call)


/*
 * AutoDoc: Disassembler helper that emits a contiguous run of attestation bits. It zeroes a scratch `dasm_ctx_t`, optionally hops to the
 * instruction after the next CALL, and then keeps calling `find_reg_to_reg_instruction` until `shift_count` hits have been turned into
 * bits through `secret_data_append_opcode_bit`. Returning FALSE means the code range ran out before the requested number of
 * instructions were found.
 */

#include "xzre_types.h"

BOOL secret_data_append_code_bits
               (void *code_start,void *code_end,secret_data_shift_cursor_t shift_cursor,
               uint shift_count,BOOL start_from_call)

{
  BOOL found_instruction;
  long wipe_index;
  dasm_ctx_t *ctx_wipe_cursor;
  ulong bits_appended;
  secret_data_shift_cursor_t cursor_work[3];
  dasm_ctx_t decoder_ctx;
  
  ctx_wipe_cursor = &decoder_ctx;
  // AutoDoc: Blank the decoder context so each pass starts with predictable instruction/size windows.
  for (wipe_index = 0x16; wipe_index != 0; wipe_index = wipe_index + -1) {
    *(u32 *)&ctx_wipe_cursor->instruction = 0;
    ctx_wipe_cursor = (dasm_ctx_t *)((long)&ctx_wipe_cursor->instruction + 4);
  }
  cursor_work[0] = shift_cursor;
  // AutoDoc: When start_from_call is TRUE, fast-forward to the first instruction after the next CALL before collecting bits.
  if (start_from_call != FALSE) {
    found_instruction = find_rel32_call_instruction((u8 *)code_start,(u8 *)code_end,(u8 *)0x0,&decoder_ctx);
    if (found_instruction == FALSE) {
      return FALSE;
    }
    // AutoDoc: Bump the start pointer past the consumed instruction so the next search resumes immediately afterward.
    code_start = decoder_ctx.instruction + decoder_ctx.instruction_size;
  }
  bits_appended = 0;
  do {
    // AutoDoc: Search the provided span for the next instruction that matches the reg-to-reg filter; failure exits early.
    found_instruction = find_reg_to_reg_instruction((u8 *)code_start,(u8 *)code_end,&decoder_ctx);
    if (found_instruction == FALSE) {
LAB_0010aa80:
      return (uint)(shift_count == (uint)bits_appended);
    }
    // AutoDoc: As soon as we have emitted `shift_count` bits, stop scanning and report success.
    if (bits_appended == shift_count) {
      if (shift_count < (uint)bits_appended) {
        return FALSE;
      }
      goto LAB_0010aa80;
    }
    bits_appended = bits_appended + 1;
    // AutoDoc: Append a single bit using the decoded instruction; any error bubbles up to the singleton gate.
    found_instruction = secret_data_append_opcode_bit(&decoder_ctx,cursor_work);
    if (found_instruction == FALSE) {
      return FALSE;
    }
    code_start = decoder_ctx.instruction + decoder_ctx.instruction_size;
  } while( TRUE );
}

