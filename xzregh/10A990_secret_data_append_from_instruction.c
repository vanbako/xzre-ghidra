// /home/kali/xzre-ghidra/xzregh/10A990_secret_data_append_from_instruction.c
// Function: secret_data_append_from_instruction @ 0x10A990
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_instruction(dasm_ctx_t * dctx, secret_data_shift_cursor_t * cursor)


/*
 * AutoDoc: Writes a single attestation bit using the opcode selected by `find_reg2reg_instruction`. The helper enforces the 0x1c8-bit
 * budget tracked inside `secret_data_shift_cursor_t`, peeks the canonical opcode from `dctx->opcode_window`, skips CALL/MOV identities
 * plus the masked opcode table, and otherwise maps the cursor into `global_ctx->secret_data` before ORing the bit. The cursor is
 * incremented regardless of whether a bit was set so the caller stays in sync.
 */
#include "xzre_types.h"

BOOL secret_data_append_from_instruction(dasm_ctx_t *dctx,secret_data_shift_cursor_t *cursor)

{
  byte *bit_slot;
  uint bit_index;
  int decoded_opcode;
  
  // AutoDoc: Read the next attestation slot that this decode pass should fill.
  bit_index = cursor->bit_position;
  // AutoDoc: Stop writing once the 0x1c8-bit budget is exhausted; callers still advance the cursor to keep later scans aligned.
  if (bit_index < 0x1c8) {
    // AutoDoc: Grab the canonical opcode byte from the sliding decode window.
    decoded_opcode = *(int *)(dctx->opcode_window + 3);
    // AutoDoc: Skip CALL (0x109), MOV imm64 (0xbb), and opcodes masked out by the 0x83–0xb1 bit table so noise does not pollute the log.
    if (((decoded_opcode != 0x109) && (decoded_opcode != 0xbb)) &&
       ((0x2e < decoded_opcode - 0x83U || ((0x410100000101U >> ((byte)(decoded_opcode - 0x83U) & 0x3f) & 1) == 0)))) {
      bit_slot = (byte *)(global_ctx + 0x108 + (ulong)(bit_index >> 3));
      // AutoDoc: Translate the global bit index into the packed secret_data array and set the corresponding bit.
      *bit_slot = *bit_slot | (byte)(1 << ((byte)bit_index & 7));
    }
    // AutoDoc: Advance the cursor even when the opcode filter skipped a write so future calls keep counting forward.
    cursor->bit_position = bit_index + 1;
  }
  return TRUE;
}

