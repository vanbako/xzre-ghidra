// /home/kali/xzre-ghidra/xzregh/10A990_secret_data_append_from_instruction.c
// Function: secret_data_append_from_instruction @ 0x10A990
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_from_instruction(dasm_ctx_t * dctx, secret_data_shift_cursor_t * cursor)


/*
 * AutoDoc: Sets the next bit inside global_ctx->secret_data based on a decoded instruction. The cursor enforces the 0x1C8-bit ceiling,
 * skips certain opcodes (0x109, 0xBB, and entries in the precomputed 0x83–0xB1 mask), and otherwise locates the byte/bit inside
 * the secret_data array and ORs it in before advancing the cursor.
 */

#include "xzre_types.h"

BOOL secret_data_append_from_instruction(dasm_ctx_t *dctx,secret_data_shift_cursor_t *cursor)

{
  byte *secret_byte;
  uint cursor_index;
  int opcode;
  
  cursor_index = cursor->index;
  if (cursor_index < 0x1c8) {
    opcode = *(int *)(dctx->opcode_window + 3);
    if (((opcode != 0x109) && (opcode != 0xbb)) &&
       ((0x2e < opcode - 0x83U || ((0x410100000101U >> ((byte)(opcode - 0x83U) & 0x3f) & 1) == 0)))) {
      secret_byte = (byte *)(global_ctx + 0x108 + (ulong)(cursor_index >> 3));
      *secret_byte = *secret_byte | (byte)(1 << ((byte)cursor_index & 7));
    }
    cursor->index = cursor_index + 1;
  }
  return TRUE;
}

