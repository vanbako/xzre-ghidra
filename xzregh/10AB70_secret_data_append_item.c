// /home/kali/xzre-ghidra/xzregh/10AB70_secret_data_append_item.c
// Function: secret_data_append_item @ 0x10AB70
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_item(secret_data_shift_cursor_t shift_cursor, uint operation_index, uint shift_count, int index, u8 * code)


/*
 * AutoDoc: Convenience wrapper used by the secret-data descriptor tables: when the supplied index is non-zero it simply calls
 * secret_data_append_singleton with the provided code pointer and cursor, otherwise it treats the entry as disabled and reports
 * FALSE so the batch runner can bail out early.
 */

#include "xzre_types.h"

BOOL secret_data_append_item
               (secret_data_shift_cursor_t shift_cursor,uint operation_index,uint shift_count,
               int index,u8 *code)

{
  BOOL success;
  
  if (index != 0) {
    success = secret_data_append_singleton(code,code,shift_cursor,shift_count,operation_index);
    return success;
  }
  return FALSE;
}

