// /home/kali/xzre-ghidra/xzregh/10AB70_secret_data_append_item.c
// Function: secret_data_append_item @ 0x10AB70
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_item(secret_data_shift_cursor_t shift_cursor, uint operation_index, uint shift_count, int index, u8 * code)


/*
 * AutoDoc: Descriptor helper that optionally skips work. Index 0 entries represent disabled slots and immediately return FALSE so the
 * batch walker can abort; any other index calls `secret_data_append_singleton` with the supplied cursor/code tuple.
 */
#include "xzre_types.h"

BOOL secret_data_append_item
               (secret_data_shift_cursor_t shift_cursor,uint operation_index,uint shift_count,
               int index,u8 *code)

{
  BOOL appended;
  
  // AutoDoc: Treat a non-zero descriptor index as active by forwarding the work to the singleton helper.
  if (index != 0) {
    appended = secret_data_append_singleton(code,code,shift_cursor,shift_count,operation_index);
    return appended;
  }
  // AutoDoc: Disabled entries short-circuit the caller so the batch can stop trying to append bits for this slot.
  return FALSE;
}

