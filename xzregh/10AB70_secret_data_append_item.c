// /home/kali/xzre-ghidra/xzregh/10AB70_secret_data_append_item.c
// Function: secret_data_append_item @ 0x10AB70
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_item(secret_data_shift_cursor_t shift_cursor, uint operation_index, uint shift_count, int index, u8 * code)
/*
 * AutoDoc: Calls the singleton appender only when a supplied index is non-zero, making it easy to gate optional fingerprint operations. The various secret-data tables use it to share common code while respecting per-item enable flags.
 */

#include "xzre_types.h"


BOOL secret_data_append_item
               (secret_data_shift_cursor_t shift_cursor,uint operation_index,uint shift_count,
               int index,u8 *code)

{
  BOOL BVar1;
  
  if (index != 0) {
    BVar1 = secret_data_append_singleton(code,code,shift_cursor,shift_count,operation_index);
    return BVar1;
  }
  return 0;
}

