// /home/kali/xzre-ghidra/xzregh/10ABE0_secret_data_append_items.c
// Function: secret_data_append_items @ 0x10ABE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_items(secret_data_item_t * items, u64 items_count, secret_data_appender_fn appender)


/*
 * AutoDoc: Batch driver for arrays of secret_data_item_t. It assigns sequential indexes to entries that have not been initialised yet,
 * calls the provided appender for each descriptor (passing the 1-based ordinal and the recorded code pointer), and stops at the
 * first failure so callers know whether the entire batch completed.
 */

#include "xzre_types.h"

BOOL secret_data_append_items
               (secret_data_item_t *items,u64 items_count,secret_data_appender_fn appender)

{
  BOOL success;
  secret_data_item_t *item;
  u32 slot_index;
  uint index;
  ulong item_index;
  
  slot_index = 0;
  item_index = 0;
  while( TRUE ) {
    while( TRUE ) {
      if (items_count <= item_index) {
        return TRUE;
      }
      index = (int)item_index + 1;
      item = items + item_index;
      item_index = (ulong)index;
      if (item->ordinal != 0) break;
      item->ordinal = slot_index;
    }
    success = (*appender)((secret_data_shift_cursor_t)(item->bit_cursor).bit_position,
                        item->operation_slot,item->bits_to_shift,index,item->anchor_pc);
    if (success == FALSE) break;
    slot_index = slot_index + 1;
  }
  return FALSE;
}

